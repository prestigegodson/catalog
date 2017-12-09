from flask import Flask, render_template, make_response
from flask import session as login_session, abort, flash
from flask import request, jsonify, url_for, redirect
import json
import string
import random
from helper import get_session_state, generate_csrf_token
from oauth2client.client import flow_from_clientsecrets
from oauth2client.client import FlowExchangeError
import httplib2
import requests
from models import Category, User, Item, Base
from sqlalchemy import create_engine, event, asc
from sqlalchemy.orm import sessionmaker
from functools import wraps
from datetime import datetime

app = Flask(__name__)

client_json = json.loads(open('client_secret.json', 'r').read())
CLIENT_ID = client_json['web']['client_id']

engine = create_engine("sqlite:///catalog.db")
Base.metadata.bind = engine

DBSession = sessionmaker(bind=engine)
session = DBSession()


@app.before_first_request
def seed_category_table():
    """
    if there is no record in Category Table:
        insert default categories
    else:
        pass
    """
    categories = session.query(Category).all()
    if len(categories) == 0:
        category_computer = Category(name='computer')
        category_soccer = Category(name='soccer')
        category_car = Category(name='car')

        session.add(category_computer)
        session.commit()
        session.add(category_soccer)
        session.commit()
        session.add(category_car)
        session.commit()


def csrf_protect(f):
    """
    This higher order function when applied, protects any form
    post request from cross site request forgery attack by
    checking if the _csrf_token passed is equal to the csrf_token
    generated and stored in session
    """
    @wraps(f)
    def wrapper(*args, **kwds):
        if request.method == "POST":
            token = login_session.pop('_csrf_token', None)
            if not token or token != request.form.get('_csrf_token'):
                abort(403)
        return f(*args, **kwds)
    return wrapper


def is_logged_in(f):
    """
    This higher order function when applied, checks if a user is logged in
    """
    @wraps(f)
    def wrapper(*args, **kwds):
        if 'email' not in login_session:
            return redirect(url_for('login_page'))
        return f(*args, **kwds)
    return wrapper


def get_csrf_token():
    """
    This function gets random csrf token and saves in session
    """
    if '_csrf_token' not in login_session:
        login_session['_csrf_token'] = generate_csrf_token()
    return login_session['_csrf_token']


@app.route('/login', methods=['GET'])
def login_page():
    """
    This function renders the login page
    if the user is not logged in
    """
    if 'email' in login_session:
        return redirect(url_for('showCategories'))

    session_token = get_session_state()
    login_session['state'] = session_token
    csrf_token = get_csrf_token()
    return render_template("login.html", state=session_token,
                           _csrf_token=csrf_token)


@app.route('/login', methods=['POST'])
def login():
    """
    This function accepts Authentication code,
    and attempts to retrieve access_token from auth server
    """
    if request.args.get('state') != login_session['state']:
        return make_response("Invalide state parameter", 401)

    code = request.data

    try:
        oauth_flow = flow_from_clientsecrets('client_secret.json', scope='')
        oauth_flow.redirect_uri = 'postmessage'
        credentials = oauth_flow.step2_exchange(code)
    except FlowExchangeError:
        response = make_response(
            json.dumps('Failed to upgrade the authorization code.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Check that the access token is valid.
    access_token = credentials.access_token
    url = ('https://www.googleapis.com/oauth2/v1/tokeninfo?access_token=%s'
           % access_token)
    h = httplib2.Http()
    result = json.loads(h.request(url, 'GET')[1])
    # If there was an error in the access token info, abort.
    if result.get('error') is not None:
        response = make_response(json.dumps(result.get('error')), 500)
        response.headers['Content-Type'] = 'application/json'
        return response
    # Verify that the access token is used for the intended user.
    gplus_id = credentials.id_token['sub']
    if result['user_id'] != gplus_id:
        response = make_response(
            json.dumps("Token's user ID doesn't match given user ID."), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Verify that the access token is valid for this app.
    if result['issued_to'] != CLIENT_ID:
        response = make_response(
            json.dumps("Token's client ID does not match app's."), 401)
        print("Token's client ID does not match app's.")
        response.headers['Content-Type'] = 'application/json'
        return response

    stored_access_token = login_session.get('access_token')
    stored_gplus_id = login_session.get('gplus_id')
    if stored_access_token is not None and gplus_id == stored_gplus_id:
        response = make_response(json.dumps('User is already connected.'),
                                 200)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Store the access token in the session for later use.
    login_session['access_token'] = credentials.access_token
    login_session['gplus_id'] = gplus_id

    # Get user info
    userinfo_url = "https://www.googleapis.com/oauth2/v1/userinfo"
    params = {'access_token': credentials.access_token, 'alt': 'json'}
    answer = requests.get(userinfo_url, params=params)

    data = answer.json()

    login_session['username'] = data['name']
    login_session['picture'] = data['picture']
    login_session['email'] = data['email']

    user = session.query(User).filter_by(email=data['email']).one_or_none()
    if user is None:
        create_new_user()

    return jsonify({'name': data['name'], 'email': data['email']})


@app.route('/logout')
def logout():
    access_token = login_session['access_token']
    print('In gdisconnect access token is %s', access_token)
    print('User name is: ')
    print(login_session['username'])
    if access_token is None:
        print('Access Token is None')
        response = make_response(json.dumps('Current user not connected.'),
                                 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    url = ('https://accounts.google.com/o/oauth2/revoke?token=%s'
           % login_session['access_token'])
    h = httplib2.Http()
    result = h.request(url, 'GET')[0]
    print('result is ')
    print(result)
    if result['status'] == '200':
        del login_session['access_token']
        del login_session['gplus_id']
        del login_session['username']
        del login_session['email']
        del login_session['picture']
        return redirect(url_for('login_page'))
    else:
        del login_session['access_token']
        del login_session['gplus_id']
        del login_session['username']
        del login_session['email']
        del login_session['picture']
        return redirect(url_for('login_page'))


def create_new_user():
    """
    This function creates a new user after login
    if the user does not exist in database
    """

    user = User(email=login_session['email'],
                username=login_session['username'],
                pix=login_session['picture'])
    session.add(user)
    session.commit()


@app.route('/', methods=['GET'])
@app.route('/categories', methods=['GET'])
def showCategories():
    categories = session.query(Category).all()
    items = session.query(Item).order_by(Item.id).limit(5)
    return render_template('categories.html',
                           categories=categories, items=items)


@app.route('/category/<int:cat_id>/items')
def view_items_page(cat_id):
    item_list = session.query(Item).filter_by(category_id=cat_id).all()
    cat = session.query(Category).filter_by(id=cat_id).one()

    return render_template('items.html', items=item_list,
                           category=cat)


@app.route('/category/item/<int:id>')
def item_page(id):
    item = session.query(Item).filter_by(id=id).one()
    user = None
    if 'email' in login_session:
        user = (session.query(User)
                .filter_by(email=login_session['email']).one())
    return render_template('item_page.html', item=item, user=user)


@app.route('/category/item/new', methods=['GET'])
@is_logged_in
def create_item_page():
    csrf_token = get_csrf_token()
    categories = session.query(Category).all()
    return render_template("create_item.html",
                           _csrf_token=csrf_token, categories=categories)


@app.route('/category/item/new', methods=['POST'])
@is_logged_in
@csrf_protect
def create_new_item():
    user_email = login_session['email']
    user = session.query(User).filter_by(email=user_email).one_or_none()
    if user is not None:
        item_name = request.form['item_name']
        item_description = request.form['item_description']
        cat_id = request.form['category']

        item = Item(name=item_name, description=item_description,
                    created_date=datetime.now(), user_id=user.id,
                    category_id=cat_id)

        session.add(item)
        session.commit()

        flash('%s Item created successfully!!!' % item_name)
        return redirect(url_for('create_item_page'))
    else:
        abort(401)


@app.route('/category/item/<int:item_id>/confirm_delete', methods=['GET'])
@is_logged_in
def confirm_delete_item(item_id):
    item = session.query(Item).filter_by(id=item_id).one_or_none()

    return render_template('confirm_item_delete.html', item=item)


@app.route('/category/item/<int:item_id>/delete', methods=['GET'])
@is_logged_in
def delete_item(item_id):
    item = session.query(Item).filter_by(id=item_id).one_or_none()
    cat_id = item.category_id
    session.query(Item).filter_by(id=item_id).delete()

    return redirect(url_for('view_items_page', cat_id=cat_id))


@app.route('/category/item/<int:item_id>/edit', methods=['GET'])
@is_logged_in
def edit_item_page(item_id):
    csrf_token = get_csrf_token()
    categories = session.query(Category).all()
    item = session.query(Item).filter_by(id=item_id).one_or_none()
    return render_template("edit_item.html", _csrf_token=csrf_token,
                           categories=categories, item=item)


@app.route('/category/item/edit', methods=['POST'])
@is_logged_in
@csrf_protect
def edit_item():
    item_id = request.form['item_id']
    item = session.query(Item).filter_by(id=item_id).one_or_none()

    item_name = request.form['item_name']
    item_description = request.form['item_description']
    cat_id = request.form['category']

    item.name = item_name
    item.description = item_description
    item.category_id = cat_id
    item.updated_Date = datetime.now()

    return redirect(url_for('item_page', id=item_id))


@app.route('/category.json')
def show_categories_json():
    categories = session.query(Category).all()
    cats = [c.serialize for c in categories]
    return jsonify({'categories': cats})


@app.route('/user.json')
def show_users_json():
    users = session.query(User).all()
    users_json = [u.serialize for u in users]
    return jsonify({'users': users_json})


@app.route('/item.json')
def show_items_json():
    items = session.query(Item).all()
    items_json = [i.serialize for i in items]
    return jsonify({'items': items_json})

if __name__ == '__main__':
    print('server running on port : %s' % (5000))
    app.secret_key = 'otuonye14437'
    app.debug = True
    app.run(host='0.0.0.0', port=5000)
