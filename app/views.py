from flask import Flask, render_template, make_response, request, jsonify, url_for, redirect
from flask import session as login_session, abort, flash
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

CLIENT_ID = json.loads(open('client_secret.json','r').read())['web']['client_id']

engine = create_engine("sqlite:///catalog.db")
Base.metadata.bind = engine

DBSession = sessionmaker(bind=engine)
session = DBSession()

@app.before_first_request
def seed_category_table():
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
    This higher order function when applied, protects any form post request from
    cross site request forgery attack by checking if the _csrf_token passed
    is equal to the csrf_token generated and stored in session
    """
    @wraps(f)
    def wrapper(*args, **kwds):
        if request.method == "POST":
            token = login_session.pop('_csrf_token', None)
            if not token or token != request.form.get('_csrf_token'):
                abort(403)

def is_logged_in(f):
    """
    This higher order function when applied, checks if a user is logged in
    """
    @wraps(f)
    def wrapper(*args, **kwds):
        if 'email' not in login_session:
            redirect(url_for('login_page'))

def get_csrf_token():
    if '_csrf_token' not in login_session:
        login_session['_csrf_token'] = generate_csrf_token()
    return login_session['_csrf_token']

@app.route('/login', methods=['GET'])
def login_page():
    
    if 'email' in login_session:
        return redirect(url_for('showCategories'))

    session_token = get_session_state()
    login_session['state'] = session_token
    csrf_token = get_csrf_token()
    return render_template("login.html",state=session_token,_csrf_token=csrf_token)

@app.route('/login',methods=['POST'])
def login():
    if request.args.get('state') != login_session['state']:
        return make_response("Invalide state parameter",401)

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
        response = make_response(json.dumps('Current user is already connected.'),
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

    return jsonify({'name': data['name'], 'email': data['email']})
    
@app.route('/',methods=['GET'])
@app.route('/categories',methods=['GET'])
def showCategories():
    categories = session.query(Category).all()
    return render_template('categories.html',categories=categories)

@app.route('/logout')
def logout():
    access_token = login_session['access_token']
    print('In gdisconnect access token is %s', access_token)
    print('User name is: ' )
    print(login_session['username'])
    if access_token is None:
        print('Access Token is None')
        response = make_response(json.dumps('Current user not connected.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    url = 'https://accounts.google.com/o/oauth2/revoke?token=%s' % login_session['access_token']
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
    	response = make_response(json.dumps('Failed to revoke token for given user.'),400)
    	response.headers['Content-Type'] = 'application/json'
    	return response

@app.route('category/<int:category_id>/items')
def view_category_page(category_id):
    """
    """
    items = session.query()

@is_logged_in
@app.route('/category/item/new',methods=['GET'])
def create_item_page():
    
    csrf_token = get_csrf_token()
    return render_template("create_item.html",_csrf_token=csrf_token)

@is_logged_in
@csrf_protect
@app.route('/category/item/new',methods=['POST'])
def create_new_item():
    """
    """
    user_email = login_session['email']
    user = session.query(User).filter_by(email=user_email).one()
    item_name = request.form['item_name']
    item_description = request.form['item_description']

    item = Item(name=item_name, description=item_description, created_date=datetime.now(), user_id=user.id)

    session.add(item)
    session.commit()

    flash('%s Item created successfully!!!' % item_name)
    return redirect(url_for('create_item_page'))

if __name__ == '__main__':
    print('server running on port : %s' % (5000))
    app.secret_key = 'otuonye14437'
    app.debug = True
    app.run(host='0.0.0.0',port=5000);