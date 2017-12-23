import string
import random


def get_session_state():
    """
    This function returns randomized characters
    as a state token for users state management
    """
    session_id = (''.join(random.choice(string.ascii_uppercase + string.digits)
                  for x in range(32)))

    return session_id


def generate_csrf_token():
    """
    This function generates token in other to
    prevent cross site request forgery for all
    post request
    """
    csrf = (''.join(random.choice(string.ascii_uppercase + string.digits)
            for x in range(32)))

    return csrf
