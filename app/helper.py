import string
import random

def get_session_state():
    session_id = ''.join(random.choice(string.ascii_uppercase + string.digits)
                 for x in range(32))
    
    return session_id

def generate_csrf_token():
    csrf = ''.join(random.choice(string.ascii_uppercase + string.digits)
                 for x in range(32))
    
    return csrf
