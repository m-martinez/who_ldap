from paste.httpexceptions import HTTPFound
from ldapauth.model import DBSession, User

class UserModelPlugin(object):
    
    def authenticate(self, environ, identity):
        try:
            username = identity['login']
            password = identity['password']
        except KeyError:
            return None
        
        results = DBSession.query(User).filter(User.user_name==username)
        
        if results.count() != 1:
            # There are zero or 2+ results
            return None
        
        the_user = results[0]
        
        if the_user.validate_password(password):
            return username
        else:
            return None

    def add_metadata(self, environ, identity):
        username = identity.get('repoze.who.userid')
        user = DBSession.query(User).filter(User.user_name==username).first()
        
        if user is not None:
            identity['user'] = user
