"""Main Controller"""
from ldapauth.lib.base import BaseController
from tg import expose, flash

from pylons.controllers.util import abort
from pylons import request

class RootController(BaseController):
    @expose('ldapauth.templates.index')
    def index(self):
        return dict()

    @expose('ldapauth.templates.about')
    def about(self):
        if request.environ.get('repoze.who.identity') == None:
            abort(401)
        user = request.environ['repoze.who.identity']['repoze.who.userid']
        flash('Your Distinguished Name (DN) is "%s"' % user)
        return dict()
