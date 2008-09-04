"""Main Controller"""
from ldapauth.lib.base import BaseController
from tg import expose, flash
from pylons.i18n import ugettext as _

from pylons.controllers.util import abort
from pylons import request

class RootController(BaseController):
    #admin = DBMechanic(SAProvider(metadata), '/admin')

    @expose('ldapauth.templates.index')
    def index(self):
        return dict(page='index')

    @expose('ldapauth.templates.about')
    def about(self):
        if request.environ.get('repoze.who.identity') == None:
            abort(401)
        user = request.environ.get('repoze.who.identity')['user']
        flash("You are %s" % user.user_name)
        return dict(page='about')

    @expose('ldapauth.templates.index')
    def login(self, **kw):
        """
        The login section of the website.
        
        This is the page from which visitors can log in.
        
        """
        came_from = kw.get('came_from', '/')
        flash('Logged in!')
        return dict(page='login', header=lambda *arg: None,
                    footer=lambda *arg: None, came_from=came_from)

