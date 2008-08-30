# -*- coding: utf-8 -*-
#
# repoze.who.plugins.ldap, LDAP authentication for WSGI applications.
# Copyright (C) 2008 by Gustavo Narea <http://gustavonarea.net/>
#
# This file is part of repoze.who.plugins.ldap
# <http://code.gustavonarea.net/repoze.who.plugins.ldap/>
#
# repoze.who.plugins.ldap is freedomware: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by the
# Free Software Foundation, either version 3 of the License, or any later
# version.
#
# repoze.who.plugins.ldap is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of 
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General
# Public License for more details.
#
# You should have received a copy of the GNU General Public License along with
# repoze.who.plugins.ldap. If not, see <http://www.gnu.org/licenses/>.

"""LDAP plugins for repoze.who.



"""

__all__ = ['LDAPAuthenticatorPlugin']

from zope.interface import implements
import ldap

from repoze.who.interfaces import IAuthenticator

class LDAPAuthenticatorPlugin(object):

    implements(IAuthenticator)

    def __init__(self, ldap_connection):
        """Create an LDAP authentication plugin.
        
        By passing an existing LDAPObject, you're free to use the LDAP
        authentication method you want, the way you want.
        
        @param ldap_connection: An initialized LDAP connection.
        @type ldap_connection: ldap.LDAPObject
        
        """
        self.ldap_connection = ldap_connection

    # IAuthenticatorPlugin
    def authenticate(self, environ, identity):
        """Authenticate a given user with the Distinguished Name (DN) and
        password defined in 'identity'.
        
        @attention: The uid is not returned because it may not be unique; the
            DN, on the contrary, is always unique.
        @return: The Distinguished Name (DN).
        @rtype: C{unicode} or C{None}
        
        """
        
        try:
            dn = identity['dn']
            password = identity['password']
        except (KeyError, TypeError):
            return None

        if not hasattr(self.ldap_connection, 'simple_bind_s'):
            environ['repoze.who.logger'].warn('Cannot bind with the provided '
                                              'LDAP connection object')
            return None
        
        try:
            self.ldap_connection.simple_bind_s(dn, password)
            # The credentials are valid!
            return dn
        except ldap.LDAPError:
            return None

    def __repr__(self):
        return '<%s %s>' % (self.__class__.__name__, id(self))
