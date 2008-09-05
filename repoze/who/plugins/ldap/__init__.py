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

"""repoze.who LDAP plugin

G{packagetree}

"""

import ldap

from repoze.who.plugins.ldap.plugins import LDAPAuthenticatorPlugin

__all__ = ['LDAPAuthenticatorPlugin', 'make_authenticator_plugin']


def make_authenticator_plugin(ldap_connection=None, base_dn=None):
    """
    Make an LDAPAuthenticatorPlugin plugin instance.
    
    @param ldap_connection: An LDAP connection object; if you pass an string,
        it will create the connection for you.
    @type ldap_connection: C{str}, C{unicode} or C{ldap.LDAPObject}
    @param base_dn: The base for the Distinguished Name.
    @type base_dn: C{str} or C{unicode}
    @return: An LDAP authenticator.
    @rtype: L{LDAPAuthenticatorPlugin}
    @raise ValueError: If at least one of the parameters is not defined.
    
    """
    if isinstance(ldap_connection, str) or isinstance(ldap_connection, unicode):
        ldap_connection = ldap.initialize(ldap_connection)
    elif ldap_connection is None:
        raise ValueError('ldap_connection must be specified')
    
    if base_dn is None:
        raise ValueError('A base Distinguished Name must be specified')
    
    return LDAPAuthenticatorPlugin(ldap_connection, base_dn)
