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

from os import path

import ldap

from repoze.who.plugins.ldap.plugins import LDAPAuthenticatorPlugin

__all__ = ['LDAPAuthenticatorPlugin']

# Defining the version number of the plugin:
root = path.abspath(path.dirname(
                path.dirname(path.dirname(path.dirname(path.dirname(__file__))))
       ))
__version__ = open(path.join(root, 'VERSION')).readline().rstrip()
