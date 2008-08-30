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

"""Test suite for repoze.who.plugins.ldap"""

import unittest

from dataflake.ldapconnection.tests import fakeldap
from ldap import modlist
from zope.interface.verify import verifyClass
from repoze.who.interfaces import IAuthenticator

from repoze.who.plugins.ldap import LDAPAuthenticatorPlugin, \
                                    make_authenticator_plugin


class TestLDAPAuthenticatorPlugin(unittest.TestCase):
    fakeuser = {
        'dn': 'uid=carla,ou=people,dc=example,dc=org',
        'uid': 'carla',
        'cn': 'Carla Paola',
        'password': 'hello',
        'hashedPassword': '{SHA}qvTGHdzF6KLavt4PO0gs2a6pQ00='}
    
    def setUp(self):
        # Connecting to a fake server with a fake account:
        conn = fakeldap.initialize('ldap://example.org')
        conn.simple_bind_s('Manager', 'some password')
        # Adding a fake user, which is used in the tests
        person_attr = {'cn': [self.fakeuser['cn']],
                       'uid': self.fakeuser['uid'],
                       'userPassword': [self.fakeuser['hashedPassword']]}
        conn.add_s(self.fakeuser['dn'], modlist.addModlist(person_attr))
        self.connection = conn
        # Creating a fake environment:
        self.env  = self._makeEnviron()
        # Loading the plugin:
        self.plugin = LDAPAuthenticatorPlugin(self.connection)
    
    def tearDown(self):
        self.connection.delete_s(self.fakeuser['dn'])
    
    def _makeEnviron(self, kw=None):
        environ = {}
        environ['wsgi.version'] = (1,0)
        if kw is not None:
            environ.update(kw)
        return environ

    def test_implements(self):
        verifyClass(IAuthenticator, LDAPAuthenticatorPlugin, tentative=True)

    def test_authenticate_nologin(self):
        result = self.plugin.authenticate(self.env, None)
        self.assertEqual(result, None)

    def test_authenticate_incomplete_credentials(self):
        identity1 = {'dn': self.fakeuser['dn']}
        identity2 = {'password': self.fakeuser['password']}
        result1 = self.plugin.authenticate(self.env, identity1)
        result2 = self.plugin.authenticate(self.env, identity2)
        self.assertEqual(result1, None)
        self.assertEqual(result2, None)

    def test_authenticate_noresults(self):
        identity = {'dn': 'uid=i_dont_exist,dc=example,dc=org',
                    'password': 'some super secure password'}
        result = self.plugin.authenticate(self.env, identity)
        self.assertEqual(result, None)

    def test_authenticate_comparefail(self):
        identity = {'dn': self.fakeuser['dn'],
                    'password': 'wrong password'}
        result = self.plugin.authenticate(self.env, identity)
        self.assertEqual(result, None)

    def test_authenticate_comparesuccess(self):
        identity = {'dn': self.fakeuser['dn'],
                    'password': self.fakeuser['password']}
        result = self.plugin.authenticate(self.env, identity)
        self.assertEqual(result, self.fakeuser['dn'])


class TestMakeLDAPAuthenticatorPlugin(unittest.TestCase):
    def test_without_connection(self):
        f = make_authenticator_plugin
        self.assertRaises(ValueError, make_authenticator_plugin)
    
    def test_with_connection(self):
        conn = fakeldap.initialize('ldap://example.org')
        authenticator = make_authenticator_plugin(conn)
        assert authenticator.__class__ == LDAPAuthenticatorPlugin


def suite():
    """
    Return the test suite.
    
    @return: The test suite for the data model.
    @rtype: C{unittest.TestSuite}
    
    """
    suite = unittest.TestSuite()
    suite.addTest(unittest.makeSuite(TestLDAPAuthenticatorPlugin, "test"))
    suite.addTest(unittest.makeSuite(TestMakeLDAPAuthenticatorPlugin, "test"))
    return suite


if __name__ == '__main__':
    unittest.main(defaultTest='suite')
