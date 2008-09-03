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
from repoze.who.interfaces import IAuthenticator, IIdentifier, IChallenger
from repoze.who.tests import encode_multipart_formdata, DummyIdentifier

from repoze.who.plugins.ldap import LDAPAuthenticatorPlugin, \
                                    make_authenticator_plugin, \
                                    LDAPFormPlugin, \
                                    LDAPRedirectingFormPlugin


class Base(unittest.TestCase):
    """Base test case for the plugins"""
    
    def _makeEnviron(self, kw=None):
        """Create a fake WSGI environment
        
        This is based on the same method of the test suite of repoze.who.
        
        """
        environ = {}
        environ['wsgi.version'] = (1,0)
        if kw is not None:
            environ.update(kw)
        return environ


class BaseLDAPFormTest(Base):
    """Base class for tests for L{LDAPFormPlugin}-based plugins.
    
    This is mostly based on the test case for repoze.who's FormPlugin.
    
    """

    def _makeFormEnviron(self, login=None, password=None, do_login=False):
        from StringIO import StringIO
        fields = []
        if login:
            fields.append(('login', login))
        if password:
            fields.append(('password', password))
        content_type, body = encode_multipart_formdata(fields)
        credentials = {'login': 'carla', 'password': 'hello'}
        identifier = DummyIdentifier(credentials)

        extra = {'wsgi.input':StringIO(body),
                 'wsgi.url_scheme': 'http',
                 'SERVER_NAME': 'localhost',
                 'SERVER_PORT': '8080',
                 'CONTENT_TYPE': content_type,
                 'CONTENT_LENGTH': len(body),
                 'REQUEST_METHOD': 'POST',
                 'repoze.who.plugins': {'cookie':identifier},
                 'PATH_INFO': '/protected',
                 'QUERY_STRING': '',
                 }
        if do_login:
            extra['QUERY_STRING'] = '__do_login=true'
        environ = self._makeEnviron(extra)
        return environ


class TestLDAPFormPlugin(BaseLDAPFormTest):
    """Tests for the L{LDAPFormPlugin} plugin."""
    
    def setUp(self):
        self.plugin = LDAPFormPlugin('ou=people,dc=example,dc=org',
                                        '__do_login', 'cookie', None)

    def test_implements(self):
        """The plugin implements the IIdentifier and IChallenger interfaces"""
        verifyClass(IIdentifier, LDAPFormPlugin)
        verifyClass(IChallenger, LDAPFormPlugin)

    def test_identify_no_credentials(self):
        """The identity dictionary is empty if no credentials are given"""
        environ = self._makeFormEnviron(do_login=True)
        identity = self.plugin.identify(environ)
        self.assertEqual(identity, None)

    def test_identify_no_login(self):
        """The identity dictionary is empty if no user name is given"""
        environ = self._makeFormEnviron(do_login=True, password='hello')
        identity = self.plugin.identify(environ)
        self.assertEqual(identity, None)

    def test_identify_no_password(self):
        """The identity dictionary is empty if no password is given"""
        environ = self._makeFormEnviron(do_login=True, login='carla')
        identity = self.plugin.identify(environ)
        self.assertEqual(identity, None)

    def test_identify_success(self):
        """The identity dictionary should include the DN"""
        environ = self._makeFormEnviron(do_login=True, login='carla',
                                        password='hello')
        identity = self.plugin.identify(environ)
        expected_identity = {'login': 'carla', 'password': 'hello',
                             'dn': 'uid=carla,ou=people,dc=example,dc=org'}
        self.assertEqual(identity, expected_identity)


class TestLDAPRedirectingFormPlugin(BaseLDAPFormTest):
    """Tests for the L{LDAPRedirectingFormPlugin} plugin."""
    
    def setUp(self):
        self.plugin = LDAPRedirectingFormPlugin('ou=people,dc=example,dc=org',
                                        '/', '/login', '/logout', 'cookie')

    def _makeFormEnviron(self, login=None, password=None, came_from=None,
                         path_info='/', identifier=None):
        from StringIO import StringIO
        fields = []
        if login:
            fields.append(('login', login))
        if password:
            fields.append(('password', password))
        if came_from:
            fields.append(('came_from', came_from))
        if identifier is None:
            credentials = {'login':'chris', 'password':'password'}
            identifier = DummyIdentifier(credentials)
        content_type, body = encode_multipart_formdata(fields)
        extra = {'wsgi.input':StringIO(body),
                 'wsgi.url_scheme':'http',
                 'SERVER_NAME':'www.example.com',
                 'SERVER_PORT':'80',
                 'CONTENT_TYPE':content_type,
                 'CONTENT_LENGTH':len(body),
                 'REQUEST_METHOD':'POST',
                 'repoze.who.plugins': {'cookie':identifier},
                 'QUERY_STRING':'default=1',
                 'PATH_INFO':path_info,
                 }
        environ = self._makeEnviron(extra)
        return environ

    def test_implements(self):
        """The plugin implements the IIdentifier and IChallenger interfaces"""
        verifyClass(IIdentifier, LDAPRedirectingFormPlugin)
        verifyClass(IChallenger, LDAPRedirectingFormPlugin)

    def test_identify_no_credentials(self):
        """The identity dictionary is empty if no credentials are given"""
        environ = self._makeFormEnviron()
        identity = self.plugin.identify(environ)
        self.assertEqual(identity, None)

    def test_identify_no_login(self):
        """The identity dictionary is empty if no user name is given"""
        environ = self._makeFormEnviron(password='hello')
        identity = self.plugin.identify(environ)
        self.assertEqual(identity, None)

    def test_identify_no_password(self):
        """The identity dictionary is empty if no password is given"""
        environ = self._makeFormEnviron(login='carla')
        identity = self.plugin.identify(environ)
        self.assertEqual(identity, None)

    def test_identify_success(self):
        """The identity dictionary should include the DN"""
        environ = self._makeFormEnviron(login='carla', password='hello',
                                        path_info='/login')
        identity = self.plugin.identify(environ)
        expected_identity = {'login': 'carla', 'password': 'hello',
                             'dn': 'uid=carla,ou=people,dc=example,dc=org'}
        self.assertEqual(identity, expected_identity)


class TestCustomLDAPFormPlugin(BaseLDAPFormTest):
    """Tests for a subclass of L{LDAPFormPlugin} that overrides the DN
    finder"""
    
    def setUp(self):
        self.plugin = CustomLDAPFormPlugin('dc=example,dc=org',
                                              '__do_login', 'cookie', None)

    def test_identify_success(self):
        """The identity dictionary should include the DN"""
        environ = self._makeFormEnviron(do_login=True, login='carla',
                                        password='hello')
        identity = self.plugin.identify(environ)
        expected_identity = {'login': 'carla', 'password': 'hello',
                             'dn': 'uid=carla,ou=admins,dc=example,dc=org,dc=ve'}
        self.assertEqual(identity, expected_identity)
    

class TestLDAPAuthenticatorPlugin(Base):
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


class CustomLDAPFormPlugin(LDAPFormPlugin):
    """Fake class to test that L{LDAPFormPlugin._get_dn} can be overriden
    with no problems"""
    def _get_dn(self, environ, identity):
        try:
            return u'uid=%s,ou=admins,%s,dc=ve' % (identity['login'], 
                                                   self.base_dn)
        except (KeyError, TypeError):
            raise ValueError, ('Could not find the DN from the identity and '
                               'environment')


def suite():
    """
    Return the test suite.
    
    @return: The test suite for the data model.
    @rtype: C{unittest.TestSuite}
    
    """
    suite = unittest.TestSuite()
    suite.addTest(unittest.makeSuite(TestLDAPFormPlugin, "test"))
    suite.addTest(unittest.makeSuite(TestLDAPRedirectingFormPlugin, "test"))
    suite.addTest(unittest.makeSuite(TestCustomLDAPFormPlugin, "test"))
    suite.addTest(unittest.makeSuite(TestLDAPAuthenticatorPlugin, "test"))
    suite.addTest(unittest.makeSuite(TestMakeLDAPAuthenticatorPlugin, "test"))
    return suite


if __name__ == '__main__':
    unittest.main(defaultTest='suite')
