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
from ldap.ldapobject import SimpleLDAPObject
from zope.interface.verify import verifyClass
from repoze.who.interfaces import IAuthenticator, IMetadataProvider

from repoze.who.plugins.ldap import LDAPAuthenticatorPlugin, \
                                    LDAPAttributesPlugin
from repoze.who.plugins.ldap.plugins import make_ldap_connection


class Base(unittest.TestCase):
    """Base test case for the plugins"""
    
    def setUp(self):
        # Connecting to a fake server with a fake account:
        conn = fakeldap.initialize('ldap://example.org')
        conn.simple_bind_s('Manager', 'some password')
        # Adding a fake user, which is used in the tests
        person_attr = {'cn': [fakeuser['cn']],
                       'uid': fakeuser['uid'],
                       'userPassword': [fakeuser['hashedPassword']]}
        conn.add_s(fakeuser['dn'], modlist.addModlist(person_attr))
        self.connection = conn
        # Creating a fake environment:
        self.env  = self._makeEnviron()
    
    def tearDown(self):
        self.connection.delete_s(fakeuser['dn'])
    
    def _makeEnviron(self, kw=None):
        """Create a fake WSGI environment
        
        This is based on the same method of the test suite of repoze.who.
        
        """
        environ = {}
        environ['wsgi.version'] = (1,0)
        if kw is not None:
            environ.update(kw)
        return environ


#{ Test cases for the plugins


class TestMakeLDAPAuthenticatorPlugin(unittest.TestCase):
    """Tests for the constructor of the L{LDAPAuthenticatorPlugin} plugin"""
    
    def test_without_connection(self):
        self.assertRaises(ValueError, LDAPAuthenticatorPlugin, None,
                          'dc=example,dc=org')
    def test_without_base_dn(self):
        conn = fakeldap.initialize('ldap://example.org')
        self.assertRaises(TypeError, LDAPAuthenticatorPlugin, conn)
        self.assertRaises(ValueError, LDAPAuthenticatorPlugin, conn, None)
    
    def test_with_connection(self):
        conn = fakeldap.initialize('ldap://example.org')
        LDAPAuthenticatorPlugin(conn, 'dc=example,dc=org')
    
    def test_connection_is_url(self):
        LDAPAuthenticatorPlugin('ldap://example.org', 'dc=example,dc=org')


class TestLDAPAuthenticatorPlugin(Base):
    """Tests for the L{LDAPAuthenticatorPlugin} IAuthenticator plugin"""
    
    def setUp(self):
        super(TestLDAPAuthenticatorPlugin, self).setUp()
        # Loading the plugin:
        self.plugin = LDAPAuthenticatorPlugin(self.connection, base_dn)

    def test_implements(self):
        verifyClass(IAuthenticator, LDAPAuthenticatorPlugin, tentative=True)

    def test_authenticate_nologin(self):
        result = self.plugin.authenticate(self.env, None)
        self.assertEqual(result, None)

    def test_authenticate_incomplete_credentials(self):
        identity1 = {'login': fakeuser['uid']}
        identity2 = {'password': fakeuser['password']}
        result1 = self.plugin.authenticate(self.env, identity1)
        result2 = self.plugin.authenticate(self.env, identity2)
        self.assertEqual(result1, None)
        self.assertEqual(result2, None)

    def test_authenticate_noresults(self):
        identity = {'login': 'i_dont_exist',
                    'password': 'super secure password'}
        result = self.plugin.authenticate(self.env, identity)
        self.assertEqual(result, None)

    def test_authenticate_comparefail(self):
        identity = {'login': fakeuser['uid'],
                    'password': 'wrong password'}
        result = self.plugin.authenticate(self.env, identity)
        self.assertEqual(result, None)

    def test_authenticate_comparesuccess(self):
        identity = {'login': fakeuser['uid'],
                    'password': fakeuser['password']}
        result = self.plugin.authenticate(self.env, identity)
        self.assertEqual(result, fakeuser['dn'])
    
    def test_custom_authenticator(self):
        """L{LDAPAuthenticatorPlugin._get_dn} should be overriden with no
        problems"""
        plugin = CustomLDAPAuthenticatorPlugin(self.connection, base_dn)
        identity = {'login': fakeuser['uid'],
                    'password': fakeuser['password']}
        result = plugin.authenticate(self.env, identity)
        expected = 'uid=%s,ou=admins,%s' % (fakeuser['uid'], base_dn)
        self.assertEqual(result, expected)


class TestMakeLDAPAttributesPlugin(unittest.TestCase):
    """Tests for the constructor of L{LDAPAttributesPlugin}"""
    
    def test_connection_is_invalid(self):
        self.assertRaises(ValueError, LDAPAttributesPlugin, None, 'cn')
    
    def test_attributes_is_none(self):
        """If attributes is None then fetch all the attributes"""
        plugin = LDAPAttributesPlugin('ldap://localhost', None)
        self.assertEqual(plugin.attributes, None)
    
    def test_attributes_is_comma_separated_str(self):
        attributes = "cn,uid,mail"
        plugin = LDAPAttributesPlugin('ldap://localhost', attributes)
        self.assertEqual(plugin.attributes, attributes.split(','))
    
    def test_attributes_is_only_one_as_str(self):
        attributes = "mail"
        plugin = LDAPAttributesPlugin('ldap://localhost', attributes)
        self.assertEqual(plugin.attributes, ['mail'])
    
    def test_attributes_is_iterable(self):
        # The plugin, with a tuple as attributes
        attributes_t = ('cn', 'mail')
        plugin_t = LDAPAttributesPlugin('ldap://localhost', attributes_t)
        self.assertEqual(plugin_t.attributes, list(attributes_t))
        # The plugin, with a list as attributes
        attributes_l = ['cn', 'mail']
        plugin_l = LDAPAttributesPlugin('ldap://localhost', attributes_l)
        self.assertEqual(plugin_l.attributes, attributes_l)
        # The plugin, with a dict as attributes
        attributes_d = {'first': 'cn', 'second': 'mail'}
        plugin_d = LDAPAttributesPlugin('ldap://localhost', attributes_d)
        self.assertEqual(plugin_d.attributes, list(attributes_d))
    
    def test_attributes_is_not_iterable_nor_string(self):
        self.assertRaises(ValueError, LDAPAttributesPlugin, 'ldap://localhost',
                          12345)
    
    def test_parameters_are_valid(self):
        LDAPAttributesPlugin('ldap://localhost', 'cn', '(objectClass=*)')


class TestLDAPAttributesPlugin(Base):
    """Tests for the L{LDAPAttributesPlugin} IMetadata plugin"""

    def test_implements(self):
        verifyClass(IMetadataProvider, LDAPAttributesPlugin, tentative=True)

    def test_add_metadata(self):
        plugin = LDAPAttributesPlugin(self.connection)
        environ = {}
        identity = {'repoze.who.userid': fakeuser['dn']}
        expected_identity = {
            'repoze.who.userid': fakeuser['dn'],
            'cn': [fakeuser['cn']],
            'userPassword': [fakeuser['hashedPassword']],
            'uid': fakeuser['uid']
        }
        plugin.add_metadata(environ, identity)
        self.assertEqual(identity, expected_identity)


# Test cases for plugin utilities


class TestLDAPConnectionFactory(unittest.TestCase):
    """Tests for L{make_ldap_connection}"""
    
    def test_connection_is_object(self):
        conn = fakeldap.initialize('ldap://example.org')
        self.assertEqual(make_ldap_connection(conn), conn)
    
    def test_connection_is_str(self):
        conn = make_ldap_connection('ldap://example.org')
        self.assertTrue(isinstance(conn, SimpleLDAPObject))
    
    def test_connection_is_unicode(self):
        conn = make_ldap_connection(u'ldap://example.org')
        self.assertTrue(isinstance(conn, SimpleLDAPObject))
    
    def test_connection_is_none(self):
        self.assertRaises(ValueError, make_ldap_connection, None)


#{ Fixtures

base_dn = 'ou=people,dc=example,dc=org'
    
fakeuser = {
    'dn': 'uid=carla,%s' % base_dn,
    'uid': 'carla',
    'cn': 'Carla Paola',
    'mail': 'carla@example.org',
    'password': 'hello',
    'hashedPassword': '{SHA}qvTGHdzF6KLavt4PO0gs2a6pQ00='
}

class CustomLDAPAuthenticatorPlugin(LDAPAuthenticatorPlugin):
    """Fake class to test that L{LDAPAuthenticatorPlugin._get_dn} can be
    overriden with no problems"""
    def _get_dn(self, environ, identity):
        try:
            return u'uid=%s,ou=admins,%s' % (identity['login'], self.base_dn)
        except (KeyError, TypeError):
            raise ValueError, ('Could not find the DN from the identity and '
                               'environment')


#}


def suite():
    """
    Return the test suite.
    
    @return: The test suite for the plugin.
    @rtype: C{unittest.TestSuite}
    
    """
    suite = unittest.TestSuite()
    suite.addTest(unittest.makeSuite(TestMakeLDAPAuthenticatorPlugin, "test"))
    suite.addTest(unittest.makeSuite(TestLDAPAuthenticatorPlugin, "test"))
    suite.addTest(unittest.makeSuite(TestMakeLDAPAttributesPlugin, "test"))
    suite.addTest(unittest.makeSuite(TestLDAPAttributesPlugin, "test"))
    suite.addTest(unittest.makeSuite(TestLDAPConnectionFactory, "test"))
    return suite


if __name__ == '__main__':
    unittest.main(defaultTest='suite')
