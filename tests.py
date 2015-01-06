# -*- coding: utf-8 -*-
#
# who_ldap, LDAP authentication for WSGI applications.
# Copyright (C) 2010-2014 by contributors <see CONTRIBUTORS file>
#
# This file is part of who_ldap
# <https://github.com/m-martinez/who_ldap.git>
#
# This software is subject to the provisions of the BSD-like license at
# http://www.repoze.org/LICENSE.txt.  A copy of the license should accompany
# this distribution.  THIS SOFTWARE IS PROVIDED 'AS IS' AND ANY AND ALL
# EXPRESS OR IMPLIED WARRANTIES ARE DISCLAIMED, INCLUDING, BUT NOT LIMITED TO,
# THE IMPLIED WARRANTIES OF TITLE, MERCHANTABILITY, AGAINST INFRINGEMENT, AND
# FITNESS FOR A PARTICULAR PURPOSE.
"""
Test suite for who_ldap

Uses an actual connection, and attempts to create the testing items
"""

import unittest

BIND_HOST = 'localhost'
BIND_PORT = 389
BIND_URI = 'ldap://%s:%s' % (BIND_HOST, BIND_PORT)
BIND_DN = 'cn=root,dc=example,dc=org'
BIND_PW = 'some password'

DOMAIN_DN = 'dc=example,dc=org'
BASE_DN = 'ou=people,dc=example,dc=org'

fakeuser = {
    'dn': 'uid=carla,%s' % BASE_DN,
    'uid': 'carla',
    'cn': 'Carla Paola',
    'sn': 'Paola',
    'mail': 'carla@example.org',
    'telephoneNumber': '39 123 456 789',
    'password': 'hello',
    'hashedPassword': '{SHA}qvTGHdzF6KLavt4PO0gs2a6pQ00='
}


def setup_module():
    clear()
    import ldap3
    # Connecting to a fake server with a fake account:
    server = ldap3.Server(BIND_HOST, port=BIND_PORT)
    conn = ldap3.Connection(
        server, user=BIND_DN, password=BIND_PW, auto_bind=True)
    # We must explicitly create the BASE_DN DIT components
    # Not in ldap3?
    # Adding a fake user, which is used in the tests
    person_attr = {'cn': fakeuser['cn'],
                   'sn': fakeuser['sn'],
                   'uid': fakeuser['uid'],
                   'userPassword': fakeuser['hashedPassword'],
                   'telephoneNumber': fakeuser['telephoneNumber'],
                   'mail': fakeuser['mail']}
    assert conn.add(DOMAIN_DN, 'domain'), conn.result
    assert conn.add(BASE_DN, 'organizationalUnit'), conn.result
    assert conn.add(fakeuser['dn'], 'inetOrgPerson', person_attr), conn.result
    conn.close()


def teardown_module():
    clear()


def clear():
    import ldap3
    # Connecting to a fake server with a fake account:
    server = ldap3.Server(BIND_HOST, port=BIND_PORT)
    conn = ldap3.Connection(
        server, user=BIND_DN, password=BIND_PW, auto_bind=True)
    conn.delete(fakeuser['dn'])
    conn.delete(BASE_DN)
    conn.delete(DOMAIN_DN)
    conn.close()


class AssertMixin(object):

    def assertCountEqual(self, *args, **kw):
        if hasattr(self, 'assertItemsEqual'):
            self.assertItemsEqual(*args, **kw)
        else:
            super(AssertMixin, self).assertCountEqual(*args, **kw)


class Base(unittest.TestCase):
    """Base test case for the plugins"""

    def makeEnviron(self, kw=None):
        """Create a fake WSGI environment

        This is based on the same method of the test suite of repoze.who.

        """
        environ = {}
        environ['wsgi.version'] = (1, 0)
        if kw:
            environ.update(kw)
        return environ


class TestMakeLDAPAuthenticatorPlugin(unittest.TestCase):
    """Tests for the constructor of the L{LDAPAuthenticatorPlugin} plugin"""

    def test_without_connection(self):
        from who_ldap import LDAPAuthenticatorPlugin
        self.assertRaises(ValueError, LDAPAuthenticatorPlugin, None,
                          'dc=example,dc=org')

    def test_without_BASE_DN(self):
        from who_ldap import LDAPAuthenticatorPlugin
        self.assertRaises(TypeError, LDAPAuthenticatorPlugin, BIND_URI)
        self.assertRaises(ValueError, LDAPAuthenticatorPlugin, BIND_URI, None)

    def test_connection_is_url(self):
        from who_ldap import LDAPAuthenticatorPlugin
        LDAPAuthenticatorPlugin('ldap://example.org', 'dc=example,dc=org')


class TestLDAPAuthenticatorPlugin(Base):
    """Tests for the L{LDAPAuthenticatorPlugin} IAuthenticator plugin"""

    def makePlugin(self):
        from who_ldap import LDAPAuthenticatorPlugin
        return LDAPAuthenticatorPlugin(BIND_URI, BASE_DN)

    def test_implements(self):
        from zope.interface.verify import verifyClass
        from repoze.who.interfaces import IAuthenticator
        from who_ldap import LDAPAuthenticatorPlugin
        verifyClass(IAuthenticator, LDAPAuthenticatorPlugin, tentative=True)

    def test_authenticate_nologin(self):
        plugin = self.makePlugin()
        env = self.makeEnviron()
        result = plugin.authenticate(env, None)
        self.assertIsNone(result)

    def test_authenticate_incomplete_credentials(self):
        plugin = self.makePlugin()
        env = self.makeEnviron()
        identity1 = {'login': fakeuser['uid']}
        identity2 = {'password': fakeuser['password']}
        result1 = plugin.authenticate(env, identity1)
        result2 = plugin.authenticate(env, identity2)
        self.assertIsNone(result1)
        self.assertIsNone(result2)

    def test_authenticate_noresults(self):
        identity = {'login': 'i_dont_exist',
                    'password': 'super secure password'}
        plugin = self.makePlugin()
        env = self.makeEnviron()
        result = plugin.authenticate(env, identity)
        self.assertIsNone(result)

    def test_authenticate_comparefail(self):
        plugin = self.makePlugin()
        env = self.makeEnviron()
        identity = {'login': fakeuser['uid'],
                    'password': 'wrong password'}
        result = plugin.authenticate(env, identity)
        self.assertIsNone(result)

    def test_authenticate_comparesuccess(self):
        plugin = self.makePlugin()
        env = self.makeEnviron()
        identity = {'login': fakeuser['uid'],
                    'password': fakeuser['password']}
        result = plugin.authenticate(env, identity)
        self.assertEqual(result, fakeuser['dn'])

    def test_custom_authenticator(self):
        """L{LDAPAuthenticatorPlugin._get_dn} should be overriden with no
        problems"""
        from who_ldap import LDAPAuthenticatorPlugin

        class CustomLDAPAuthenticatorPlugin(LDAPAuthenticatorPlugin):
            """Fake class to test that L{LDAPAuthenticatorPlugin._get_dn} can
            be overriden with no problems"""

            def _get_dn(self, environ, identity):
                self.called = True
                try:
                    return u'uid=%s,%s' % (identity['login'], self.base_dn)
                except (KeyError, TypeError):
                    raise ValueError(
                        'Could not find the DN from the identity '
                        'and environment')
        plugin = CustomLDAPAuthenticatorPlugin(BIND_URI, BASE_DN)
        env = self.makeEnviron()
        identity = {'login': fakeuser['uid'],
                    'password': fakeuser['password']}
        result = plugin.authenticate(env, identity)
        expected = 'uid=%s,%s' % (fakeuser['uid'], BASE_DN)
        self.assertEqual(result, expected)
        self.assertTrue(plugin.called)


class TestLDAPSearchAuthenticatorPluginNaming(Base):
    """Tests for the L{LDAPSearchAuthenticatorPlugin} IAuthenticator plugin"""

    def makePlugin(self):
        from who_ldap import LDAPSearchAuthenticatorPlugin
        return LDAPSearchAuthenticatorPlugin(
            BIND_URI,
            BASE_DN,
            naming_attribute='telephoneNumber',
            )

    def test_authenticate_noresults(self):
        plugin = self.makePlugin()
        env = self.makeEnviron()
        identity = {'login': 'i_dont_exist',
                    'password': 'super secure password'}
        result = plugin.authenticate(env, identity)
        self.assertIsNone(result)

    def test_authenticate_comparefail(self):
        plugin = self.makePlugin()
        env = self.makeEnviron()
        identity = {'login': fakeuser['telephoneNumber'],
                    'password': 'wrong password'}
        result = plugin.authenticate(env, identity)
        self.assertIsNone(result)

    def test_authenticate_comparesuccess(self):
        plugin = self.makePlugin()
        env = self.makeEnviron()
        identity = {'login': fakeuser['telephoneNumber'],
                    'password': fakeuser['password']}
        result = plugin.authenticate(env, identity)
        self.assertEqual(result, fakeuser['dn'])


class TestLDAPAuthenticatorReturnLogin(Base):
    """
    Tests the L{LDAPAuthenticatorPlugin} IAuthenticator plugin returning
    login.

    """

    def makePlugin(self):
        from who_ldap import LDAPAuthenticatorPlugin
        return LDAPAuthenticatorPlugin(
            BIND_URI,
            BASE_DN,
            returned_id='login',
            )

    def test_authenticate_noresults(self):
        plugin = self.makePlugin()
        env = self.makeEnviron()
        identity = {'login': 'i_dont_exist',
                    'password': 'super secure password'}
        result = plugin.authenticate(env, identity)
        self.assertIsNone(result)

    def test_authenticate_comparefail(self):
        plugin = self.makePlugin()
        env = self.makeEnviron()
        identity = {'login': fakeuser['uid'],
                    'password': 'wrong password'}
        result = plugin.authenticate(env, identity)
        self.assertIsNone(result)

    def test_authenticate_comparesuccess(self):
        plugin = self.makePlugin()
        env = self.makeEnviron()
        identity = {'login': fakeuser['uid'],
                    'password': fakeuser['password']}
        result = plugin.authenticate(env, identity)
        self.assertEqual(result, fakeuser['uid'])

    def test_authenticate_dn_in_userdata(self):
        from base64 import b64encode
        plugin = self.makePlugin()
        env = self.makeEnviron()
        identity = {'login': fakeuser['uid'],
                    'password': fakeuser['password']}
        expected_dn = '<dn:%s>' % b64encode(fakeuser['dn'].encode('utf-8'))
        result = plugin.authenticate(env, identity)  # NOQA
        self.assertEqual(identity['userdata'], expected_dn)


class TestLDAPSearchAuthenticatorReturnLogin(Base):
    """
    Tests the L{LDAPSearchAuthenticatorPlugin} IAuthenticator plugin returning
    login.

    """

    def makePlugin(self):
        from who_ldap import LDAPSearchAuthenticatorPlugin
        return LDAPSearchAuthenticatorPlugin(
            BIND_URI,
            BASE_DN,
            returned_id='login',
            )

    def test_authenticate_noresults(self):
        plugin = self.makePlugin()
        env = self.makeEnviron()
        identity = {'login': 'i_dont_exist',
                    'password': 'super secure password'}
        result = plugin.authenticate(env, identity)
        self.assertIsNone(result)

    def test_authenticate_comparefail(self):
        plugin = self.makePlugin()
        env = self.makeEnviron()
        identity = {'login': fakeuser['uid'],
                    'password': 'wrong password'}
        result = plugin.authenticate(env, identity)
        self.assertIsNone(result)

    def test_authenticate_comparesuccess(self):
        plugin = self.makePlugin()
        env = self.makeEnviron()
        identity = {'login': fakeuser['uid'],
                    'password': fakeuser['password']}
        result = plugin.authenticate(env, identity)
        self.assertEqual(result, fakeuser['uid'])

    def test_authenticate_dn_in_userdata(self):
        from base64 import b64encode
        plugin = self.makePlugin()
        env = self.makeEnviron()
        identity = {'login': fakeuser['uid'],
                    'password': fakeuser['password']}
        expected_dn = '<dn:%s>' % b64encode(fakeuser['dn'].encode('utf-8'))
        result = plugin.authenticate(env, identity)  # NOQA
        self.assertEqual(identity['userdata'], expected_dn)


class TestLDAPAuthenticatorPluginStartTls(Base):
    """Tests for the L{LDAPAuthenticatorPlugin} IAuthenticator plugin"""

    def test_implements(self):
        from zope.interface.verify import verifyClass
        from repoze.who.interfaces import IAuthenticator
        from who_ldap import LDAPAuthenticatorPlugin
        verifyClass(IAuthenticator, LDAPAuthenticatorPlugin, tentative=True)


class TestMakeLDAPAttributesPlugin(unittest.TestCase, AssertMixin):
    """Tests for the constructor of L{LDAPAttributesPlugin}"""

    def test_connection_is_invalid(self):
        from who_ldap import LDAPAttributesPlugin
        self.assertRaises(ValueError, LDAPAttributesPlugin, None, 'cn')

    def test_attributes_is_none(self):
        """If attributes is None then fetch all the attributes"""
        from who_ldap import LDAPAttributesPlugin
        plugin = LDAPAttributesPlugin(BIND_URI, None)
        self.assertIsNone(plugin.attributes)

    def test_attributes_is_comma_separated_str(self):
        from who_ldap import LDAPAttributesPlugin
        attributes = "cn,uid,mail"
        plugin = LDAPAttributesPlugin(BIND_URI, attributes)
        self.assertCountEqual(plugin.attributes, attributes.split(','))

    def test_attributes_is_only_one_as_str(self):
        from who_ldap import LDAPAttributesPlugin
        attributes = "mail"
        plugin = LDAPAttributesPlugin(BIND_URI, attributes)
        self.assertEqual(plugin.attributes, ['mail'])

    def test_attributes_is_iterable(self):
        from who_ldap import LDAPAttributesPlugin
        # The plugin, with a tuple as attributes
        attributes_t = ('cn', 'mail')
        plugin_t = LDAPAttributesPlugin(BIND_URI, attributes_t)
        self.assertCountEqual(plugin_t.attributes, list(attributes_t))
        # The plugin, with a list as attributes
        attributes_l = ['cn', 'mail']
        plugin_l = LDAPAttributesPlugin(BIND_URI, attributes_l)
        self.assertCountEqual(plugin_l.attributes, attributes_l)
        # The plugin, with a dict as attributes
        attributes_d = {'first': 'cn', 'second': 'mail'}
        plugin_d = LDAPAttributesPlugin(BIND_URI, attributes_d)
        self.assertCountEqual(plugin_d.attributes, list(attributes_d))

    def test_attributes_is_not_iterable_nor_string(self):
        from who_ldap import LDAPAttributesPlugin
        self.assertRaises(ValueError, LDAPAttributesPlugin, BIND_URI,
                          12345)

    def test_parameters_are_valid(self):
        from who_ldap import LDAPAttributesPlugin
        LDAPAttributesPlugin(BIND_URI, 'cn', '(objectClass=*)')


class TestLDAPAttributesPlugin(Base):
    """Tests for the L{LDAPAttributesPlugin} IMetadata plugin"""

    def test_implements(self):
        from who_ldap import LDAPAttributesPlugin
        from zope.interface.verify import verifyClass
        from repoze.who.interfaces import IMetadataProvider
        verifyClass(IMetadataProvider, LDAPAttributesPlugin, tentative=True)

    def test_add_metadata(self):
        from who_ldap import LDAPAttributesPlugin
        plugin = LDAPAttributesPlugin(BIND_URI)
        environ = {}
        identity = {'repoze.who.userid': fakeuser['dn']}
        expected_identity = {
            'repoze.who.userid': fakeuser['dn'],
            'cn': [fakeuser['cn']],
            'sn': [fakeuser['sn']],
            'objectClass': ['inetOrgPerson'],
            'userPassword': [fakeuser['hashedPassword']],
            'uid': [fakeuser['uid']],
            'telephoneNumber': [fakeuser['telephoneNumber']],
            'mail': [fakeuser['mail']]
        }
        plugin.add_metadata(environ, identity)
        self.assertDictEqual(identity, expected_identity)
