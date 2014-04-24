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
LDAP plugins for repoze.who.
"""

__all__ = ['LDAPBaseAuthenticatorPlugin', 'LDAPAuthenticatorPlugin',
           'LDAPSearchAuthenticatorPlugin', 'LDAPAttributesPlugin']

from base64 import b64encode, b64decode
try:  # pragma: nocover
    from urllib.parse import urlparse  # Python 3
except ImportError:  # pragma: nocover
    from urlparse import urlparse  # Python 2
import re

import ldap3
from repoze.who.interfaces import IAuthenticator, IMetadataProvider
from zope.interface import implementer


class LDAPBaseAuthenticatorPlugin(object):

    def __init__(self,
                 ldap_connection,
                 base_dn,
                 returned_id='dn',
                 start_tls=False,
                 bind_dn='',
                 bind_pass='',
                 **kwargs):
        """
        Create an LDAP authentication plugin.

        By passing an existing LDAPObject, you're free to use the LDAP
        authentication method you want, the way you want.

        This is an *abstract* class, which means it's useless in itself. You
        can only use subclasses of this class that implement the L{_get_dn}
        method (e.g., the built-in authenticators).

        This plugin is compatible with any identifier plugin that defines the
        C{login} and C{password} items in the I{identity} dictionary.

        @param ldap_connection: An initialized LDAP connection.
        @type ldap_connection: C{ldap.ldapobject.SimpleLDAPObject}
        @param base_dn: The base for the I{Distinguished Name}. Something like
            C{ou=employees,dc=example,dc=org}, to which will be prepended the
            user id: C{uid=jsmith,ou=employees,dc=example,dc=org}.
        @type base_dn: C{unicode}
        @param returned_id: Should we return the full DN or just the
            bare naming identifier value on successful authentication?
        @type returned_id: C{str}, 'dn' or 'login'
        @attention: While the DN is always unique, if you configure the
            authenticator plugin to return the bare naming attribute,
            you have to ensure its uniqueness in the DIT.
        @param start_tls: Should we negotiate a TLS upgrade on the connection
            with the directory server?
        @type start_tls: C{bool}
        @param bind_dn: Operate as the bind_dn directory entry
        @type bind_dn: C{str}
        @param bind_pass: The password for bind_dn directory entry
        @type bind_pass: C{str}

        @raise ValueError: If at least one of the parameters is not defined.

        """
        if base_dn is None:
            raise ValueError('A base Distinguished Name must be specified')

        self.server = create_server(ldap_connection)
        self.start_tls = start_tls

        self.bind_dn = bind_dn
        self.bind_pass = bind_pass

        self.base_dn = base_dn

        if returned_id.lower() == 'dn':
            self.ret_style = 'd'
        elif returned_id.lower() == 'login':
            self.ret_style = 'l'
        else:
            raise ValueError('The return style should be \'dn\' or \'login\'')

    def _get_dn(self, environ, identity):
        """
        Return the user DN based on the environment and the identity.

        Must be implemented in a subclass

        @param environ: The WSGI environment.
        @param identity: The identity dictionary.
        @return: The Distinguished Name (DN)
        @rtype: C{unicode}
        @raise ValueError: If the C{login} key is not in the I{identity} dict.

        """
        raise NotImplementedError

    def authenticate(self, environ, identity):
        """Return the naming identifier of the user to be authenticated.

        @return: The naming identifier, if the credentials were valid.
        @rtype: C{unicode} or C{None}

        """

        try:
            dn = self._get_dn(environ, identity)
            password = identity['password']
        except (KeyError, TypeError, ValueError) as e:  # NOQA
            return None

        try:
            conn = ldap3.Connection(self.server, dn, password, auto_bind=True)
            if self.start_tls:
                conn.start_tls()
            conn.close()
        except:
            return None

        userdata = identity.get('userdata', '')
        # The credentials are valid!
        if self.ret_style == 'd':
            return dn
        else:
            encoded = b64encode(dn.encode('utf-8'))
            identity['userdata'] = userdata + '<dn:%s>' % encoded
            return identity['login']

    def __repr__(self):
        return '<%s %s>' % (self.__class__.__name__, id(self))


@implementer(IAuthenticator)
class LDAPAuthenticatorPlugin(LDAPBaseAuthenticatorPlugin):

    def __init__(self,
                 ldap_connection,
                 base_dn,
                 naming_attribute='uid',
                 **kwargs):
        """
        Create an LDAP authentication plugin using pattern-determined DNs

        By passing an existing LDAPObject, you're free to use the LDAP
        authentication method you want, the way you want.

        This plugin is compatible with any identifier plugin that defines the
        C{login} and C{password} items in the I{identity} dictionary.

        @param ldap_connection: An initialized LDAP connection.
        @type ldap_connection: C{ldap.ldapobject.SimpleLDAPObject}
        @param base_dn: The base for the I{Distinguished Name}. Something like
            C{ou=employees,dc=example,dc=org}, to which will be prepended the
            user id: C{uid=jsmith,ou=employees,dc=example,dc=org}.
        @type base_dn: C{unicode}
        @param naming_attribute: The naming attribute for directory entries,
            C{uid} by default.
        @type naming_attribute: C{unicode}

        @raise ValueError: If at least one of the parameters is not defined.

        The following parameters are inherited from
        L{LDAPBaseAuthenticatorPlugin.__init__}
        @param base_dn: The base for the I{Distinguished Name}. Something like
            C{ou=employees,dc=example,dc=org}, to which will be prepended the
            user id: C{uid=jsmith,ou=employees,dc=example,dc=org}.
        @param returned_id: Should we return full Directory Names or just the
            bare naming identifier on successful authentication?
        @param start_tls: Should we negotiate a TLS upgrade on the connection
            with the directory server?
        @param bind_dn: Operate as the bind_dn directory entry
        @param bind_pass: The password for bind_dn directory entry


        """
        super(LDAPAuthenticatorPlugin, self).__init__(
            ldap_connection, base_dn, **kwargs)
        self.naming_pattern = u'%s=%%s,%%s' % naming_attribute

    def _get_dn(self, environ, identity):
        """
        Return the user naming identifier based on the environment and the
        identity.

        If the C{login} item of the identity is C{rms} and the base DN is
        C{ou=developers,dc=gnu,dc=org}, the resulting DN will be:
        C{uid=rms,ou=developers,dc=gnu,dc=org}

        @param environ: The WSGI environment.
        @param identity: The identity dictionary.
        @return: The Distinguished Name (DN)
        @rtype: C{unicode}
        @raise ValueError: If the C{login} key is not in the I{identity} dict.

        """
        try:
            return self.naming_pattern % (identity['login'], self.base_dn)
        except (KeyError, TypeError):
            raise ValueError


@implementer(IAuthenticator)
class LDAPSearchAuthenticatorPlugin(LDAPBaseAuthenticatorPlugin):

    def __init__(self,
                 ldap_connection,
                 base_dn,
                 naming_attribute='uid',
                 search_scope='subtree',
                 restrict='',
                 **kwargs):
        """Create an LDAP authentication plugin determining the DN via LDAP
        searches.

        By passing an existing LDAPObject, you're free to use the LDAP
        authentication method you want, the way you want.

        This plugin is compatible with any identifier plugin that defines the
        C{login} and C{password} items in the I{identity} dictionary.

        @param ldap_connection: An initialized LDAP connection.
        @type ldap_connection: C{ldap.ldapobject.SimpleLDAPObject}
        @param base_dn: The base for the I{Distinguished Name}. Something like
            C{ou=employees,dc=example,dc=org}, to which will be prepended the
            user id: C{uid=jsmith,ou=employees,dc=example,dc=org}.
        @type base_dn: C{unicode}
        @param naming_attribute: The naming attribute for directory entries,
            C{uid} by default.
        @type naming_attribute: C{unicode}
        @param search_scope: Scope for ldap searches
        @type search_scope: C{str}, 'subtree' or 'onelevel', possibly
            abbreviated to at least the first three characters
        @param restrict: An ldap filter which will be ANDed to the search
            filter while searching for entries matching the naming attribute
        @type restrict: C{unicode}
        @attention: restrict will be interpolated into the search string as a
            bare string like in "(&%s(identifier=login))". It must be correctly
            parenthesised for such usage as in restrict = "(objectClass=*)".

        @raise ValueError: If at least one of the parameters is not defined.

        The following parameters are inherited from
        L{LDAPBaseAuthenticatorPlugin.__init__}
        @param base_dn: The base for the I{Distinguished Name}. Something like
            C{ou=employees,dc=example,dc=org}, to which will be prepended the
            user id: C{uid=jsmith,ou=employees,dc=example,dc=org}.
        @param returned_id: Should we return full Directory Names or just the
            bare naming identifier on successful authentication?
        @param start_tls: Should we negotiate a TLS upgrade on the connection
            with the directory server?
        @param bind_dn: Operate as the bind_dn directory entry
        @param bind_pass: The password for bind_dn directory entry

        """
        super(LDAPSearchAuthenticatorPlugin, self).__init__(
            ldap_connection, base_dn, **kwargs)

        if search_scope[:3].lower() == 'sub':
            self.search_scope = ldap3.SEARCH_SCOPE_WHOLE_SUBTREE
        elif search_scope[:3].lower() == 'one':
            self.search_scope = ldap3.SEARCH_SCOPE_SINGLE_LEVEL
        else:
            raise ValueError(
                'The search scope should be \'one[level]\' or \'sub[tree]\')')

        if restrict:
            self.search_pattern = u'(&%s(%s=%%s))' % (
                restrict, naming_attribute)
        else:
            self.search_pattern = u'(%s=%%s)' % naming_attribute

    def _get_dn(self, environ, identity):
        """
        Return the DN based on the environment and the identity.

        Searches the directory entry with naming attribute matching the
        C{login} item of the identity.

        If the C{login} item of the identity is C{rms}, the naming attribute is
        C{uid} and the base DN is C{dc=gnu,dc=org}, we'll ask the server
        to search for C{uid = rms} beneath the search base, hopefully
        finding C{uid=rms,ou=developers,dc=gnu,dc=org}.

        @param environ: The WSGI environment.
        @param identity: The identity dictionary.

        @return: The Distinguished Name (DN)
        @rtype: C{unicode}

        @raise ValueError: If the C{login} key is not in the I{identity} dict.

        """
        if self.bind_dn:
            conn = ldap3.Connection(self.server, self.bind_dn, self.bind_pass,
                                    auto_bind=True)
        else:
            conn = ldap3.Connection(self.server, auto_bind=True)

        if self.start_tls:
            conn.start_tls()

        login_name = identity['login'].replace('*', r'\*')
        srch = self.search_pattern % login_name
        conn.search(self.base_dn, srch, self.search_scope)
        dn_list = conn.response
        conn.close()
        if len(dn_list) == 1:
            return dn_list[0]['dn']
        elif len(dn_list) > 1:
            raise ValueError('Too many entries found for %s' % srch)
        else:
            raise ValueError('No entry found for %s' % srch)


@implementer(IMetadataProvider)
class LDAPAttributesPlugin(object):
    """Loads LDAP attributes of the authenticated user."""

    dnrx = re.compile('<dn:(?P<b64dn>[A-Za-z0-9+/]+=*)>')

    def __init__(self,
                 ldap_connection,
                 attributes=None,
                 filterstr='(objectClass=*)',
                 start_tls='',
                 bind_dn='',
                 bind_pass='',
                 name=None,
                 flatten=False):
        """
        Fetch LDAP attributes of the authenticated user.

        @param ldap_connection: The LDAP connection to use to fetch this data.
        @type ldap_connection: C{ldap.ldapobject.SimpleLDAPObject} or C{str}
        @param attributes: The authenticated user's LDAP attributes you want to
            use in your application; an interable or a comma-separate list of
            attributes in a string, or C{None} to fetch them all. You may also
            specify key=value pairs if you wish to map the attributes to
            something the target system will understand.
        @type attributes: C{iterable} or C{str}
        @param flatten: Enables flattening of LDAP results
            (all values are lists by default)
        @type flatten: C{bool}
        @param filterstr: A filter for the search, as documented in U{RFC4515
            <http://www.faqs.org/rfcs/rfc4515.html>}; the results won't be
            filtered unless you define this.
        @type filterstr: C{str}
        @param start_tls: Should we negotiate a TLS upgrade on the connection
            with the directory server?
        @type start_tls: C{str}
        @param bind_dn: Operate as the bind_dn directory entry
        @type bind_dn: C{str}
        @param bind_pass: The password for bind_dn directory entry
        @type bind_pass: C{str}
        @param name: The property name in the identity to use
        @type name: C{str}

        @raise ValueError: If L{make_ldap_connection} could not create a
            connection from C{ldap_connection}, or if C{attributes} is not an
            iterable.
        """
        if hasattr(attributes, 'split'):
            conv = {}
            for item in attributes.split(','):
                item = item.split('=')
                if len(item) == 1:
                    key = value = item[0].strip()
                else:
                    key, value = [item[0].strip(), item[1].strip()]
                conv[key] = value
            attributes_map = conv
            attributes = list(conv.keys())

        elif hasattr(attributes, '__iter__'):
            attributes_map = dict((v, v) for v in attributes)

        elif hasattr(attributes, 'items'):
            attributes_map = attributes
            attributes = list(attributes.keys())

        elif attributes is not None:
            raise ValueError('The needed LDAP attributes are not valid')

        else:
            attributes = attributes_map = None

        self.server = create_server(ldap_connection)
        self.start_tls = start_tls

        self.name = name
        self.bind_dn = bind_dn
        self.bind_pass = bind_pass
        self.attributes = attributes
        self._attributes_map = attributes_map
        self.filterstr = filterstr
        self.flatten = str(flatten)[0].lower() == 't'

    def add_metadata(self, environ, identity):
        """
        Add metadata about the authenticated user to the identity.

        It modifies the C{identity} dictionary to add the metadata.

        @param environ: The WSGI environment.
        @param identity: The repoze.who's identity dictionary.

        """
        # Search arguments:
        dnmatch = self.dnrx.match(identity.get('userdata', ''))
        if dnmatch:
            dn = b64decode(dnmatch.group('b64dn'))
        else:
            dn = identity.get('repoze.who.userid')

        if self.bind_dn:
            conn = ldap3.Connection(self.server, self.bind_dn, self.bind_pass,
                                    auto_bind=True)
        else:
            conn = ldap3.Connection(self.server, auto_bind=True)

        if self.start_tls:
            conn.start_tls()

        status = conn.search(dn,
                             self.filterstr,
                             ldap3.SEARCH_SCOPE_BASE_OBJECT,
                             attributes=(ldap3.ALL_ATTRIBUTES
                                         if self.attributes is None
                                         else self.attributes))

        if not status:
            raise Exception('Cannot add metadata for %s: %s'
                            % (dn, conn.result))

        result = {}

        for k, v in conn.response[0]['attributes'].items():
            if self.flatten:
                v = v[0]
            if self.attributes:
                k = self._attributes_map[k]
            result[k] = v

        identity.update(result if not self.name else {self.name: result})


@implementer(IMetadataProvider)
class LDAPGroupsPlugin(object):
    """Loads LDAP groups of the authenticated user."""

    dnrx = re.compile('<dn:(?P<b64dn>[A-Za-z0-9+/]+=*)>')

    def __init__(self,
                 ldap_connection,
                 filterstr='',
                 start_tls='',
                 base_dn=None,
                 bind_dn='',
                 bind_pass='',
                 name=None,
                 search_scope='subtree',
                 naming_attribute='cn'):
        """
        Fetch LDAP attributes of the authenticated user.

        @param ldap_connection: The LDAP connection to use to fetch this data.
        @type ldap_connection: C{ldap.ldapobject.SimpleLDAPObject} or C{str}
        @param filterstr: A filter for the search, as documented in U{RFC4515
            <http://www.faqs.org/rfcs/rfc4515.html>}; the results won't be
            filtered unless you define this.
        @type filterstr: C{str}
        @param start_tls: Should we negotiate a TLS upgrade on the connection
            with the directory server?
        @type start_tls: C{str}
        @param bind_dn: Operate as the bind_dn directory entry
        @type bind_dn: C{str}
        @param bind_pass: The password for bind_dn directory entry
        @type bind_pass: C{str}
        @param name: The property name in the identity to use
        @type name: C{str}
        @param search_scope: Scope for ldap searches
        @type search_scope: C{str}, 'subtree' or 'onelevel', possibly
            abbreviated to at least the first three characters
        @param naming_attribute: The naming attribute for directory entries,
            C{gid} by default.
        @type naming_attribute: C{unicode}

        @raise ValueError: If L{make_ldap_connection} could not create a
            connection from C{ldap_connection}, or if C{attributes} is not an
            iterable.
        """
        if base_dn is None:
            raise ValueError('A base Distinguished Name must be specified')

        self.server = create_server(ldap_connection)
        self.start_tls = start_tls

        if search_scope[:3].lower() == 'sub':
            self.search_scope = ldap3.SEARCH_SCOPE_WHOLE_SUBTREE
        elif search_scope[:3].lower() == 'one':
            self.search_scope = ldap3.SEARCH_SCOPE_SINGLE_LEVEL
        else:
            raise ValueError(
                'The search scope should be \'one[level]\' or \'sub[tree]\')')

        self.name = name
        self.base_dn = base_dn
        self.bind_dn = bind_dn
        self.bind_pass = bind_pass
        self.filterstr = filterstr or (
            '(&(objectClass=groupOfUniqueNames)(uniqueMember=%(dn)s))')
        self.naming_attribute = naming_attribute

    def add_metadata(self, environ, identity):
        """
        Add LDAP group memberships of the authenticated user to the identity.

        It modifies the C{identity} dictionary to add the metadata.

        @param environ: The WSGI environment.
        @param identity: The repoze.who's identity dictionary.

        """
        # Search arguments:
        dnmatch = self.dnrx.match(identity.get('userdata', ''))
        if dnmatch:
            dn = b64decode(dnmatch.group('b64dn'))
        else:
            dn = identity.get('repoze.who.userid')

        if self.bind_dn:
            conn = ldap3.Connection(self.server, self.bind_dn, self.bind_pass,
                                    auto_bind=True)
        else:
            conn = ldap3.Connection(self.server)

        if self.start_tls:
            conn.start_tls()

        status = conn.search(self.base_dn,
                             self.filterstr % {'dn': dn},
                             self.search_scope,
                             attributes=[self.naming_attribute])

        if not status:
            raise Exception('Cannot add metadata for %s: %s'
                            % (dn, conn.result))

        groups = tuple(r['attributes'][self.naming_attribute][0]
                       for r in conn.response)

        identity[self.name] = groups


def create_server(uri):
    """
    Creates a LDAP server for use with client connections.

    @param uri: The ldap server URL
    @type uri: C{str}

    @return: The LDAP server
    @rtype: C{ldap3.Server}

    """
    if uri is None:
        raise ValueError
    try:
        uri = urlparse(uri)
    except:
        raise ValueError
    ssl = uri.scheme == 'ldaps'
    port = uri.port or (636 if ssl else 389)
    server = ldap3.Server(uri.hostname, port=port, use_ssl=ssl)
    return server
