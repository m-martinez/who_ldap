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
LDAP plugins for repoze.who v2 API
"""

from base64 import b64encode, b64decode
try:  # pragma: nocover
    from urllib.parse import urlparse  # Python 3
except ImportError:  # pragma: nocover
    from urlparse import urlparse  # Python 2
import re

from ldap3 import (
    Server,
    Connection,
    ALL_ATTRIBUTES,
    SEARCH_SCOPE_WHOLE_SUBTREE,
    SEARCH_SCOPE_SINGLE_LEVEL,
    SEARCH_SCOPE_BASE_OBJECT
)
from repoze.who.interfaces import IAuthenticator, IMetadataProvider
from zope.interface import implementer
import logging


DNRX = re.compile('<dn:(?P<b64dn>[A-Za-z0-9+/]+=*)>')


def make_connection(url, bind_dn, bind_pass):
    """
    Makes a LDAP Connection
    """
    uri = urlparse(url)
    ssl = uri.scheme == 'ldaps'
    port = uri.port or (636 if ssl else 389)
    server = Server(uri.hostname, port=port, use_ssl=ssl)
    return Connection(server, bind_dn, bind_pass)


def parse_map(mapstr):
    if not mapstr:
        return
    result = {}
    for item in mapstr.split(','):
        item = item.split('=')
        if len(item) == 1:
            key = value = item[0].strip()
        else:
            key, value = [item[0].strip(), item[1].strip()]
        result[key] = value
    return result


def extract_userdata(identity):
    match = DNRX.search(identity.get('userdata', ''))
    if not match:
        return
    return b64decode(match.group('b64dn')).decode('utf-8')


def save_userdata(identity, dn):
    userdata = identity.get('userdata') or ''
    encoded = '<dn:%s>' % b64encode(dn.encode('utf-8')).decode('ascii')
    identity['userdata'] = userdata + encoded


@implementer(IAuthenticator)
class LDAPAuthenticatorPlugin(object):
    """
    Authenticates directly as the user's DN
    """

    def __init__(self,
                 url,
                 base_dn,
                 start_tls=False,
                 returned_id='dn',
                 naming_attribute='uid'
                 ):
        """
        Parameters:
        url -- LDAP URL
        base_dn -- Base node to search
        start_tls -- Flag to initiate TLS upgrade on connection
        returned_id -- id to return on success ('dn' or 'login')
        naming_attribute -- naming attribute for directory entries
        """
        returned_id = returned_id or 'dn'
        naming_attribute = naming_attribute or 'uid'

        assert url, u'Connection URL is required'
        assert base_dn, u'Base DN is required'
        assert returned_id.lower() in ('dn', 'login'), \
            u'The return style should be \'dn\' or \'login\''

        self.url = url
        self.base_dn = base_dn
        self.start_tls = bool(start_tls)
        self.ret_style = 'd' if returned_id.lower() == 'dn' else 'l'
        self.naming_pattern = u'%s=%%s,%%s' % naming_attribute

    # IAuthenticator
    def authenticate(self, environ, identity):
        if 'login' not in identity:
            return
        dn = self.naming_pattern % (identity['login'], self.base_dn)
        with make_connection(self.url, dn, identity['password']) as conn:
            if self.start_tls:
                conn.start_tls()
            if not conn.bind():
                return
            save_userdata(identity, dn)
            return dn if self.ret_style == 'd' else identity['login']


@implementer(IAuthenticator)
class LDAPSearchAuthenticatorPlugin(object):
    """
    Authenticates the user by performing a search from a base DN
    """

    def __init__(self,
                 url,
                 base_dn,
                 bind_dn='',
                 bind_pass='',
                 start_tls=False,
                 returned_id='dn',
                 naming_attribute='uid',
                 search_scope='subtree',
                 restrict=''
                 ):
        """
        Parameters:
        url -- LDAP URL
        base_dn -- Base node to search
        bind_dn -- User for querying the LDAP database
        bind_pass -- User password
        start_tls -- Flag to initiate TLS upgrade on connection
        returned_id -- id to return on success ('dn' or 'login')
        naming_attribute -- naming attribute for directory entries
        search_scope -- Scope of search ('onelevel' or 'subtree')
        restrict -- Additional search criterion ANDed to search string.
        """
        returned_id = returned_id or 'dn'
        naming_attribute = naming_attribute or 'uid'
        search_scope = search_scope or 'subtree'

        assert url, u'Connection URL is required'
        assert base_dn, u'Base DN is required'
        assert bind_dn, u'Bind DN is required'
        assert bind_pass, u'Bind DN is required'
        assert returned_id.lower() in ('dn', 'login'), \
            u'The return style should be \'dn\' or \'login\''
        assert search_scope.lower()[:3] in ('one', 'sub'), \
            u'The search scope should be \'one[level]\' or \'sub[tree]\')'

        self.url = url
        self.base_dn = base_dn
        self.bind_dn = bind_dn
        self.bind_pass = bind_pass
        self.start_tls = bool(start_tls)
        self.ret_style = 'd' if returned_id.lower() == 'dn' else 'l'
        self.naming_pattern = u'%s=%%s,%%s' % naming_attribute
        self.search_scope = \
            SEARCH_SCOPE_WHOLE_SUBTREE \
            if search_scope.lower().startswith('sub') \
            else SEARCH_SCOPE_SINGLE_LEVEL
        if restrict:
            self.search_pattern = u'(&%s(%s=%%s))' % (
                restrict, naming_attribute)
        else:
            self.search_pattern = u'(%s=%%s)' % naming_attribute

    # IAuthenticator
    def authenticate(self, environ, identity):
        logger = logging.getLogger('repoze.who')

        if 'login' not in identity:
            return

        with make_connection(self.url, self.bind_dn, self.bind_pass) as conn:
            if self.start_tls:
                conn.start_tls()

            if not conn.bind():
                logger.error('Cannot establish connection')
                return

            search = \
                self.search_pattern % identity['login'].replace('*', r'\*')
            conn.search(self.base_dn, search, self.search_scope)

            if len(conn.response) > 1:
                logger.error('Too many entries found for %s', search)
                return
            if len(conn.response) < 1:
                logger.warn('No entry found for %s', search)
                return

            dn = conn.response[0]['dn']

            with make_connection(self.url, dn, identity['password']) as check:
                if not check.bind():
                    return
                save_userdata(identity, dn)
                return dn if self.ret_style == 'd' else identity['login']


@implementer(IMetadataProvider)
class LDAPAttributesPlugin(object):
    """
    Loads LDAP attributes of the authenticated user.
    """

    def __init__(self,
                 url,
                 bind_dn='',
                 bind_pass='',
                 start_tls=False,
                 filterstr='',
                 name=None,
                 attributes=None,
                 flatten=False):
        """
        Parameters:
        url -- LDAP URL
        bind_dn -- User for querying the LDAP database
        bind_pass -- User password
        start_tls -- Flag to initiate TLS upgrade on connection
        filterstr -- Filter for the search.
                     See http://www.faqs.org/rfcs/rfc4515.html
                     Results won't be filtered unless you specify this.
        name -- property name in the identity to populate. If not specified,
                will specify the identity itself.
        attributes -- attributes to use. Can be a comma-delimited list
                      of `name` or `name=alias` pairs (which will remap
                      attribute names to the desired alias)
        flatten -- If values contain a single item,
                   they will be converted to a scalar
        """
        attributes_map = parse_map(attributes)

        assert url, u'Connection URL is required'

        self.url = url
        self.bind_dn = bind_dn
        self.bind_pass = bind_pass
        self.start_tls = bool(start_tls)

        self.name = name
        self.attributes = \
            list(attributes_map.keys()) if attributes_map else ALL_ATTRIBUTES
        self._attributes_map = attributes_map
        self.filterstr = filterstr
        self.flatten = str(flatten)[0].lower() == 't'

    # IMetadataProvider
    def add_metadata(self, environ, identity):
        logger = logging.getLogger('repoze.who')

        with make_connection(self.url, self.bind_dn, self.bind_pass) as conn:
            if self.start_tls:
                conn.start_tls()
            if not conn.bind():
                logger.error('Cannot establish connection')
                return

            # Behave like search if filterstr is specified, otherwise use base
            if self.filterstr:
                search_scope = SEARCH_SCOPE_WHOLE_SUBTREE
                filterstr = self.filterstr.format(identity=identity)
                # XXX This might need to be a setting?
                base_dn = ''
            else:
                search_scope = SEARCH_SCOPE_BASE_OBJECT
                filterstr = '(objectClass=*)'   # ldap requires a filter string
                base_dn = extract_userdata(identity)
                if not base_dn:
                    logger.error('Malformed userdata')
                    return

            status = conn.search(
                base_dn,
                filterstr,
                search_scope,
                attributes=self.attributes)

            if not status:
                logger.error(
                    'Cannot add user metadata for %s: %s',
                    identity.get('repoze.who.userid'),
                    conn.result)
                return

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
    """
    Add LDAP group memberships of the authenticated user to the identity.
    """

    def __init__(self,
                 url,
                 base_dn,
                 bind_dn='',
                 bind_pass='',
                 start_tls=False,
                 filterstr='',
                 name=None,
                 search_scope='subtree',
                 returned_id='cn'):
        """
        Parameters:
        url -- LDAP URL
        base_dn -- Base node to search
        bind_dn -- User for querying the LDAP database
        bind_pass -- User password
        start_tls -- Flag to initiate TLS upgrade on connection
        filterstr -- Filter for the search.
                     See http://www.faqs.org/rfcs/rfc4515.html
                     Results won't be filtered unless you specify this.
        name -- property name in the identity to populate. If not specified,
                will specify the identity itself.
        search_scope  -- [sub]tree or [one]level of search
        returned_id -- naming attribute or group directory entries

        """
        returned_id = returned_id or 'cn'
        search_scope = search_scope or 'subtree'

        assert url, u'Connection URL is required'
        assert base_dn, u'Base DN is required'
        assert bind_dn, u'Bind DN is required'
        assert bind_pass, u'Bind DN is required'
        assert search_scope.lower()[:3] in ('one', 'sub'), \
            u'The search scope should be \'one[level]\' or \'sub[tree]\')'

        self.url = url
        self.base_dn = base_dn
        self.bind_dn = bind_dn
        self.bind_pass = bind_pass
        self.start_tls = bool(start_tls)
        self.search_scope = \
            SEARCH_SCOPE_WHOLE_SUBTREE \
            if search_scope.lower().startswith('sub') \
            else SEARCH_SCOPE_SINGLE_LEVEL

        self.name = name
        self.filterstr = filterstr or (
            '(&(objectClass=groupOfUniqueNames)(uniqueMember=%(dn)s))')
        self.returned_id = returned_id

    # IMetadataProvider
    def add_metadata(self, environ, identity):
        logger = logging.getLogger('repoze.who')

        with make_connection(self.url, self.bind_dn, self.bind_pass) as conn:
            if self.start_tls:
                conn.start_tls()
            if not conn.bind():
                logger.error('Cannot establish connection')
                return

            dn = extract_userdata(identity)

            if not dn:
                logger.error('Malformed userdata')
                return

            status = conn.search(self.base_dn,
                                 self.filterstr % {'dn': dn},
                                 self.search_scope,
                                 attributes=[self.returned_id])

            if not status:
                logger.error(
                    'Cannot add group metadata for %s: %s',
                    identity.get('repoze.who.userid'),
                    conn.result)
                return

            groups = tuple(r['attributes'][self.returned_id][0]
                           for r in conn.response)

            identity[self.name] = groups
