Changelog
=========

3.1.0 (2015-02-09)
--------------------

- Search for users via filter if present [domruf]
- Switch to ``ldap3`` package (which was renamed from ``python3-ldap``) [Cito]
- Convert b64de/encode byte strings to regular strings in Python 3 [Cito]
- Use (objectClass=*) if no filter is specified when scope is base.


3.0.2 (2014-06-11)
------------------

- Issue log messages instead of exceptions for invalid credentials. [lovelle]


3.0.1 (2014-05-19)
------------------

- Updated documentation


3.0.0 (2014-05-19)
------------------

- Major code cleanup
- Deprecated ``LDAPBaseAuthenticatorPlugin``
-
- No longer accepts ldap_connection since in order to ensure connections are
  closed.
- Allows to aliasing of LDAP properties
- Switched group ``naming_attribute`` to ``returned_id``


2.0.0 (2014-04-29)
------------------

- Forked original project
  (https://pypi.python.org/pypi/repoze.who.plugins.ldap)
- Updated to work with repoze.who v2 API
- Python 3.4 compatibility
- Allows to aliasing of LDAP properties
- Added group metadata provider


1.2 Alpha 2 (unreleased)
------------------------

- Fixed installation problems under Windows (`Bug #608622
  <https://bugs.launchpad.net/repoze.who.plugins.ldap/+bug/608622>`_).


1.1 Alpha 1 (2010-01-03)
------------------------

- Changed the license to the `Repoze license <http://repoze.org/license.html>`_.
- Provided ``start_tls`` option both for the authenticator and the metadata
  provider.
- Enable both pattern-replacement and subtree searches for the naming
  attribute in ``_get_dn()``.
- Enable configuration of the naming attribute
- Enable the option to bind to the server with privileged credential before
  doing searches
- Add a restrict pattern to pre-authentication DN searches
- Let the user choose whether to return the full DN or the supplied login as
  the user identifier


1.0 (2008-09-11)
----------------

The initial release.

- Provided the LDAP authenticator, which is compatible with identifiers that
  define the 'login' item in the identity dict.
- Included the plugin to load metadata about the authenticated user from the
  LDAP server.
- Documented how to install and use the plugins.
- Included Turbogears 3 demo project, using the plugin. There is also a section
  in the documentation to explain how the demo works.
