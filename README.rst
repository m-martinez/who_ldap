who_ldap
========

LDAP Authentication for repoze.who-v2-enabled WSGI Applications

**This project is a fork of the original repoze.who.plugins.ldap to support
who api v2 as well as Python 3 (and 2.7)**

`who_ldap` an LDAP plugin for the identification and
authentication framework for WSGI applications, `repoze.who`, which acts as WSGI
middleware.


Installing
----------

::

  pip install who_ldap


Installing the mainline development branch
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The plugin is hosted in `a git branch hosted at github.com
<https://github.com/m-martinez/who_ldap.git>`_. To get the latest source
code, run::

    git clone git@github.com:m-martinez/who_ldap.git

Then run the command below::

    pip install -e who_ldap/


Setting up ``repoze.who`` with the LDAP authenticator
-----------------------------------------------------

This section explains how to setup ``repoze.who`` in order to use the LDAP plugins
in your WSGI application. It is based on `the documentation for repoze.who
<http://docs.repoze.org/who/2.0/>`_.

You can configure your authentication mechanism powered by ``repoze.who`` with
two methods: With an INI file or with Python code.

In the examples below we are only going to use the main plugin provided by this
package: The LDAP authenticator itself (``LDAPAuthenticatorPlugin``). The
other plugins don't deal with authentication, but are useful to load automatically
data related to the authenticated user from the LDAP server.

Using the ``repoze.who`` terminology, ``LDAPAuthenticatorPlugin`` is an
``authenticator plugin`` and the others are ``metadata provider plugins``.


Configuring ``repoze.who`` in a INI file
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

You can configure your ``repoze.who`` based authentication via a ``*.ini`` file,
and then load such settings in your application.

Say we have a file called ``who.ini`` with the following contents::

    # These contents have been adapted from:
    # http://static.repoze.org/whodocs/#middleware-configuration-via-config-file
    [plugin:form]
    use = repoze.who.plugins.form:make_plugin
    rememberer_name = auth_tkt

    [plugin:auth_tkt]
    use = repoze.who.plugins.auth_tkt:make_plugin
    secret = something

    [plugin:ldap_auth]
    use = who_ldap:LDAPAuthenticatorPlugin
    url = ldap://ldap.yourcompany.com
    base_dn = ou=developers,dc=yourcompany,dc=com

    [general]
    request_classifier = repoze.who.classifiers:default_request_classifier
    challenge_decider = repoze.who.classifiers:default_challenge_decider

    [identifiers]
    plugins =
        form;browser
        auth_tkt

    [authenticators]
    plugins =
            ldap_auth

    [challengers]
    plugins =
        form;browser


With the settings above, authentication via ``repoze.who`` is configured this way:
Visitors will login with a form, providing their user name and password; then
these credentials will be checked against the LDAP server ``ldap.yourcompany.com``
under ``ou=developers,dc=yourcompany,dc=com``. This form will be displayed
when your WSGI application issues an HTTP **401** error.

For example, if an user enters ``jsmith`` as the user name and ``valencia`` as their
password, the LDAP authenticator will build their Distinguished Name (DN) as
``uid=jsmith,ou=developers,dc=yourcompany,dc=com`` and will try to
authenticate them in the ``ldap.yourcompany.com`` LDAP server with this DN and
``valencia`` as the password.

Finally, you can load these settings by adding the `repoze.who` middleware to your
application::

    from repoze.who.config import make_middleware_with_config
    app_with_auth = make_middleware_with_config(app, global_confg, '/path/to/who.ini')

In the documentation for ``repoze.who`` there is `a more detailed explanation
<http://docs.repoze.org/who/2.0/configuration.html#configuring-repoze-who-via-config-file>`_
for the INI file method.


Framework-specific documentation
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

You may want to check the following framework-specific documents to learn tips
on how to implement `repoze.who` in the framework you are using:

 * **Pyramid**: `pyramid_who
   <http://docs.pylonsproject.org/projects/pyramid-who/en/latest>`_.
 * **Pylons**: `Authentication and Authorization with repoze.who
   <http://wiki.pylonshq.com/display/pylonscookbook/Authentication+and+Authorization+with+%60repoze.who%60>`_.
 * **TurboGears 2**: `Authentication and Authorization in TurboGears 2
   <http://www.turbogears.org/2.1/docs/main/Auth/index.html>`_
   (``repoze.who`` is the default authentication library).


Using the LDAP plugins for repoze.who
-------------------------------------

LDAPAuthenticatorPlugin
~~~~~~~~~~~~~~~~~~~~~~~

This plugin connects to the specified LDAP server and tries to `bind` with the
`Distinguished Name` (DN) made by joining the `login` in the `identity`
dictionary as the naming attribute value and the **base_dn** specified in the
constructor, and then it tries to bind with the `password` found in the
`identity` dictionary; As a default, the used naming attribute is the
user id (`uid`).

For example, if the `login` provided by the identifier is `carla` and the
**base_dn** provided in the constructor is `ou=employees,dc=example,dc=org`,
the resulting DN will be `uid=carla,ou=employees,dc=example,dc=org`.

If the directory server's naming attribute were the `email` attribute,
and we provided naming_attribute='email' in the constructor, the DN
resulting for the identifier `carla@example.org` would be
`email=carla@example.org,ou=employees,dc=example,dc=org`.

To configure this plugin from an INI file, you'd have to include a section
like this::

    [plugin:ldap_auth]
    use = who_ldap:LDAPAuthenticatorPlugin
    url = ldap://yourcompany.com
    base_dn = ou=employees,dc=yourcompany,dc=com
    naming_attribute = uid
    start_tls = True


==================== ======= ========================================================
Setting              Default Description
==================== ======= ========================================================
``url``                      **Required** Connection URL
``base_dn``                  Location to begin queries
``returned_id``      dn      Attribute to return on authentication ('dn' or 'login')
``start_tls``        False   If set, initiates TLS on the connection
``naming_attribute`` uid     Naming attribute for directory entries
==================== ======= ========================================================



LDAPSearchAuthenticatorPlugin
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

This plugin connects to the specified LDAP server and searches an entry
residing below the **base_dn**, whose naming attribute's value is equal
to the supplied login. If such an entry is found, it tries to bind as the
entry's DN with the ``password`` found in the ``identity`` dictionary; As a
default, the used naming attribute is the user id (``uid``).

The ``search_scope`` parameter in the constructor allows to choose whether
to search the entry in the whole subtree below **base_dn**, or just on
the level below if set as ``search_scope='onelevel'``.

For example, if the ``login`` provided by the identifier is ``carla`` and the
**base_dn** provided in the constructor is ``dc=example,dc=org``,
with the default settings, the system could find the entry
``uid=carla,ou=employees,dc=example,dc=org``; if we set
``search_scope='onelevel'``, the entry would not be found.

If you would like to only allow some entries, you may setup a filter
by means of the **filterstr** parameter, which is an string whose format is
defined by `RFC 4515 - Lightweight Directory Access Protocol (LDAP): String
Representation of Search Filters <http://www.faqs.org/rfcs/rfc4515.html>`_.
E.g. we can assert only person entries bearing a telephone number starting
with ``999111`` can login by setting:
``filterstr='(&(objectClass=person)(telephoneNumber=999111*))'``
in the constructor.

To configure this plugin from an INI file, you'd have to include a section
like this::

    [plugin:ldap_auth]
    use = who_ldap:LDAPSearchAuthenticatorPlugin
    url = ldap://yourcompany.com
    base_dn = ou=employees,dc=yourcompany,dc=com
    naming_attribute = uid
    search_scope = subtree
    start_tls = True

Finally, add the plugin to the set of authenticators::

    [authenticators]
    plugins =
            ldap_auth


==================== ======= =======================================================
Setting              Default Description
==================== ======= =======================================================
``url``                      **Required** Connection URL
``bind_dn``                  Operating user
``bind_pass``                Operating user password
``base_dn``                  Location to begin queries
``returned_id``      dn      Attribute to return on authentication ('dn' or 'login')
``start_tls``        False   If set, initiates TLS on the connection
``naming_attribute`` uid     Naming attribute for directory entries
``search_scope``     subtree Scope of LDAP search ('subtree' or 'onelevel')
``restrict``                 Optional additional filter for search
==================== ======= =======================================================


LDAPAttributesPlugin
~~~~~~~~~~~~~~~~~~~~

This plugin enables you to load data for the authenticated user
automatically and have it available from the WSGI environment — in the
``identity`` dictionary, specifically.

**attributes** represents
the list of user's attributes that you would like to fetch from the LDAP
server; it can be an iterable, an string where the attributes are separated
by commas, or *None* to fetch all the available attributes.

By default it loads the attributes available for *any* entry whose *DN* is
the same as the one found by ``LDAPAuthenticatorPlugin``, which is
desired in most situations.
However, if you would like to exclude some entries, you may setup a filter
by means of the **filterstr** parameter, which shares the same semantics
as the **filterstr** parameter in ``LDAPSearchAuthenticatorPlugin``.

To configure this plugin from an INI file, you'd have to include a section
like this::

    [plugin:ldap_attributes]
    use = who_ldap:LDAPAttributesPlugin
    url = ldap://ldap.yourcompany.com
    attributes = cn,sn,mail

If instead of loading the *Common Name*, *surname* and *email*, as with the
settings above, you'd prefer to load all the available attributes for the
authenticated user, you'd just have to remove the *attributes* directive.

Finally, add the plugin to the set of metadata providers::

    [mdproviders]
    plugins =
            ldap_attributes


=================== =============== =======================================================
Setting             Default         Description
=================== =============== =======================================================
``url``                             **Required** Connection URL
``bind_dn``                         Operating user
``bind_pass``                       Operating user password
``base_dn``                         Location to begin queries
``start_tls``       False           If set, initiates TLS on the connection
``attributes``                      LDAP attributes to use.
                                    Can be a simple comma-delimited list (e.g. uid,cn),
                                    or a mapping list (e.g. cn=fullname,mail=email).
``filterstr``       (objectClass=*) A filter for the search
``flatten``         False           Cleans up LDAP values if they are not lists
=================== =============== =======================================================


LDAPGroupsPlugin
~~~~~~~~~~~~~~~~

This plugin enables you to load all the group memberships of the authenticated
user.

==================== ======= =======================================================
Setting              Default Description
==================== ======= =======================================================
``url``                      **Required** Connection URL
``bind_dn``                  Operating user
``bind_pass``                Operating user password
``base_dn``                  Location to begin queries
``start_tls``        False   If set, initiates TLS on the connection
``filterstr``                A filter for the search (Default behaviour:
                             (&(objectClass=groupOfUniqueNames)(uniqueMember=%(dn)s)))
``name``                     The property name in the identity to use
``search_scope``     subtree Scope of LDAP search ('subtree' or 'onelevel')
``returned_id``      cn      Which attribute value of the group entry to return
==================== ======= =======================================================
