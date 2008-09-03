===================================================================
repoze.who.plugins.ldap - LDAP Authentication for WSGI Applications
===================================================================

:Author: `Gustavo Narea <http://gustavonarea.net/>`_
:Version: |release|
:License: GNU General Public License v3
:Homepage: http://code.gustavonarea.net/repoze.who.plugins.ldap/

.. module:: repoze.who.plugins.ldap
    :synopsis: WSGI authentication middleware
 
.. toctree::
    :maxdepth: 2

`repoze.who.plugins.ldap <http://code.gustavonarea.net/repoze.who.plugins.ldap/>`_
is a `repoze.who <http://static.repoze.org/whodocs/>`_ plugin for `LDAP
<http://en.wikipedia.org/wiki/Lightweight_Directory_Access_Protocol>`_
authentication in `WSGI <http://en.wikipedia.org/wiki/Web_Server_Gateway_Interface>`_
applications. It can be used with any LDAP server and any WSGI framework, if 
you're using one.

Install
=======

To install this plugin you should run:
    easy_install repoze.who.plugins.ldap

If you have problems to install it, they are very likely to be caused by
python-ldap: You will have to install it manually in order to set the correct
path to the OpenLDAP libraries. For more information, visit:
http://python-ldap.sourceforge.net/doc/html/installing.html


Sample configuration
====================

TODO: I have to make sure that it actually works.

::

    # This script is based on
    # http://static.repoze.org/whodocs/#module-repoze.who.middleware
    from repoze.who.interfaces import IIdentifier
    from repoze.who.interfaces import IChallenger
    from repoze.who.plugins.ldap import LDAPAuthenticatorPlugin, \
                                        LDAPFormPlugin
    
    import ldap
    
    # First, you should create an LDAP connection:
    ldap_conn = ldap.initialize('ldap://ldap.yourcompany.com')
    # Then, you should pass it to repoze.who.plugins.ldap:
    ldap_auth = LDAPAuthenticatorPlugin(ldap_conn)
    form = LDAPFormPlugin('ou=employees,dc=yourcompany,dc=com', '__do_login',
                          rememberer_name='auth_tkt')
    form.classifications = { IIdentifier:['browser'],
                             IChallenger:['browser'] }
    identifiers = [('form', form)]
    authenticators = [('ldap_auth', ldap_auth)]
    challengers = [('form',form)]
    mdproviders = []
    
    from repoze.who.classifiers import default_request_classifier
    from repoze.who.classifiers import default_challenge_decider
    log_stream = None
    import os
    if os.environ.get('WHO_LOG'):
        log_stream = sys.stdout
    
    middleware = PluggableAuthenticationMiddleware(
        app,
        identifiers,
        authenticators,
        challengers,
        mdproviders,
        default_request_classifier,
        default_challenge_decider,
        log_stream = log_stream,
        log_level = logging.DEBUG
        )
    
    return middleware


Links
======

If you need help, the best place to ask is `the repoze project mailing list
<http://lists.repoze.org/listinfo/repoze-dev>`_, because the plugin author is
subscribed to this list. You may also use the `#repoze 
<irc://irc.freenode.net/repoze>`_ IRC channel or `Launchpad.net's answers for 
quick questions only <https://answers.launchpad.net/repoze.who.plugins.ldap>`_.

Development-related links include:
 - `Homepage at Launchpad.net <https://launchpad.net/repoze.who.plugins.ldap>`_.
 - `Bug tracker <https://bugs.launchpad.net/repoze.who.plugins.ldap>`_.
 - `Feature tracker <https://blueprints.launchpad.net/repoze.who.plugins.ldap>`_.
 - `Bazaar branches <https://code.launchpad.net/repoze.who.plugins.ldap>`_.


Contributing
============

Any patch is welcome, but if you can, please make sure to update the test suite
accordingly and also make sure that every test passes. Also, please try to
stick to the PEPs `8 <http://www.python.org/dev/peps/pep-0008/>`_ and `257
<http://www.python.org/dev/peps/pep-0257/>`_, as well as use `Epydoc fields
<http://epydoc.sourceforge.net/manual-fields.html>`_ where applicable.

Indices and tables
==================

* :ref:`genindex`
* :ref:`modindex`
* :ref:`search`

