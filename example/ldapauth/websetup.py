"""Setup the LDAPAuth application"""
import logging

import transaction
from paste.deploy import appconfig
from tg import config

from ldapauth.config.environment import load_environment

log = logging.getLogger(__name__)

def setup_config(command, filename, section, vars):
    """Place any commands to setup ldapauth here"""
    conf = appconfig('config:' + filename)
    load_environment(conf.global_conf, conf.local_conf)
    # Load the models
    from ldapauth import model
    print "Creating tables"
    model.metadata.create_all(bind=config['pylons.app_globals'].sa_engine)

    admin = model.User()
    admin.user_name = u"gnarea"
    admin.display_name = u'Gustavo Narea'
    admin.password = u'freedomware'
    admin.email_address = 'gustavo@example.com'
    
    model.DBSession.save(admin)
    
    transaction.commit()
    
    print "Successfully setup"
