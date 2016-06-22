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

import os
from setuptools import setup, find_packages


HERE = os.path.abspath(os.path.dirname(__file__))
README = open(os.path.join(HERE, 'README.rst')).read()
CHANGELOG = open(os.path.join(HERE, 'CHANGES.rst')).read()


REQUIRES = [
    'repoze.who>=2.3',
    'ldap3>=0.9.0',
    'setuptools',
    'zope.interface',
]

TESTS_REQUIRE = ['nose', 'coverage']


setup(
    name='who_ldap',
    version='3.2.1',
    description='LDAP plugin for repoze.who',
    long_description='\n\n'.join([README, CHANGELOG]),
    classifiers=[
        'Intended Audience :: Developers',
        'Natural Language :: English',
        'Operating System :: OS Independent',
        'Programming Language :: Python',
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 3.4',
        'Topic :: Internet :: WWW/HTTP :: WSGI :: Middleware',
        ('Topic :: System :: Systems Administration :: '
            'Authentication/Directory :: LDAP')
    ],
    keywords='ldap web application server wsgi repoze repoze.who',
    author='Marco Martinez',
    url='https://github.com/m-martinez/who_ldap.git',
    license='BSD-derived (http://www.repoze.org/LICENSE.txt)',
    include_package_data=True,
    package_dir={'': 'src'},
    packages=find_packages('src'),
    zip_safe=False,
    install_requires=REQUIRES,
    extras_require={'test': TESTS_REQUIRE},
    tests_require=TESTS_REQUIRE,
    test_suite='nose.collector'
)
