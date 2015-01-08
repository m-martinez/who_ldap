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
from subprocess import Popen, PIPE
import sys


HERE = os.path.abspath(os.path.dirname(__file__))
README = open(os.path.join(HERE, 'README.rst')).read()
CHANGELOG = open(os.path.join(HERE, 'CHANGES.rst')).read()


REQUIRES = [
    'repoze.who>=2.0',
    'ldap3>=0.9.0',
    'setuptools',
    'zope.interface',
]


EXTRAS = {
    'test': ['nose', 'coverage']
}


def get_version():
    version_file = os.path.join(HERE, 'VERSION')

    # read fallback file
    try:
        with open(version_file, 'r+') as fp:
            version_txt = fp.read().strip()
    except:
        version_txt = None

    # read git version (if available)
    try:
        version_git = (
            Popen(['git', 'describe'], stdout=PIPE, stderr=PIPE, cwd=HERE)
            .communicate()[0]
            .strip()
            .decode(sys.getdefaultencoding()))
    except:
        version_git = None

    version = version_git or version_txt or '0.0.0'

    # update fallback file if necessary
    if version != version_txt:
        with open(version_file, 'w') as fp:
            fp.write(version)

    return version


setup(
    name='who_ldap',
    version=get_version(),
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
    extras_require=EXTRAS,
    tests_require=EXTRAS['test'],
    test_suite='nose.collector'
)
