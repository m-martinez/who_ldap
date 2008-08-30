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

import os

from setuptools import setup, find_packages

here = os.path.abspath(os.path.dirname(__file__))
README = open(os.path.join(here, 'README')).read()
CHANGELOG = open(os.path.join(here, 'CHANGELOG')).read()
version = open(os.path.join(here, 'VERSION')).readline().rstrip()

setup(
    name='repoze.who.plugins.ldap',
    version=version,
    description="LDAP plugin for repoze.who",
    long_description='\n\n'.join([README, CHANGELOG]),
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: GNU General Public License (GPL)",
        "Natural Language :: English",
        "Operating System :: OS Independent",
        "Programming Language :: Python",
        "Topic :: Internet :: WWW/HTTP :: WSGI :: Middleware",
        "Topic :: System :: Systems Administration :: Authentication/Directory :: LDAP"
    ],
    keywords='ldap web application server wsgi repoze repoze.who',
    author="Gustavo Narea",
    author_email="me@gustavonarea.net",
    url="http://code.gustavonarea.net/repoze.who.plugins.ldap/",
    download_url="https://launchpad.net/repoze.who.plugins.ldap/+download",
    license="GNU General Public License v3",
    packages=find_packages(),
    include_package_data=True,
    namespace_packages=['repoze', 'repoze.who', 'repoze.who.plugins'],
    zip_safe=False,
    tests_require = 'dataflake.ldapconnection>=0.3',
    install_requires=[
        'repoze.who>=1.0.6',
        'python-ldap>=2.3.5',
        'setuptools',
        'zope.interface'
        ],
    test_suite="repoze.who.plugins.ldap.tests"
    )
