# SPDX-License-Identifier: MIT
# Copyright (C) 2026 Interpretica, Unipessoal Lda. All rights reserved.
#
# External TE library (see TE_EXT_REPO): agent-side LDAP client over
# OpenLDAP (read-only). The agent and its RPC server both link it.

headers += files(
    'ta_ldap.h',
)

sources += files(
    'ta_ldap.c',
)

te_libs += [
    'logger_core',
    'tools',
]

# OpenLDAP ships no pkg-config on many distributions, so fall back to
# finding the libraries and the header directly.
cc = meson.get_compiler('c')

ldap_dep = dependency('ldap', required: false)
if not ldap_dep.found()
    ldap_dep = cc.find_library('ldap', has_headers: 'ldap.h')
endif

lber_dep = dependency('lber', required: false)
if not lber_dep.found()
    lber_dep = cc.find_library('lber', has_headers: 'lber.h')
endif

deps += [
    ldap_dep,
    lber_dep,
]
