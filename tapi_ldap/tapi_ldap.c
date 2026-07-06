/* SPDX-License-Identifier: MIT */
/* Copyright (C) 2026 Interpretica, Unipessoal Lda. All rights reserved. */
/** @file
 * @brief Driving an LDAP directory from a test
 *
 * The test-facing layer over the ldap_* RPCs; each call is a thin,
 * named pass-through to the agent's OpenLDAP client.
 */

#define TE_LGR_USER     "TAPI LDAP"

#include "te_config.h"

#include "te_defs.h"
#include "te_errno.h"
#include "te_string.h"

#include "tapi_ldap.h"

/* See description in tapi_ldap.h */
te_errno
tapi_ldap_bind(rcf_rpc_server *rpcs, const char *uri, const char *dn,
               const char *password, te_bool starttls, int *result_code,
               te_string *detail)
{
    return rpc_ldap_bind(rpcs, uri, dn, password, starttls, result_code,
                         detail);
}

/* See description in tapi_ldap.h */
te_errno
tapi_ldap_search(rcf_rpc_server *rpcs, const char *uri, const char *dn,
                 const char *password, te_bool starttls, const char *base,
                 tapi_ldap_scope scope, const char *filter, int *count,
                 te_string *dns)
{
    return rpc_ldap_search(rpcs, uri, dn, password, starttls, base,
                           (int)scope, filter, count, dns);
}

/* See description in tapi_ldap.h */
te_errno
tapi_ldap_whoami(rcf_rpc_server *rpcs, const char *uri, const char *dn,
                 const char *password, te_bool starttls, te_string *authzid)
{
    return rpc_ldap_whoami(rpcs, uri, dn, password, starttls, authzid);
}
