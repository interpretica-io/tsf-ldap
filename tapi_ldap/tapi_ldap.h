/* SPDX-License-Identifier: MIT */
/* Copyright (C) 2026 Interpretica, Unipessoal Lda. All rights reserved. */
/** @file
 * @brief Driving an LDAP directory from a test
 *
 * @defgroup tapi_ldap LDAP (tapi_ldap)
 * @{
 *
 * Binding to an LDAP directory from a Test Agent and querying it, over
 * OpenLDAP in the agent's RPC server (not by scraping @c ldapsearch):
 * an anonymous or simple bind, a search, and @c whoami. Read-only.
 *
 * - tapi_ldap_bind() tries a bind and hands back the LDAP result code -
 *   the question "will this directory accept these credentials?";
 * - tapi_ldap_search() binds and searches, returning the matching DNs;
 * - tapi_ldap_whoami() asks the server which identity a bind maps to;
 * - @ref tapi_ldap_audit (tapi_ldap_audit.h) reads a directory as a
 *   security posture through tsf-cybersec.
 */

#ifndef __TAPI_LDAP_H__
#define __TAPI_LDAP_H__

#include "te_defs.h"
#include "te_errno.h"
#include "te_string.h"
#include "rcf_rpc.h"

#include "tapi_ldap_rpc.h"

#ifdef __cplusplus
extern "C" {
#endif

/** Search scope. */
typedef enum tapi_ldap_scope {
    TAPI_LDAP_SCOPE_BASE = 0,       /**< The base object only. */
    TAPI_LDAP_SCOPE_ONELEVEL = 1,   /**< Its immediate children. */
    TAPI_LDAP_SCOPE_SUBTREE = 2,    /**< The whole subtree. */
} tapi_ldap_scope;

/**
 * Try to bind to a directory.
 *
 * @param[in]  rpcs         RPC server on the agent.
 * @param[in]  uri          @c "ldap://host" or @c "ldaps://host".
 * @param[in]  dn           Bind DN, or @c NULL/@c "" for anonymous.
 * @param[in]  password     Password, or @c NULL/@c "" for none.
 * @param[in]  starttls     Run StartTLS before binding.
 * @param[out] result_code  LDAP result (0 = bound, 49 = bad creds, ...).
 * @param[out] detail       Server/library message, or @c NULL.
 *
 * @return Status code of reaching the server (not the bind verdict).
 */
extern te_errno tapi_ldap_bind(rcf_rpc_server *rpcs, const char *uri,
                               const char *dn, const char *password,
                               te_bool starttls, int *result_code,
                               te_string *detail);

/**
 * Bind, then search, returning the matching entries' DNs.
 *
 * @param[in]  rpcs         RPC server on the agent.
 * @param[in]  uri          Directory URI.
 * @param[in]  dn           Bind DN, or @c NULL/@c "" for anonymous.
 * @param[in]  password     Password, or @c NULL/@c "" for none.
 * @param[in]  starttls     Run StartTLS before binding.
 * @param[in]  base         Search base (@c "" for the root DSE).
 * @param[in]  scope        A #tapi_ldap_scope value.
 * @param[in]  filter       Filter, or @c NULL for @c "(objectClass=*)".
 * @param[out] count        Number of entries, or @c NULL.
 * @param[out] dns          One DN per line, or @c NULL.
 *
 * @return Status code; a bind failure is @c TE_EACCES.
 */
extern te_errno tapi_ldap_search(rcf_rpc_server *rpcs, const char *uri,
                                 const char *dn, const char *password,
                                 te_bool starttls, const char *base,
                                 tapi_ldap_scope scope, const char *filter,
                                 int *count, te_string *dns);

/**
 * Bind, then ask the server which identity the bind maps to.
 *
 * @param[in]  rpcs         RPC server on the agent.
 * @param[in]  uri          Directory URI.
 * @param[in]  dn           Bind DN, or @c NULL/@c "" for anonymous.
 * @param[in]  password     Password, or @c NULL/@c "" for none.
 * @param[in]  starttls     Run StartTLS before binding.
 * @param[out] authzid      The authorization identity, or @c NULL.
 *
 * @return Status code; a bind failure is @c TE_EACCES.
 */
extern te_errno tapi_ldap_whoami(rcf_rpc_server *rpcs, const char *uri,
                                 const char *dn, const char *password,
                                 te_bool starttls, te_string *authzid);

#ifdef __cplusplus
} /* extern "C" */
#endif
#endif /* !__TAPI_LDAP_H__ */

/**@} <!-- END tapi_ldap --> */
