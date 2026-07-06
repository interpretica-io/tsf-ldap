/* SPDX-License-Identifier: MIT */
/* Copyright (C) 2026 Interpretica, Unipessoal Lda. All rights reserved. */
/** @file
 * @brief LDAP TAPI: RPC client wrappers
 *
 * Client wrappers of the ldap_* RPCs, see ldap_rpc.x.m4. Tests use
 * tapi_ldap.h; these are the calls behind it, one per RPC.
 */

#ifndef __TAPI_LDAP_RPC_H__
#define __TAPI_LDAP_RPC_H__

#include "te_errno.h"
#include "te_string.h"
#include "rcf_rpc.h"

#ifdef __cplusplus
extern "C" {
#endif

/** Try a bind; @p result_code gets the LDAP result (0 ok). */
extern te_errno rpc_ldap_bind(rcf_rpc_server *rpcs, const char *uri,
                              const char *dn, const char *password,
                              te_bool starttls, int *result_code,
                              te_string *detail);

/** Bind then search; @p result is one DN per line, @p count their number. */
extern te_errno rpc_ldap_search(rcf_rpc_server *rpcs, const char *uri,
                                const char *dn, const char *password,
                                te_bool starttls, const char *base,
                                int scope, const char *filter, int *count,
                                te_string *result);

/** Bind then RFC 4532 "Who am I?". */
extern te_errno rpc_ldap_whoami(rcf_rpc_server *rpcs, const char *uri,
                                const char *dn, const char *password,
                                te_bool starttls, te_string *authzid);

#ifdef __cplusplus
} /* extern "C" */
#endif
#endif /* !__TAPI_LDAP_RPC_H__ */
