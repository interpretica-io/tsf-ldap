/* SPDX-License-Identifier: MIT */
/* Copyright (C) 2026 Interpretica, Unipessoal Lda. All rights reserved. */
/** @file
 * @brief LDAP TAPI: RPC client wrappers
 *
 * The rcf_rpc_call() boilerplate behind tapi_ldap. The RPCs return
 * te_errno; an RPC transport failure is mapped to TE_ECORRUPTED.
 */

#define TE_LGR_USER     "TAPI LDAP RPC"

#include "te_config.h"

#include <string.h>

#include "te_defs.h"
#include "te_errno.h"
#include "te_string.h"
#include "logger_api.h"
#include "tapi_rpc_internal.h"
#include "tarpc.h"

#include "tapi_ldap_rpc.h"

#define CHECK_RPC_ERRNO_UNCHANGED(_func, _var) \
    CHECK_RETVAL_VAR_ERR_COND(_func, _var, false,                    \
                              TE_RC(TE_TAPI, TE_ECORRUPTED), false)

/* Append an RPC string result, when there is one. */
static void
take_string(te_string *dst, const char *src)
{
    if (dst != NULL && src != NULL)
        te_string_append(dst, "%s", src);
}

/* See description in tapi_ldap_rpc.h */
te_errno
rpc_ldap_bind(rcf_rpc_server *rpcs, const char *uri, const char *dn,
              const char *password, te_bool starttls, int *result_code,
              te_string *detail)
{
    tarpc_ldap_bind_in in;
    tarpc_ldap_bind_out out;

    memset(&in, 0, sizeof(in));
    memset(&out, 0, sizeof(out));
    in.uri = (char *)(uri != NULL ? uri : "");
    in.dn = (char *)(dn != NULL ? dn : "");
    in.password = (char *)(password != NULL ? password : "");
    in.starttls = starttls;

    rcf_rpc_call(rpcs, "ldap_bind", &in, &out);
    CHECK_RPC_ERRNO_UNCHANGED(ldap_bind, out.retval);
    TAPI_RPC_LOG(rpcs, ldap_bind, "%s dn=%s tls=%d", "%r code=%d",
                 uri != NULL ? uri : "", dn != NULL ? dn : "", starttls,
                 out.retval, out.result_code);

    if (out.retval == 0 && result_code != NULL)
        *result_code = out.result_code;
    take_string(detail, out.detail);
    RETVAL_TE_ERRNO(ldap_bind, out.retval);
}

/* See description in tapi_ldap_rpc.h */
te_errno
rpc_ldap_search(rcf_rpc_server *rpcs, const char *uri, const char *dn,
                const char *password, te_bool starttls, const char *base,
                int scope, const char *filter, int *count,
                te_string *result)
{
    tarpc_ldap_search_in in;
    tarpc_ldap_search_out out;

    memset(&in, 0, sizeof(in));
    memset(&out, 0, sizeof(out));
    in.uri = (char *)(uri != NULL ? uri : "");
    in.dn = (char *)(dn != NULL ? dn : "");
    in.password = (char *)(password != NULL ? password : "");
    in.starttls = starttls;
    in.base = (char *)(base != NULL ? base : "");
    in.scope = scope;
    in.filter = (char *)(filter != NULL ? filter : "");

    rcf_rpc_call(rpcs, "ldap_search", &in, &out);
    CHECK_RPC_ERRNO_UNCHANGED(ldap_search, out.retval);
    TAPI_RPC_LOG(rpcs, ldap_search, "%s base=%s scope=%d", "%r count=%d",
                 uri != NULL ? uri : "", base != NULL ? base : "", scope,
                 out.retval, out.count);

    if (out.retval == 0)
    {
        if (count != NULL)
            *count = out.count;
        take_string(result, out.result);
    }
    RETVAL_TE_ERRNO(ldap_search, out.retval);
}

/* See description in tapi_ldap_rpc.h */
te_errno
rpc_ldap_whoami(rcf_rpc_server *rpcs, const char *uri, const char *dn,
                const char *password, te_bool starttls, te_string *authzid)
{
    tarpc_ldap_whoami_in in;
    tarpc_ldap_whoami_out out;

    memset(&in, 0, sizeof(in));
    memset(&out, 0, sizeof(out));
    in.uri = (char *)(uri != NULL ? uri : "");
    in.dn = (char *)(dn != NULL ? dn : "");
    in.password = (char *)(password != NULL ? password : "");
    in.starttls = starttls;

    rcf_rpc_call(rpcs, "ldap_whoami", &in, &out);
    CHECK_RPC_ERRNO_UNCHANGED(ldap_whoami, out.retval);
    TAPI_RPC_LOG(rpcs, ldap_whoami, "%s dn=%s", "%r",
                 uri != NULL ? uri : "", dn != NULL ? dn : "", out.retval);

    if (out.retval == 0)
        take_string(authzid, out.authzid);
    RETVAL_TE_ERRNO(ldap_whoami, out.retval);
}
