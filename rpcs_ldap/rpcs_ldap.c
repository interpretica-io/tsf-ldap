/* SPDX-License-Identifier: MIT */
/* Copyright (C) 2026 Interpretica, Unipessoal Lda. All rights reserved. */
/** @file
 * @brief LDAP RPC server library
 *
 * The ldap_* RPCs (see ldap_rpc.x.m4) on top of ta_ldap.
 * TARPC_FUNC_STATIC() binds an RPC to the function of the same name,
 * so each RPC has a plain C function first and the wrapper after it.
 */

#define TE_LGR_USER     "RPC LDAP"

#include "te_config.h"

#include <string.h>

#include "te_defs.h"
#include "te_errno.h"
#include "te_alloc.h"
#include "te_str.h"
#include "te_string.h"
#include "rpc_server.h"

#include "ta_ldap.h"

/* Hand a te_string result over to an RPC string field (never NULL). */
static char *
take(te_string *str)
{
    return str->ptr != NULL ? str->ptr : TE_STRDUP("");
}

static te_errno
ldap_bind(const char *uri, const char *dn, const char *password,
          te_bool starttls, int *result_code, char **detail)
{
    te_string d = TE_STRING_INIT;
    te_errno rc = ta_ldap_bind(uri, dn, password, starttls, result_code, &d);

    *detail = take(&d);
    return rc;
}

TARPC_FUNC_STATIC(ldap_bind, {},
{
    int result_code = -1;

    MAKE_CALL(out->retval = func(in->uri, in->dn, in->password,
                                 in->starttls, &result_code, &out->detail));
    out->result_code = result_code;
    out->common.errno_changed = false;
})

static te_errno
ldap_search(const char *uri, const char *dn, const char *password,
            te_bool starttls, const char *base, int scope,
            const char *filter, int *count, char **result)
{
    te_string r = TE_STRING_INIT;
    te_errno rc = ta_ldap_search(uri, dn, password, starttls, base, scope,
                                 filter, count, &r);

    *result = take(&r);
    return rc;
}

TARPC_FUNC_STATIC(ldap_search, {},
{
    int count = 0;

    MAKE_CALL(out->retval = func(in->uri, in->dn, in->password,
                                 in->starttls, in->base, in->scope,
                                 in->filter, &count, &out->result));
    out->count = count;
    out->common.errno_changed = false;
})

static te_errno
ldap_whoami(const char *uri, const char *dn, const char *password,
            te_bool starttls, char **authzid)
{
    te_string a = TE_STRING_INIT;
    te_errno rc = ta_ldap_whoami(uri, dn, password, starttls, &a);

    *authzid = take(&a);
    return rc;
}

TARPC_FUNC_STATIC(ldap_whoami, {},
{
    MAKE_CALL(out->retval = func(in->uri, in->dn, in->password,
                                 in->starttls, &out->authzid));
    out->common.errno_changed = false;
})
