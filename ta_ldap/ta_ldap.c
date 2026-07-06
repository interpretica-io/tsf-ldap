/* SPDX-License-Identifier: MIT */
/* Copyright (C) 2026 Interpretica, Unipessoal Lda. All rights reserved. */
/** @file
 * @brief Agent-side LDAP client over OpenLDAP
 *
 * Written against the OpenLDAP 2.6 client API (ldap_initialize,
 * ldap_sasl_bind_s with LDAP_SASL_SIMPLE, ldap_search_ext_s,
 * ldap_whoami_s). The library is linked and called in-process; nothing
 * is spawned. A connection is opened, used and closed within each call.
 */

#define TE_LGR_USER     "TA LDAP"

#include "te_config.h"

#include <stdlib.h>
#include <string.h>

#include <ldap.h>

#include "te_defs.h"
#include "te_errno.h"
#include "te_alloc.h"
#include "te_str.h"
#include "te_string.h"
#include "logger_api.h"

#include "ta_ldap.h"

/** Open @p uri, set LDAP v3, optionally StartTLS. */
static te_errno
ldap_open(const char *uri, te_bool starttls, LDAP **ld)
{
    int version = LDAP_VERSION3;
    int rc;

    *ld = NULL;
    rc = ldap_initialize(ld, uri);
    if (rc != LDAP_SUCCESS || *ld == NULL)
    {
        ERROR("ldap_initialize(%s): %s", uri != NULL ? uri : "",
              ldap_err2string(rc));
        return TE_RC(TE_TA_UNIX, TE_ECONNREFUSED);
    }

    ldap_set_option(*ld, LDAP_OPT_PROTOCOL_VERSION, &version);

    if (starttls)
    {
        rc = ldap_start_tls_s(*ld, NULL, NULL);
        if (rc != LDAP_SUCCESS)
        {
            ERROR("ldap_start_tls_s(%s): %s", uri, ldap_err2string(rc));
            ldap_unbind_ext_s(*ld, NULL, NULL);
            *ld = NULL;
            return TE_RC(TE_TA_UNIX, TE_ECOMM);
        }
    }

    return 0;
}

/** Simple bind (anonymous when @p dn/@p pw are empty); returns LDAP rc. */
static int
ldap_simple_bind(LDAP *ld, const char *dn, const char *pw)
{
    struct berval cred;

    cred.bv_val = (char *)(pw != NULL ? pw : "");
    cred.bv_len = pw != NULL ? strlen(pw) : 0;

    return ldap_sasl_bind_s(ld, (dn != NULL && dn[0] != '\0') ? dn : NULL,
                            LDAP_SASL_SIMPLE, &cred, NULL, NULL, NULL);
}

/* See description in ta_ldap.h */
te_errno
ta_ldap_bind(const char *uri, const char *bind_dn, const char *password,
             te_bool starttls, int *result_code, te_string *detail)
{
    LDAP *ld = NULL;
    te_errno rc;
    int lrc;

    *result_code = -1;

    rc = ldap_open(uri, starttls, &ld);
    if (rc != 0)
        return rc;

    lrc = ldap_simple_bind(ld, bind_dn, password);
    *result_code = lrc;
    if (detail != NULL)
        te_string_append(detail, "%s", ldap_err2string(lrc));

    ldap_unbind_ext_s(ld, NULL, NULL);

    return 0;
}

/** Bind helper shared by search/whoami: open + bind, TE_EACCES on reject. */
static te_errno
ldap_connect_bound(const char *uri, const char *dn, const char *pw,
                   te_bool starttls, LDAP **ld)
{
    te_errno rc = ldap_open(uri, starttls, ld);
    int lrc;

    if (rc != 0)
        return rc;

    lrc = ldap_simple_bind(*ld, dn, pw);
    if (lrc != LDAP_SUCCESS)
    {
        ERROR("bind to %s: %s", uri, ldap_err2string(lrc));
        ldap_unbind_ext_s(*ld, NULL, NULL);
        *ld = NULL;
        return TE_RC(TE_TA_UNIX, TE_EACCES);
    }

    return 0;
}

/* See description in ta_ldap.h */
te_errno
ta_ldap_search(const char *uri, const char *bind_dn, const char *password,
               te_bool starttls, const char *base, int scope,
               const char *filter, int *count, te_string *result)
{
    LDAP *ld = NULL;
    LDAPMessage *res = NULL;
    LDAPMessage *e;
    te_errno rc;
    int lrc;

    *count = 0;

    rc = ldap_connect_bound(uri, bind_dn, password, starttls, &ld);
    if (rc != 0)
        return rc;

    lrc = ldap_search_ext_s(ld, base != NULL ? base : "", scope,
                            filter != NULL ? filter : "(objectClass=*)",
                            NULL, 0, NULL, NULL, NULL, 0, &res);
    if (lrc != LDAP_SUCCESS)
    {
        ERROR("ldap_search_ext_s(%s): %s", base != NULL ? base : "",
              ldap_err2string(lrc));
        if (res != NULL)
            ldap_msgfree(res);
        ldap_unbind_ext_s(ld, NULL, NULL);
        return TE_RC(TE_TA_UNIX, TE_EFAIL);
    }

    for (e = ldap_first_entry(ld, res); e != NULL;
         e = ldap_next_entry(ld, e))
    {
        char *dn = ldap_get_dn(ld, e);

        te_string_append(result, "%s\n", dn != NULL ? dn : "");
        if (dn != NULL)
            ldap_memfree(dn);
        (*count)++;
    }

    ldap_msgfree(res);
    ldap_unbind_ext_s(ld, NULL, NULL);

    return 0;
}

/* See description in ta_ldap.h */
te_errno
ta_ldap_whoami(const char *uri, const char *bind_dn, const char *password,
               te_bool starttls, te_string *authzid)
{
    LDAP *ld = NULL;
    struct berval *id = NULL;
    te_errno rc;
    int lrc;

    rc = ldap_connect_bound(uri, bind_dn, password, starttls, &ld);
    if (rc != 0)
        return rc;

    lrc = ldap_whoami_s(ld, &id, NULL, NULL);
    if (lrc != LDAP_SUCCESS)
    {
        ERROR("ldap_whoami_s(%s): %s", uri, ldap_err2string(lrc));
        ldap_unbind_ext_s(ld, NULL, NULL);
        return TE_RC(TE_TA_UNIX, TE_EFAIL);
    }

    if (id != NULL)
    {
        if (id->bv_val != NULL && id->bv_len != 0)
            te_string_append(authzid, "%.*s", (int)id->bv_len, id->bv_val);
        ber_bvfree(id);
    }

    ldap_unbind_ext_s(ld, NULL, NULL);

    return 0;
}
