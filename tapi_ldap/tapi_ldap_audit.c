/* SPDX-License-Identifier: MIT */
/* Copyright (C) 2026 Interpretica, Unipessoal Lda. All rights reserved. */
/** @file
 * @brief What a directory's LDAP exposure is worth as a security posture
 *
 * Probes a directory with tapi_ldap_* and classifies the result into
 * tsf-cybersec findings. Read-only; nothing is written to the directory.
 */

#define TE_LGR_USER     "TAPI LDAP AUDIT"

#include "te_config.h"

#include <string.h>

#include "te_defs.h"
#include "te_errno.h"
#include "te_string.h"
#include "logger_api.h"

#include "tapi_ldap.h"
#include "tapi_ldap_audit.h"

/* See description in tapi_ldap_audit.h */
const tapi_ldap_audit_policy tapi_ldap_default_audit_policy = {
    .allow_anonymous = false,
    .probe_base = NULL,
};

/** Is the URI an unencrypted ldap:// (not ldaps://)? */
static bool
ldap_is_cleartext_scheme(const char *uri)
{
    return uri != NULL &&
           strncmp(uri, "ldap://", 7) == 0 &&
           strncmp(uri, "ldaps://", 8) != 0;
}

/* See description in tapi_ldap_audit.h */
te_errno
tapi_ldap_audit(rcf_rpc_server *rpcs, const char *uri,
                const tapi_ldap_audit_policy *policy,
                tapi_cybersec_report *report)
{
    te_string detail = TE_STRING_INIT;
    int result_code = -1;
    te_errno rc;

    if (policy == NULL)
        policy = &tapi_ldap_default_audit_policy;

    /* An anonymous bind with no StartTLS: the cheapest reach probe. */
    rc = tapi_ldap_bind(rpcs, uri, NULL, NULL, false, &result_code, &detail);
    if (rc != 0)
    {
        tapi_cybersec_report_add(report, TAPI_CYBERSEC_SEV_INFO,
            "ldap.not-assessed", uri,
            "the directory could not be reached (%r)", rc);
        te_string_free(&detail);
        return 0;
    }

    tapi_cybersec_report_add(report, TAPI_CYBERSEC_SEV_INFO,
        "ldap.reachable", uri, "the directory answered a bind attempt");

    if (result_code == 0)
    {
        if (!policy->allow_anonymous)
        {
            tapi_cybersec_report_add(report, TAPI_CYBERSEC_SEV_MEDIUM,
                "ldap.anonymous-bind", uri,
                "an anonymous bind was accepted");
        }

        if (ldap_is_cleartext_scheme(uri))
        {
            tapi_cybersec_report_add(report, TAPI_CYBERSEC_SEV_MEDIUM,
                "ldap.cleartext", uri,
                "a bind succeeded over ldap:// with no TLS - binds and "
                "queries travel in clear");
        }

        /* Anonymous read probe: can a stranger pull entries out of it? */
        {
            te_string dns = TE_STRING_INIT;
            int count = 0;

            if (tapi_ldap_search(rpcs, uri, NULL, NULL, false,
                                 policy->probe_base != NULL ?
                                 policy->probe_base : "",
                                 TAPI_LDAP_SCOPE_BASE, NULL, &count,
                                 &dns) == 0 && count > 0)
            {
                tapi_cybersec_report_add(report, TAPI_CYBERSEC_SEV_LOW,
                    "ldap.base-readable", uri,
                    "an anonymous search returned %d entr%s", count,
                    count == 1 ? "y" : "ies");
            }
            te_string_free(&dns);
        }
    }
    else
    {
        RING("LDAP %s: anonymous bind rejected (code %d: %s)", uri,
             result_code, te_string_value(&detail));
    }

    te_string_free(&detail);

    return 0;
}
