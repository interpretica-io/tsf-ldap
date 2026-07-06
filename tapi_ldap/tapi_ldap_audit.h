/* SPDX-License-Identifier: MIT */
/* Copyright (C) 2026 Interpretica, Unipessoal Lda. All rights reserved. */
/** @file
 * @brief What a directory's LDAP exposure is worth as a security posture
 *
 * @defgroup tapi_ldap_audit LDAP security posture
 * @ingroup tapi_ldap
 * @{
 *
 * An LDAP directory read as a security posture and reported through
 * tsf-cybersec: does it accept an anonymous bind, does it carry a bind
 * over an unencrypted @c ldap:// channel (no StartTLS, no @c ldaps),
 * and does an anonymous client get to read entries out of it.
 *
 * It binds and reads; it writes nothing to the directory. It still
 * talks to a real service, so it is for an **authorized** assessment -
 * a directory you own or are engaged to test. Point it only there.
 *
 * | Finding | Severity | Raised when |
 * |---|---|---|
 * | @c ldap.reachable | info | the directory answered a bind attempt |
 * | @c ldap.anonymous-bind | medium | an anonymous bind was accepted |
 * | @c ldap.cleartext | medium | a bind succeeded over ldap:// with no TLS |
 * | @c ldap.base-readable | low | an anonymous search returned entries |
 * | @c ldap.not-assessed | info | the directory could not be reached |
 *
 * A finding's subject is the directory URI, which is stable between
 * runs.
 */

#ifndef __TAPI_LDAP_AUDIT_H__
#define __TAPI_LDAP_AUDIT_H__

#include "te_errno.h"
#include "rcf_rpc.h"

#include "tapi_cybersec.h"

#ifdef __cplusplus
extern "C" {
#endif

/** What a directory's LDAP exposure is expected to be. */
typedef struct tapi_ldap_audit_policy {
    /** An anonymous bind is acceptable (it often is for the root DSE). */
    bool allow_anonymous;
    /**
     * Base DN for the anonymous-read probe, or @c NULL to use the empty
     * base (the root DSE). An empty string probes the root DSE too.
     */
    const char *probe_base;
} tapi_ldap_audit_policy;

/**
 * The default: anonymous bind flagged, the anonymous-read probe over
 * the root DSE.
 */
extern const tapi_ldap_audit_policy tapi_ldap_default_audit_policy;

/**
 * Read a directory's LDAP posture into @p report.
 *
 * @param[in]  rpcs     RPC server on the agent.
 * @param[in]  uri      @c "ldap://host" or @c "ldaps://host".
 * @param[in]  policy   What is expected, or @c NULL for the default.
 * @param[out] report   Report to append findings to.
 *
 * @return Status code of reading the posture, not its verdict.
 */
extern te_errno tapi_ldap_audit(rcf_rpc_server *rpcs, const char *uri,
                                const tapi_ldap_audit_policy *policy,
                                tapi_cybersec_report *report);

#ifdef __cplusplus
} /* extern "C" */
#endif
#endif /* !__TAPI_LDAP_AUDIT_H__ */

/**@} <!-- END tapi_ldap_audit --> */
