/* SPDX-License-Identifier: MIT */
/* Copyright (C) 2026 Interpretica, Unipessoal Lda. All rights reserved. */
/** @file
 * @brief Agent-side LDAP client
 *
 * An LDAP client on top of **OpenLDAP** (@c ldap.h / @c lber.h,
 * @c -lldap @c -llber): bind (anonymous or simple), search, and
 * @c whoami, driven from a Test Agent. The library is linked into the
 * agent and called in-process - no @c ldapsearch is spawned. The agent
 * and its RPC server both link this; the RPCs (see ldap_rpc.x.m4) are
 * thin wrappers over these functions.
 *
 * Read-only: it binds, searches and reads, it writes nothing to the
 * directory. Every call names its target by URI and carries its own
 * credentials, so nothing survives between calls - a connection is
 * opened, used and closed each time, the same stateless shape tsf-usb
 * and tsf-upnp use. Results that are lists come back as newline-
 * separated text, one record per line with tab-separated fields.
 */

#ifndef __TA_LDAP_H__
#define __TA_LDAP_H__

#include "te_defs.h"
#include "te_errno.h"
#include "te_string.h"

#ifdef __cplusplus
extern "C" {
#endif

/** Search scope, matching OpenLDAP's @c LDAP_SCOPE_*. */
enum {
    TA_LDAP_SCOPE_BASE = 0,     /**< The base object only. */
    TA_LDAP_SCOPE_ONELEVEL = 1, /**< Its immediate children. */
    TA_LDAP_SCOPE_SUBTREE = 2,  /**< The whole subtree. */
};

/**
 * Try to bind to a directory and report the LDAP result.
 *
 * Opens @p uri, sets protocol version 3, optionally runs StartTLS, and
 * does a simple bind. An anonymous bind is @p bind_dn @c NULL/empty and
 * @p password @c NULL/empty. The connection is closed before return.
 *
 * @param[in]  uri          @c "ldap://host" or @c "ldaps://host".
 * @param[in]  bind_dn      Bind DN, or @c NULL/@c "" for anonymous.
 * @param[in]  password     Password, or @c NULL/@c "" for none.
 * @param[in]  starttls     Run StartTLS before binding.
 * @param[out] result_code  The LDAP result code (0 = success, 49 =
 *                          invalid credentials, ...).
 * @param[out] detail       The server/library message; may be empty.
 *
 * @return Status code of reaching the server (not the bind verdict).
 * @retval TE_ECONNREFUSED  The endpoint could not be reached.
 */
extern te_errno ta_ldap_bind(const char *uri, const char *bind_dn,
                             const char *password, te_bool starttls,
                             int *result_code, te_string *detail);

/**
 * Bind, then search, and return the matching entries' DNs.
 *
 * @param[in]  uri          Directory URI.
 * @param[in]  bind_dn      Bind DN, or @c NULL/@c "" for anonymous.
 * @param[in]  password     Password, or @c NULL/@c "" for none.
 * @param[in]  starttls     Run StartTLS before binding.
 * @param[in]  base         Search base DN (@c "" for the root DSE).
 * @param[in]  scope        A @c TA_LDAP_SCOPE_* value.
 * @param[in]  filter       LDAP filter, or @c NULL for
 *                          @c "(objectClass=*)".
 * @param[out] count        Number of entries returned.
 * @param[out] result       One DN per line.
 *
 * @return Status code. A bind failure is @c TE_EACCES.
 */
extern te_errno ta_ldap_search(const char *uri, const char *bind_dn,
                               const char *password, te_bool starttls,
                               const char *base, int scope,
                               const char *filter, int *count,
                               te_string *result);

/**
 * Bind, then ask the server who it thinks you are (RFC 4532).
 *
 * @param[in]  uri          Directory URI.
 * @param[in]  bind_dn      Bind DN, or @c NULL/@c "" for anonymous.
 * @param[in]  password     Password, or @c NULL/@c "" for none.
 * @param[in]  starttls     Run StartTLS before binding.
 * @param[out] authzid      The authorization identity the server
 *                          reports (e.g. @c "dn:..." or @c "u:..."),
 *                          empty for an anonymous identity.
 *
 * @return Status code. A bind failure is @c TE_EACCES.
 */
extern te_errno ta_ldap_whoami(const char *uri, const char *bind_dn,
                               const char *password, te_bool starttls,
                               te_string *authzid);

#ifdef __cplusplus
} /* extern "C" */
#endif
#endif /* !__TA_LDAP_H__ */
