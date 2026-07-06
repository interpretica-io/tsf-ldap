/* SPDX-License-Identifier: MIT */
/* Copyright (C) 2026 Interpretica, Unipessoal Lda. All rights reserved. */
/** @file
 * @brief RPC for LDAP operations
 *
 * The RPCs of rpcs_ldap, a thin layer over ta_ldap, which drives an
 * LDAP directory from the RPC server process over OpenLDAP. Add this
 * file to the rpcxdr definitions of the engine platform and of the
 * agent platform:
 *
 *   TE_LIB_PARMS([rpcxdr], [<platform>], [],
 *                [--with-rpcdefs=tarpc_job.x.m4,../ta_ldap/ldap_rpc.x.m4])
 *
 * No handle survives between calls: each call opens, binds, acts and
 * closes. A search returns one DN per line; the engine side parses it.
 */

/* ldap_bind(): try a bind and report the LDAP result code. */
struct tarpc_ldap_bind_in {
    struct tarpc_in_arg common;

    string      uri<>;
    string      dn<>;           /* "" for anonymous */
    string      password<>;
    tarpc_bool  starttls;
};

struct tarpc_ldap_bind_out {
    struct tarpc_out_arg common;

    tarpc_int   retval;
    tarpc_int   result_code;    /* LDAP result (0 ok, 49 bad creds, ...) */
    string      detail<>;
};

/* ldap_search(): bind, then search; result is one DN per line. */
struct tarpc_ldap_search_in {
    struct tarpc_in_arg common;

    string      uri<>;
    string      dn<>;
    string      password<>;
    tarpc_bool  starttls;
    string      base<>;
    tarpc_int   scope;          /* 0 base, 1 onelevel, 2 subtree */
    string      filter<>;
};

struct tarpc_ldap_search_out {
    struct tarpc_out_arg common;

    tarpc_int   retval;
    tarpc_int   count;
    string      result<>;
};

/* ldap_whoami(): bind, then RFC 4532 "Who am I?". */
struct tarpc_ldap_whoami_in {
    struct tarpc_in_arg common;

    string      uri<>;
    string      dn<>;
    string      password<>;
    tarpc_bool  starttls;
};

struct tarpc_ldap_whoami_out {
    struct tarpc_out_arg common;

    tarpc_int   retval;
    string      authzid<>;
};

program ldap
{
    version ver0
    {
        RPC_DEF(ldap_bind)
        RPC_DEF(ldap_search)
        RPC_DEF(ldap_whoami)
    } = 1;
} = 40;
