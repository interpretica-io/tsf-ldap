# tsf-ldap

Driving an LDAP directory from a Test Agent, packaged as an external
Test Environment (TE) repository (consumed with the `TE_EXT_REPO`
builder directive). It talks to the directory over a low-level C
library — **OpenLDAP, no `ldapsearch` scraped** — for both functional
queries and a security posture.

Three libraries:

- `ta_ldap` — agent side. An LDAP client over **OpenLDAP** (`ldap.h`,
  `-lldap -llber`): bind (anonymous or simple), StartTLS, search, and
  `whoami` (RFC 4532). Read-only — it binds and reads, it writes nothing
  to the directory. A connection is opened, used and closed per call.
  The agent and its RPC server both link it.
- `rpcs_ldap` — the `ldap_*` RPCs for the RPC server of the agent, thin
  wrappers over `ta_ldap`. The queries originate on the agent, where the
  directory is reachable.
- `tapi_ldap` — engine side. `tapi_ldap.h` gives a test bind/search/
  whoami; `tapi_ldap_audit.h` reads a directory as a security posture
  through tsf-cybersec; `tapi_ldap_rpc.h` is the one-per-RPC layer.

TE has no LDAP client of its own.

## What it does

```c
int code;
te_string dns = TE_STRING_INIT;

/* Does the directory accept an anonymous bind? */
CHECK_RC(tapi_ldap_bind(rpcs, "ldap://dir.example", NULL, NULL, false,
                        &code, NULL));
RING("anonymous bind: LDAP result %d", code);   /* 0 = accepted */

/* What can an anonymous client read? */
tapi_ldap_search(rpcs, "ldap://dir.example", NULL, NULL, false,
                 "dc=example,dc=com", TAPI_LDAP_SCOPE_ONELEVEL,
                 "(objectClass=*)", NULL, &dns);
RING("entries:\n%s", dns.ptr != NULL ? dns.ptr : "");
te_string_free(&dns);
```

An anonymous bind is a `NULL`/empty DN and password; a simple bind
carries both. `whoami` asks the server which identity a bind maps to.
A search returns one DN per line, parsed on the engine side.

## Security posture

`tapi_ldap_audit()` probes a directory and reports through
tsf-cybersec's finding model. It binds and reads only — it writes
nothing — but it talks to a real service, so point it at a directory
you own or are **authorized** to assess.

| Finding | Severity | Raised when |
|---|---|---|
| `ldap.reachable` | info | the directory answered a bind attempt |
| `ldap.anonymous-bind` | medium | an anonymous bind was accepted |
| `ldap.cleartext` | medium | a bind succeeded over `ldap://` with no TLS |
| `ldap.base-readable` | low | an anonymous search returned entries |
| `ldap.not-assessed` | info | the directory could not be reached |

The subject of every finding is the directory URI (stable between runs).

## Agent host requirements

- **OpenLDAP** client libraries with their development headers (Debian:
  `apt install libldap2-dev`; gives `ldap.h`, `-lldap -llber`). The
  2.6 client API used here (`ldap_initialize`, `ldap_sasl_bind_s`,
  `ldap_search_ext_s`, `ldap_whoami_s`) is long-standing.

## Usage

Declare the repository in an external libraries catalog and pass it to
`dispatcher.sh --external=<catalog.yml>`:

```yaml
repositories:
  - name: tsf_ldap
    url: https://github.com/interpretica-io/tsf-ldap.git
    ref: <tag>
    libs:
      - ta_ldap
      - rpcs_ldap
      - tapi_ldap
```

In `builder.conf`, bind `tapi_ldap` to the engine, list `ta_ldap` and
`rpcs_ldap` among the RPC server's libraries, and add the RPC
definitions to both platforms (`../ta_ldap/ldap_rpc.x.m4`). The posture
reports through tsf-cybersec, so build that repository too. The RPC
program number is **40**.

## Scope

- **Read-only.** It binds, searches and reads; it never adds, modifies
  or deletes a directory entry.
- **The directory must exist.** tsf-ldap does not stand up a server; it
  drives whichever one a test points it at, and `tapi_ldap_audit()`
  records `ldap.not-assessed` when none answers.
