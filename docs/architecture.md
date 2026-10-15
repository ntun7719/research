# Architecture

## Design objective

Lattice DNS treats DNS resolution as a small data plane that must remain predictable while configuration, downloads, UI activity and external integrations happen around it.

The request path is deliberately short:

~~~text
Android or DoT client
        |
        v
TLS transport
        |
        v
client profile
        |
        v
manual policy
        |
        v
category subscription lookup
        |
        v
local Unbound
        |
        v
suffix route
        |
        v
verified upstream DoT
~~~

FRP inserts only a PROXY protocol header before the same TLS transport path. The public FRPS server never terminates DNS TLS.

## Policy precedence

For a query, Lattice selects the client profile using the longest matching CIDR network. It then evaluates profile scoped rules before global rules. An exact rule is checked before suffix rules. If no manual rule decides the request, enabled subscription sources are checked for categories selected by the profile.

Manual allow rules can therefore override a subscription block.

Address rewrite rules synthesize A or AAAA responses locally. Other record types receive an empty successful answer for the rewritten owner name.

## Subscription index

Subscription domains remain in SQLite with an index on domain and category. The in process Bloom structure contains only enough information to say whether a domain is definitely absent or might exist.

For every queried hostname, Lattice checks the hostname and each parent suffix against the Bloom structure. Only possible matches cause a SQLite lookup. SQLite must return an enabled source in a category selected by the client profile before the decision becomes a block.

This gives bounded Python memory while preserving exact blocking semantics.

## Resolver

Unbound listens only on loopback. The transport forwards allowed packets to it over local TCP.

The generated configuration enables DNSSEC validation, QNAME minimization, hardened glue processing, aggressive NSEC, bounded message and RRset caches, optional serve expired behavior and TLS certificate verification for every upstream.

Suffix routes compile to Unbound forward zones. The default forward zone contains all enabled upstreams.

Remote control is loopback only and does not use certificates because it is never exposed outside the container.

## Configuration transactions

A configuration update follows this sequence:

1. Strict schema validation
2. Optional encrypted secret update
3. Persist candidate configuration
4. Generate candidate Unbound configuration
5. Validate Unbound syntax
6. Replace resolver process
7. Recompile policy
8. Verify and replace FRPC when enabled

Any exception restores the previous configuration and secrets, restarts the previous resolver and recompiles the previous policy.

## Certificate generations

Certificates are immutable generation directories. Validation checks key pair equality, current validity and SAN coverage before a generation is accepted. The active generation pointer is updated only after a usable server SSL context is created.

Several recent generations are retained for recovery.

## Authentication

The first start setup secret exists only in process memory and is printed to logs. The administrator password is PBKDF2 hashed with a random salt. Authenticated browser sessions are memory resident and expire after one day.

Mutating API requests require a session cookie and matching CSRF token.

## Privacy

Full mode stores the client address and hostname.

Balanced mode stores the hostname but replaces the client address with a stable truncated SHA256 value.

Minimal mode disables per query persistence while transport counters continue to operate.

Profiles may independently disable query persistence.
