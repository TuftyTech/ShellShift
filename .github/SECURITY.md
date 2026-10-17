# Security Policy

## Supported Versions

only the latest [release](https://github.com/TuftyTech/ShellShift/releases/latest) and the current `main` get security fixes. the live dashboard is always built from `main`.

## Reporting a Vulnerability

found a security issue (a way to make the pipeline dial something it should not, leak a credential into a log, publish a node that skips certificate checks, inject script into the dashboard)? please **don't** open a public issue for it.

- report it privately [here](https://github.com/TuftyTech/ShellShift/security/advisories/new)

tell us what's affected, how to reproduce it and what an attacker could do with it. please leave real feed URLs and real node credentials out of the report, a structural example is enough.

## Out of Scope

- the published nodes themselves. they are operated by third parties, ShellShift only proves that HTTPS with a valid certificate chain completes through them. a node you think is malicious goes through the [node report](https://github.com/TuftyTech/ShellShift/issues/new?template=node-report.yml) form.
- missing HTTP headers on the dashboard that GitHub Pages cannot set (`frame-ancestors`, `immutable` caching). this limitation is documented in the README.
