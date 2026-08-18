# Security Policy

sulis is maintained by a single maintainer as an open-source project. This
policy sets expectations accordingly: honest commitments we can actually
keep, not enterprise SLA theater.

## Reporting a Vulnerability

Please report security vulnerabilities using [GitHub's private vulnerability
reporting](https://github.com/borfast/sulis/security/advisories/new) for this
repository (the "Report a vulnerability" button under the Security tab).
This keeps the report private between you and the maintainer while a fix is
worked out.

Do not open a public issue for a security report.

If you cannot use GitHub's reporting flow for some reason, contact the
maintainer directly through their GitHub profile.

Please include:

- The version or commit you tested against.
- Which package (`sulis`, `totp`, `passkey`, `recovery`, `passwordcheck`,
  `store/sql/sqlite`, `store/sql/postgres`) is affected.
- A minimal reproduction or a clear description of the flow and the
  violated guarantee (see `docs/threat-model.md` for what is and isn't
  guaranteed).

## Response Commitment

- **Acknowledgment within 7 days.** This is a solo-maintained project; 7
  days is a bound the maintainer can actually keep, not an aspiration.
- A fix timeline depends on severity and complexity, and will be
  communicated once the report is triaged. There is no fixed SLA beyond the
  acknowledgment above.
- Credit is given in the advisory and release notes unless you ask to stay
  anonymous.

## Supported Versions

sulis is pre-1.0. Before 1.0, **only the latest minor release (or, if no
release has been tagged yet, the tip of the default branch) is supported.**
Security fixes are not backported to older pre-1.0 minors — upgrade to get
a fix.

At 1.0, this policy will be replaced with a real support window (for
example, the current major version plus the immediately preceding one) and
recorded here before the 1.0 tag is cut.

## Scope

sulis is a library, not a deployed service. A report about this project
should concern a flaw in the library's own logic — for example, a bypass of
a documented guarantee (second-factor enforcement, token single-use,
timing equalization, CSRF defenses) or a memory-safety/crash issue reachable
from untrusted input (e.g. a parser in `totp`, `passkey`, or `recovery`).

Issues that are inherent to how the library is designed to be used by a
consuming application — such as a store implementation that violates the
documented store contracts, or a deployment that skips one of the
"Operational requirements" the README calls out — are configuration or
integration issues, not vulnerabilities in sulis itself. `docs/threat-model.md`
spells out this boundary in detail, including what is explicitly out of
scope.

## Threat Model

See [`docs/threat-model.md`](docs/threat-model.md) for the full threat
model: what sulis defends against, the specific shipped mitigation for
each threat, what is explicitly out of scope, and the residual risks that
remain even when everything is configured as documented.
