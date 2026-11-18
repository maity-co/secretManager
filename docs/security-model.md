# Security model and verification limits

The trusted computing base includes the host operator, application process,
PostgreSQL administrator and encryption key. Host/application compromise can
expose secrets legitimately available to the service. A writable database can
also change identities and permissions. Application RBAC does not isolate users
from a malicious host operator or database administrator.

## Cryptographic storage

Secret values, TOTP seeds and saved email API keys use Node's AES-256-GCM with
random 96-bit nonces and authenticated record context. Secret version context
binds ciphertext to its record ID and version. Names, keys, paths, email addresses,
role assignments, timestamps and audit metadata are not application-encrypted.
Passwords use salted scrypt with N=32768, r=8, p=3 and a 32-byte output; the cost
parameters are included in the stored verifier. This is one of the parameter
sets in [OWASP's password-storage guidance](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html).

Session tokens, invitation tokens and machine credentials are generated from
256 random bits and stored as SHA-256 digests. Recovery codes have the same
entropy and are single-use. A database fingerprint detects an incorrect master
key at startup; it cannot recover a lost key. Back up the key separately.

Encrypted backup archives authenticate the complete PostgreSQL dump before
restore invokes pg_restore. Restore currently buffers the decrypted archive in
memory and uses an owner-only temporary file, removed afterward. Plan memory
and private temporary-disk capacity for the database size. Temporary files left
by an abrupt host failure must be treated as sensitive database material.

## Authentication and revocation

MFA is required by default for all human accounts. Administrators can change the
policy. An account with an enrolled factor always completes it at login even if
organization-wide enforcement is disabled. TOTP accepts a one-step clock window,
records the consumed counter transactionally and rejects replay. Replacing an
enrolled factor requires the password (or a recent full Google login) and a valid
current factor or unused recovery code. A password reset does not clear MFA. Keep server time accurate.

Human sessions last eight hours, incomplete login sessions ten minutes, and
machine tokens fifteen minutes. Machine authentication rechecks the original
credential's expiry/revocation and the machine's enabled state on every request.
Account disabling and password changes invalidate sessions. Role changes and
revocations are checked from persisted state on each request. Already completed
reads cannot be revoked retroactively.

Authentication endpoints have per-IP and login-identity rate limits. Factor
operations also have an account-wide limit across pending sessions. Limits are
in-memory for the selected single-process deployment and reset on restart; they
are not a distributed defense. Place suitable network admission controls in
front of a publicly reachable installation. Password hashing uses the bounded
Node worker pool; do not expose the service without resource planning.

A deployment can additionally restrict human account and email-recipient domains.
This is checked before passwords are created/reset and before any provider call,
and on every human session, including pending MFA sessions and the owner. It
limits accepted addresses rather than proving ownership of an email address.
Trusted administrators still control invitations and manual identity admission.
Other self-hosters can choose their own allowlist or leave it unset. Existing
outside-domain account data is retained but inaccessible under that policy.

## Data handling

The service emits no request-body, credential or secret-value logs. Database
statement/error detail logging is suppressed in the bundled server. Audit events
record actions and identifiers, never values, invitation URLs, factors or provider
responses. Database administrators can modify audit storage; it is not an
externally tamper-evident audit service. Audit retention is currently indefinite.

UI/CLI reveal, export, clipboard and environment-injection actions necessarily
deliver plaintext to an authorized client. Protect client machines, clipboard
history, shell output and CI logs. A child application or same-user host process
can inspect injected environment variables. This service cannot hide those
values from an authorized recipient or its host operator.

The server serves no third-party UI scripts, fonts or analytics. Sensitive API
responses use no-store caching, no-referrer policy and restrictive browser
headers. Request/proxy infrastructure must independently avoid logging cookies,
authorization headers and request bodies. Invitation/reset tokens use URL
fragments, which the UI removes before API requests.

## Release verification

Tests cover encryption tampering and record binding, dotenv round-trips,
permission denials across scopes, role escalation, MFA gating/replay, recovery,
invitation lifecycle, machine revocation and encrypted archive integrity.
Real PostgreSQL and container tests are separate from local embedded-engine
checks. Provider delivery uses stubs in tests; verify your Resend sender domain
and delivery on staging using your own configuration.

There has been no independent penetration test or external cryptographic review.
Do not interpret passing CI as certification, high availability or proof against
all attacks. Before migrating operational secrets, review the implementation and
exercise host recovery and isolated backup restoration on your intended platform.

## Optional Google identity

The server uses Google's authentication library for signature, issuer, audience
and lifetime verification, then verifies nonce, authorized party, verified email
and optional exact Workspace `hd` again. Signed Google `sub` is the persistent
identity; email matches do not automatically link existing accounts. Authentication
is an authorization-code flow with S256 PKCE, random state and nonce, a separate
HttpOnly SameSite=Lax browser-binding cookie, and encrypted five-minute database
state. Callback state is consumed once in a committed transaction before any
provider call. Provider calls have ten-second deadlines and retries/redirects
disabled; Google access/refresh/ID tokens are never persisted.

Bootstrap still needs the protected setup token and optionally pinned owner email.
Invitations remain single-use and email-bound. Existing account linking requires
a full session, CSRF, password/current factor and matching Google email. Session
revocation and disablement are rechecked before linking. Every resulting sign-in
retains the authenticator requirement; Google does not confer project permissions.

Google-only mode rejects old password sessions and all password APIs. Removing
Google configuration rejects existing Google sessions. Replacing MFA after a
Google login needs a full session no older than five minutes and an existing
factor/recovery code; password-session replacement retains the password check.
The ordinary session cookie stays SameSite=Strict. Public metadata exposes only
Google availability/mode booleans. Callback query strings contain short-lived
provider codes/state; suppress them in reverse-proxy access logs. See
[operations](operations.md#google-sign-in) for recovery and migration limits.
