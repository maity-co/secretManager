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
enrolled factor requires the password and a valid current factor or unused
recovery code. A password reset does not clear MFA. Keep server time accurate.

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
