# Architecture and scope

The initial service is one organization per installation. Organization roles
control project creation, account administration, organization-role management,
email/authentication settings and organization audit access. Project roles control
project metadata, environments, project roles, machines and secret operations.

The owner is the installation's explicit superuser. There is exactly one owner;
the network API cannot disable the owner, transfer ownership or reset the owner's
MFA. A server operator can perform audited owner recovery through the CLI.

## Authorization

Bindings attach a role to a user or machine. Project bindings can constrain the
role to one environment and a folder subtree. `/app` includes `/app/worker` but
not `/application`. Missing assignments deny access. Machine identities belong
to one project and cannot receive organization roles.

Organization and project roles are separate records. The built-in organization
Administrator manages organization administration without automatic access to
project values. Built-in project Administrator, Writer and Reader roles are
immutable examples; administrators can create, edit and delete custom roles.
A Reader cannot export secrets unless a separate role explicitly grants export.

Role management is delegated only at the entire relevant organization/project
scope in this release. A person may only create or assign permissions they hold
at the target scope. Editing a custom role also checks that complete permission
set at the role's full scope, preventing escalation through existing assignments.
Organization/project role changes take effect on the next request; permissions
are not embedded in an access token.

The API independently checks each secret's persisted project/environment/folder,
including direct-ID reads, restore and history. Listing is exact-folder; subtree
permission inheritance does not implicitly export every descendant folder.
Folders are logical paths and exist as soon as a secret is stored at that path.

Machine identity IDs are persistent. Credentials may have a fixed expiry or an
explicit until-revoked lifetime; only credential expiry is nullable. Existing
finite expiry timestamps are preserved by schema 4. Machine sessions always
expire after 15 minutes, and every authenticated request rechecks credential
revocation, applicable expiry and identity disablement. Both lifetime types count
toward the five-active-credential limit. Rotation remains an explicit overlapping
issue/update/revoke operation, without automatic renewal.

## Storage and execution

PostgreSQL owns users, roles, assignments, credentials, sessions, invitations,
secret versions and audit events. Mutations and value-bearing reads run inside
serializable transactions; audit insertion commits before a value is returned.
Serialization conflicts receive bounded retries. Provider email is sent only after
the invitation transaction commits, so delivery failure retains a usable link.

Node.js serves the bundled UI and JSON API on one origin. Browser sessions use
HttpOnly, SameSite=Strict cookies; HTTPS installations use a Secure `__Host-`
cookie. Browser mutations require a CSRF token, JSON content type and accepted
origin. CLI/machine clients use opaque bearer tokens with server-side records.

Tabs in one browser profile share a session cookie. Signing in as another user
replaces that cookie while an older tab may retain its previous account and CSRF
token in memory. A rejected CSRF check returns `CSRF_MISMATCH`; the UI hides the
stale workspace, blocks further requests and asks for a reload to confirm the
current account. It never refreshes the token and replays the rejected mutation.
Use separate browser profiles or a private window for simultaneous accounts.

Optional remembered-browser credentials are opaque random tokens, hashed at rest
and bound to a keyed client-IP hash and user. An absolute 30-day expiry does not
slide on login. Sessions issued with trust link to its database row: revocation
cascades to those sessions, and request authentication checks the cookie/IP again.
Password and verified Google identity are still required at login; sensitive
factor/password operations still require fresh factors. Legacy sessions remain
unlinked after the additive schema-3 migration. IP matching is a risk check and
does not identify physical hardware. See [trusted browsers](operations.md#trusted-browsers).

The image starts PostgreSQL and Node under separate operating-system identities.
PostgreSQL listens on a Unix socket only, with peer authentication. Tini and the
entrypoint supervise both processes; one exiting stops the other. Only port 8080
is exposed. A local reverse proxy owns public TLS.

Database, encryption-key and encrypted-backup storage are separate volumes.
Never mount the source checkout or private workspace into the running service.

## Deferred

Multi-organization tenancy, SSO, passkeys, workload OIDC, approval workflows,
dynamic credentials, provider-side secret rotation, multi-node HA, offsite backup
replication and master-key rotation are not implemented. Do not silently replace
the master key. Runtime secret values and factors remain encrypted until read by
the trusted server; this is not a zero-knowledge vault.
