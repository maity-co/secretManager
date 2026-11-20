# Operations

## Installation and TLS

Use `docker compose up --build -d` for a single-container installation. Compose
creates named database, key and backup volumes. Container replacement preserves
those volumes. `docker compose down -v` destroys them; never use that command
against an installation whose data you intend to retain.

The supplied port mapping binds to `127.0.0.1:8080`. For remote users, terminate
HTTPS at a reverse proxy and set `APP_ORIGIN=https://secrets.example.com`.
`APP_ORIGIN` is an origin only: no path, trailing slash, username or query.
Plain HTTP origins are accepted only for loopback development. Do not expose
HTTP to remote clients or publish the PostgreSQL socket/directory.

If requests pass through a proxy, set `TRUST_PROXY_HOPS` to the exact trusted hop
count (0, 1 or 2). Keep the application network unreachable except through that
proxy. A wrong value allows forged client addresses or merges users into one
rate-limit identity. The application does not obtain TLS certificates itself.

First setup requires the generated `/keys/setup-token`. Read it only in a private
operator terminal. Setup is single-use; the persisted database state rejects it
after owner creation. Enroll the owner authenticator and save recovery codes
outside this service. The owner account cannot be disabled through the API.

## Configuration

| Setting                            | Default / purpose                                                                               |
| ---------------------------------- | ----------------------------------------------------------------------------------------------- |
| `APP_ORIGIN`                       | `http://localhost:8080`; exact browser origin and invitation base                               |
| `PORT`                             | `8080`; container web listener                                                                  |
| `BIND_ADDRESS`                     | `0.0.0.0`; rely on the loopback host port mapping                                               |
| `TRUST_PROXY_HOPS`                 | `0`; explicitly set trusted reverse-proxy hops                                                  |
| `ALLOWED_EMAIL_DOMAINS`            | Blank allows any valid email; exact comma-separated domains restrict humans and mail recipients |
| `PUBLIC_OPERATOR_NAME`             | Optional public organization name shown on `/info`                                              |
| `MASTER_KEY_FILE`                  | `/keys/master.key`; base64-encoded 32-byte key                                                  |
| `SETUP_TOKEN_FILE`                 | `/keys/setup-token`; bootstrap admission token                                                  |
| `PGHOST` / `PGUSER` / `PGDATABASE` | Unix socket / `secretmanager` / `secretmanager`                                                 |
| `DATABASE_URL`                     | Optional for a separately run backend or development                                            |
| `RESEND_API_KEY_FILE`              | Optional protected mounted Resend key file                                                      |
| `RESEND_API_KEY`                   | Alternative runtime-injected email key; never a build argument                                  |
| `EMAIL_FROM`                       | Plain sender email for deployment-managed email                                                 |
| `BACKUP_DIRECTORY`                 | `/backups`; private encrypted archive destination                                               |
| `BACKUP_INTERVAL_HOURS`            | `24`; `0` disables; otherwise 1–168 whole hours                                                 |

The stock compose file passes the origin and proxy settings. Add other runtime
settings in your private compose override or deployment system; do not commit
credentials. A separately run backend requires the same key/setup files and a
reachable PostgreSQL database. `node src/cli.js init --directory .local/keys`
generates protected development files without overwriting existing ones. Pass
their paths through `MASTER_KEY_FILE` and `SETUP_TOKEN_FILE` when starting Node.

## Hosted email policy and public page

Set `ALLOWED_EMAIL_DOMAINS` to a comma-separated list of exact domains for a
restricted installation, for example `example.com`. Set `PUBLIC_OPERATOR_NAME`
to the organization name displayed on the public page. Both settings are passed
by the supplied Compose file. Keep actual deployment values in private runtime
configuration; the public defaults remain unrestricted for other self-hosters.

The backend applies this policy to initial owner setup, login, existing human
sessions (including the owner), invitation creation/acceptance, password resets
and changes, and every outgoing invitation/reset/test-email recipient. Matching
is case-insensitive after trimming; subdomains, lookalike suffixes and wildcards
are not implicitly accepted. Invalid configuration prevents startup. The policy
cannot be changed through the admin panel or API. Machine credentials retain
their separate project-scoped authentication.

Existing outside-domain accounts and outstanding links become unusable while the
restriction is enabled; records are not deleted. Verify the owner's email is in
an allowed domain before enabling the setting. All API instances must use the
same policy. This is an email-address admission rule; administrators remain
responsible for identity checks and private invitation delivery. It does not
add email-ownership verification or SSO.

`/info` is a script-free public page explaining Maity's internal use and linking
to the source and self-hosting guide. Restricted anonymous browser visits to `/`
redirect there once the application loads its public policy. `/signin` provides
the existing account flow, and new invitation/reset links use that path. Older
root-fragment links remain supported by the UI. Denied account access redirects
browsers to `/info`; API clients receive a JSON 403 with code
`EMAIL_DOMAIN_NOT_ALLOWED` and `infoUrl: "/info"`. Admin attempts to address mail
outside the allowlist fail without redirecting the administrator's page.

## Google sign-in

Create a Google OAuth client of type **Web application**. Register the exact
redirect URI `https://secrets.example.com/api/auth/google/callback`, replacing
the example origin with the installation's `APP_ORIGIN`. Only the `openid email`
scopes are requested. See [Google's setup guide](https://developers.google.com/identity/openid-connect/openid-connect#settingup).

Configure these settings only in private runtime storage:

| Setting                     | Purpose                                                                                                      |
| --------------------------- | ------------------------------------------------------------------------------------------------------------ |
| `GOOGLE_CLIENT_ID`          | Web client ID                                                                                                |
| `GOOGLE_CLIENT_SECRET_FILE` | Preferred: protected mounted client-secret file                                                              |
| `GOOGLE_CLIENT_SECRET`      | Alternative runtime-injected secret; the file takes precedence                                               |
| `GOOGLE_HOSTED_DOMAIN`      | Optional exact Google Workspace domain; verified against signed `hd` claims                                  |
| `GOOGLE_ONLY`               | `true` disables all local password login/setup/reset paths, including old password sessions; default `false` |
| `BOOTSTRAP_OWNER_EMAIL`     | Optional exact owner email, checked during password or Google bootstrap                                      |

The stock Compose file passes environment-based Google configuration. To use a
secret file, mount it privately and set `GOOGLE_CLIENT_SECRET_FILE` in a private
Compose override. Never add real credentials to examples, build arguments or image
layers. Partial/invalid configuration fails startup. Runtime policy cannot be
changed through the admin UI or API. Leave all Google settings blank to retain
ordinary password/TOTP self-hosting.

For a restricted Workspace deployment, set both `ALLOWED_EMAIL_DOMAINS` and
`GOOGLE_HOSTED_DOMAIN` to the intended domain, pin `BOOTSTRAP_OWNER_EMAIL`, and
optionally enable `GOOGLE_ONLY=true`. The browser uses a server authorization-code
flow. An ID token must have a verified email and authoritative Google ownership
(Workspace `hd` or a Gmail address); a third-party Google-account email without
`hd` is rejected. The allowlist is rechecked on every human request.

On a fresh installation, open `/signin`, enter the setup token in the browser,
choose the configured owner email/name, and continue with Google. The Google
account must match that email. A successful callback creates the single owner
without a local password and still requires authenticator enrollment and recovery
code storage. All later Google sign-ins challenge the existing authenticator.

Google does not enable open signup. Administrators issue the existing one-time
invitation links; recipients choose their name and accept with the matching
Google account. Revoked, expired, used and wrong-email invitations are rejected.
Users receive no project access until an administrator grants it.

An existing password account is never linked by matching email alone. Before
enabling Google-only mode on an existing installation, each user signs in normally
and uses **Security → Link Google account**, verifying their password and current
factor. Google must return the same email. Linking revokes existing sessions and
requires another authenticator challenge. Keep the original authentication mode
until all needed accounts are linked.

To replace an authenticator after Google login, sign in again, complete the current
factor, then start replacement within five minutes using another current factor or
unused recovery code. Google-only accounts use Google's own password recovery. If
the owner loses its authenticator and all recovery codes, the trusted host-only
`owner-reset-link --reset-mfa` operation below clears MFA; sign in with the linked
Google identity and enroll again. Its generated password-reset link is unusable
while Google-only mode is enabled; keep/remove that file privately.

The CLI's human login remains password-based. Google-only installations use machine
identities for CLI/service automation; no Google tokens are copied into CLI files.

## Trusted browsers

After completing authenticator or recovery-code verification, people may select
**Trust this browser for 30 days on this IP**. Trust is opt-in. Every new sign-in
still requires the password or verified Google identity; the cookie alone never
authenticates an account. Human CLI and machine authentication do not use this
feature. First-time MFA enrollment and sensitive factor/password changes retain
their existing verification requirements.

The opaque HttpOnly cookie is Secure and host-only on HTTPS, SameSite=Strict, and
expires after 30 days without sliding renewal. Server records contain only a
token hash and keyed IP hash. The account and exact normalized client IP must
match. A new network/VPN, missing cookie, expiry or revocation requires MFA again.
Sessions linked to remembered access are also checked on every request and stop
working when their browser credential or IP no longer matches.

Only the configured proxy chain may supply client IP information. Configure
`TRUST_PROXY_HOPS` accurately and prevent direct access around that proxy.
Untrusted `X-Forwarded-For` headers must not determine the remembered IP.

**Account security → Trusted browsers** lists expiry/last-use dates and supports
forgetting one or all browsers. At most ten records are retained per account;
remembering an eleventh forgets the least recently used record and its linked
sessions. Ordinary Sign out keeps browser trust for the next sign-in. Forgetting
a browser, clearing cookies, password changes/resets, MFA replacement, Google
linking, account disablement, session revocation and host-owner recovery remove
the applicable trust. Record removal also revokes its linked sessions.

Google's cross-site callback does not receive the Strict cookie. The same-origin
login start instead binds its hash and IP into the encrypted, browser-bound flow.
The callback rechecks that binding only after verifying the Google identity.
Account, IP, expiry and revocation are checked again; no raw trust cookie enters
the redirect URL or application JSON responses.

This reduces repeat prompts; it is not a hardware-bound factor. Password and fresh
MFA checks still protect factor/password changes. See the
[OWASP authentication guidance](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html)
and [Express proxy configuration](https://expressjs.com/en/guide/behind-proxies/).

## Email and invitations

Configure Resend in Settings or with `PUT /api/settings`. Stored keys are encrypted
and never returned; leave the key empty to preserve it. A configured sender must
be verified in Resend. Use the test-email action before enabling delivery.

Deployment-provided email keys take precedence over database settings and make
the email fields read-only in the UI/API. Set `EMAIL_FROM` with the key. A mounted
API-key file takes precedence over the key environment variable. There is no
provider URL setting; outbound mail only targets Resend's HTTPS API.

Invitations expire in 24 hours; password resets expire in one hour. The UI shows
the single-use URL once, independently of email availability. Share it privately.
Creating a replacement invalidates earlier outstanding links for that email.
Delivery failure returns a safe status and retains the link. Revocation and
acceptance are persisted; passwords/factors are not included in URLs.

## Backups and restoration

The server creates an encrypted archive one minute after startup and then every
24 hours by default, retaining seven days of its own scheduled archives. Monitor
backup failures. Copy encrypted archives off the host through your own backup
system; the service does not implement offsite replication. Manual archives are
not automatically pruned.

Create a manual archive inside the mounted backup volume:

```sh
docker compose exec --user secretmanager secretmanager node src/cli.js backup --file /backups/manual.smbak
```

Use a fresh filename; the CLI refuses to overwrite a backup. Preserve the key
volume separately in a protected recovery location. An archive without its
original key cannot be decrypted. Copying database and key storage together
negates the intended separation. Backups include private account/audit metadata
as well as encrypted secret records.

Restore only while the normal application is stopped, using the same image
version and the intended key volume:

```sh
docker compose stop secretmanager
docker compose run --rm --no-deps secretmanager node src/cli.js restore --file /backups/manual.smbak --confirm-replace
docker compose up -d secretmanager
```

Restore replaces database contents transactionally after archive authentication.
Validate in a separate recovery installation first. Database dumps and active
sessions return to their backup state: revoke restored sessions and rotate any
credentials whose revocation occurred after the backup. Do not restore an old
database while allowing clients to use the application.

Never replace the master key to rotate it. Online master-key rotation is deferred.
The service refuses a database/key fingerprint mismatch. Restore the original key
or recover using a matching archive/key pair.

## Host-only owner recovery

If the owner has lost both its password and MFA recovery material, a trusted
server operator may issue a reset link and explicitly clear MFA:

```sh
docker compose exec --user secretmanager secretmanager node src/cli.js owner-reset-link --url https://secrets.example.com --file /tmp/owner-recovery-link --reset-mfa
```

The command saves a one-hour link in an owner-only file, revokes owner sessions
and records an audit event. Read/share that file privately, then remove it after
use. Omit `--reset-mfa` when the owner still has its factor. This is an explicit
host-administration operation, not a network-accessible recovery bypass. Complete
the reset and enroll a new authenticator before using the workspace again.

## Upgrades and rollback

1. Create an encrypted database archive and independently verify the key backup.
2. Read the target release's migration notes. Keep the old image for recovery.
3. Stop the application and rebuild/pull the reviewed image, preserving volumes.
4. Start it and check health, sign-in, a scoped read and the latest backup.
5. On failure, stop the new service. Restore the archive with its matching key and
   old image. Do not run old code against a newer schema or PostgreSQL data major.

The entrypoint rejects PostgreSQL data from a different major version. PostgreSQL
major upgrades require an explicit dump/restore or reviewed pg_upgrade procedure;
changing the image tag is not a data migration. Schema startup refuses downgrades
from a newer application schema. This release has schema version 4. Upgrading from
version 1 adds optional Google identity/session metadata and encrypted temporary
login flows; upgrading from version 2 adds trusted-browser records and nullable
session links. Upgrading from version 3 allows explicitly issued machine
credentials without an expiry; existing credential timestamps, hashes and
revocation state remain unchanged. The UI's **Issue credential** dialog offers
finite lifetimes and **Until revoked (no expiration)**, with 30 days still selected
by default. Until-revoked credentials require deliberate revocation or rotation;
they do not change access-token lifetimes or grant additional permissions.
Existing password accounts, sessions, role bindings and secrets are preserved. Older
application versions refuse this schema. Rollback requires a pre-upgrade backup
and the matching key, as described above.

The current design is one active application/database instance, with brief
upgrade downtime. Do not share the same database volume between running
containers. Health failure alone does not restart a container under ordinary
Docker restart policies; monitor it. Exiting PostgreSQL or Node stops the whole
container so the restart policy can act.

## Publish a tested image

Maintainers can manually run the **Validation** Actions workflow on `main` to
publish an immutable source-tagged image. Ordinary push/PR runs never publish.
The manual run repeats the full tests, container backup/recovery/supervision
checks and file/history secret scans. It transfers the exact tested Docker image
to a separate publication job; it does not rebuild after testing or snapshot a
running test container. Runtime keys, databases and synthetic test volumes are
not image inputs.

The publication job alone has package-write permission. It rejects a source
revision that is no longer current main, verifies OCI source/revision labels, and
pushes `ghcr.io/<lowercase-owner>/<lowercase-repository>:sha-<source-sha>`.
The run summary and `image-digest` artifact provide the pull reference to pin in
your deployment system. No server deployment, DNS change or automatic promotion
is performed.

A newly created GHCR package may be private. Keep it private and configure an
appropriate pull-only runtime identity, or explicitly make it public through the
package settings if that is your intended distribution policy. The workflow does
not change package visibility or copy existing registry credentials. Verify an
actual digest pull from the destination before activating the service.
