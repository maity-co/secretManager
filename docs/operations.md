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

| Setting                            | Default / purpose                                                 |
| ---------------------------------- | ----------------------------------------------------------------- |
| `APP_ORIGIN`                       | `http://localhost:8080`; exact browser origin and invitation base |
| `PORT`                             | `8080`; container web listener                                    |
| `BIND_ADDRESS`                     | `0.0.0.0`; rely on the loopback host port mapping                 |
| `TRUST_PROXY_HOPS`                 | `0`; explicitly set trusted reverse-proxy hops                    |
| `MASTER_KEY_FILE`                  | `/keys/master.key`; base64-encoded 32-byte key                    |
| `SETUP_TOKEN_FILE`                 | `/keys/setup-token`; bootstrap admission token                    |
| `PGHOST` / `PGUSER` / `PGDATABASE` | Unix socket / `secretmanager` / `secretmanager`                   |
| `DATABASE_URL`                     | Optional for a separately run backend or development              |
| `RESEND_API_KEY_FILE`              | Optional protected mounted Resend key file                        |
| `RESEND_API_KEY`                   | Alternative runtime-injected email key; never a build argument    |
| `EMAIL_FROM`                       | Plain sender email for deployment-managed email                   |
| `BACKUP_DIRECTORY`                 | `/backups`; private encrypted archive destination                 |
| `BACKUP_INTERVAL_HOURS`            | `24`; `0` disables scheduling                                     |

The stock compose file passes the origin and proxy settings. Add other runtime
settings in your private compose override or deployment system; do not commit
credentials. A separately run backend requires the same key/setup files and a
reachable PostgreSQL database. `node src/cli.js init --directory .local/keys`
generates protected development files without overwriting existing ones. Pass
their paths through `MASTER_KEY_FILE` and `SETUP_TOKEN_FILE` when starting Node.

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
from a newer application schema. This release has schema version 1.

The current design is one active application/database instance, with brief
upgrade downtime. Do not share the same database volume between running
containers. Health failure alone does not restart a container under ordinary
Docker restart policies; monitor it. Exiting PostgreSQL or Node stops the whole
container so the restart policy can act.
