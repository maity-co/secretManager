# SecretManager

A self-hosted, single-organization secrets manager for people and machines. One
Docker image runs PostgreSQL, a Node.js API and a React web UI. There is no required
hosted secrets service or email provider.

This is an initial implementation for review. Passing tests does not establish
production readiness; review the [security model](docs/security-model.md) and
validate recovery on your own staging installation before moving live secrets.

## Included

- Projects, environments and folder scopes; encrypted key/value and multiline secrets.
- Custom organization and project roles, with backend authorization and delegation
  checks. Organization administration does not automatically grant secret access.
- Password accounts, authenticator-app TOTP, single-use recovery codes, session
  revocation, account disabling and host-only owner recovery.
- Expiring, revocable invitations and password-reset links. Copy a link manually
  when email is absent or delivery fails. Password resets preserve existing MFA.
- Resend configuration through the admin UI, authenticated API or deployment
  settings, with encrypted stored API keys and a test-email action.
- Per-project machine identities, overlapping expiring credentials, 15-minute
  access tokens, and immediate credential/identity revocation checks.
- Secret versions, soft deletion and a 30-day recovery window; transactional
  `.env` preview/import and permission-controlled export.
- Value-free audit events, a stdin-based CLI, encrypted PostgreSQL backups and
  maintenance-mode restore.
- Supervised processes, health checks, separate database/key/backup volumes,
  scheduled encrypted backups and documented upgrades.

## Start a local installation

Install Docker with Compose, then:

```sh
docker compose up --build -d
```

Open `http://localhost:8080`. The compose file binds the web port to loopback and
publishes no PostgreSQL port. Get the initial setup token in your private terminal:

```sh
docker compose exec --user secretmanager secretmanager cat /keys/setup-token
```

Do not paste the token into a ticket, CI log or this repository. Use it in the
setup screen, create the owner account, enroll an authenticator and save the
single-use recovery codes outside the service.

For a remote installation, configure `APP_ORIGIN=https://secrets.example.com` and
put an HTTPS reverse proxy in front of the loopback web port. See
[operations](docs/operations.md) for proxy trust, persistence, email, backup,
restore and upgrades. The browser origin must match `APP_ORIGIN` exactly.

## Use the CLI

The CLI is `node src/cli.js`. It requires Node.js 20 or newer and the installed
runtime dependencies. It also ships inside the container. Credentials are read
from JSON on stdin, never from command-line arguments. Examples use placeholder
files; create those outside version control with owner-only permissions.

```sh
node src/cli.js login --url https://secrets.example.com < /secure/user-login.json
node src/cli.js machine-login --url https://secrets.example.com < /secure/machine-login.json
node src/cli.js projects
node src/cli.js run --project PROJECT_ID --environment production --path /app -- node server.js
```

Human login input contains `email`, `password`, and an authenticator/recovery
`code`. Machine login input contains `clientId` and `clientSecret`. Initial human
MFA enrollment is performed in the web UI. Sessions are saved in an owner-only
local file and expire after eight hours for people or fifteen minutes for machines.
Reauthenticate machines at the start of each job; reusable machine credentials
are not saved by the CLI.

`get` and `export` intentionally write plaintext to stdout. `run` injects values
into a child process without printing them. See [CLI and API usage](docs/api.md).

## Development and validation

```sh
npm ci --userconfig=/dev/null --registry=https://registry.npmjs.org
npm run check
npm run build
npm test
```

Local tests use disposable embedded PostgreSQL through PGlite. Set
`TEST_DATABASE_URL` to a loopback PostgreSQL database named `secretmanager_test*`
to run the same API suite against the real server. Never point tests at a live
service database. CI exercises Node.js 20/24 with PostgreSQL 17 and independently
builds the Docker image, tests human/machine CLI access, startup and persistence, performs a real encrypted
backup/restore, and checks process supervision. CI does not deploy or publish an
image. The public repository also runs a checksum-pinned Gitleaks scan.

See [architecture](docs/architecture.md), [API](docs/api.md),
[operations](docs/operations.md), and [security reporting](SECURITY.md).
