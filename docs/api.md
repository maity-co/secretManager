# API, CLI and environment-file format

All endpoints are under `/api`. Requests that carry a body use JSON. Browser
clients use same-origin cookies plus `X-CSRF-Token`; the token is returned by
`GET /auth/me`. CLI/machine clients use `Authorization: Bearer …`. Never put
credentials in query strings. Authentication errors are bounded and redact
provider/database diagnostics.

## Main endpoints

| Operation              | Endpoints                                                                                                                                                               |
| ---------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Bootstrap              | `GET /bootstrap`, `POST /bootstrap`                                                                                                                                     |
| Human authentication   | `POST /auth/login`, `GET /auth/me`, `POST /auth/logout`                                                                                                                 |
| Authenticator          | `POST /auth/mfa/start`, `/auth/mfa/confirm`, `/auth/mfa/verify`                                                                                                         |
| Password and sessions  | `POST /auth/password`, `GET /auth/sessions`, `DELETE /auth/sessions`                                                                                                    |
| Machine authentication | `POST /auth/machine`                                                                                                                                                    |
| Users and invitations  | `GET /admin/users`, `PATCH /admin/users/:id`, `DELETE /admin/users/:id/sessions`, `POST /admin/invitations`, `DELETE /admin/invitations/:id`, `POST /accept-invitation` |
| Settings/email         | `GET /settings`, `PUT /settings`, `POST /settings/test-email`                                                                                                           |
| Projects               | `GET /projects`, `POST /projects`, `GET /projects/:projectId`, `POST /projects/:projectId/environments`                                                                 |
| Organization roles     | `GET/POST /roles`, `PATCH/DELETE /roles/:id`, `POST /bindings`, `DELETE /bindings/:id`                                                                                  |
| Project roles          | Same role/binding routes prefixed by `/projects/:projectId`                                                                                                             |
| Machines               | `GET/POST /projects/:projectId/machines`, `PATCH /projects/:projectId/machines/:id`                                                                                     |
| Machine credentials    | `POST /projects/:projectId/machines/:id/credentials`, `DELETE /projects/:projectId/credentials/:id`                                                                     |
| Secrets                | `GET/POST /projects/:projectId/secrets`, `GET /projects/:projectId/secrets/:id/value`, `DELETE /projects/:projectId/secrets/:id`                                        |
| Secret history         | `GET /projects/:projectId/secrets/:id/versions`, `POST /projects/:projectId/secrets/:id/restore`                                                                        |
| Import/export          | `POST /projects/:projectId/import/preview`, `POST /projects/:projectId/import`, `GET /projects/:projectId/export`                                                       |
| Audit                  | `GET /audit` or `/audit?projectId=…&environment=…&path=…`                                                                                                               |
| Health                 | `GET /health`                                                                                                                                                           |

A machine login accepts `{clientId, clientSecret}` and returns a bearer token and
expiry. Credentials default to 30 days; creation accepts `days` from 1 to 365,
with at most five unrevoked, unexpired credentials per identity. Issue a second
credential, update your workload, then revoke the old one. Identity disabling is
independent of individual credential revocation.

A human login accepts `{email, password}`. For CLI use, add `delivery: "token"`.
If `pending` is true, complete `/auth/mfa/verify` with `{code, delivery: "token"}`
using the pending bearer token. Initial enrollment uses `/auth/mfa/start` and
`/auth/mfa/confirm`; confirm returns ten recovery codes once and revokes existing
sessions. In the browser, all session tokens stay in HttpOnly cookies.

A role body is `{name, permissions: [...]}`. The roles response supplies the exact
permission names. A binding is `{roleId, principalType, email}` for a person, or
`{roleId, principalType: "machine", principalId}` for a machine. Project bindings
also accept `environment` (null means all) and `path` (default `/`). For people,
`principalId` can replace email. Organization roles cannot be assigned to machines.

A secret write accepts `{environment, path, key, value}`. Reusing an active key
creates a version. Direct reads/history/restore always authorize the stored scope.
Restore accepts `{version}` and creates a new version. Deleted secrets remain
recoverable for 30 days; their names cannot be reused until restoration or purge.

Listing and export select an exact environment/folder through `environment` and
`path` query parameters. Import selects them in its body, along with `content`
and `conflicts: "skip" | "overwrite"`. Preview never mutates records. Deleted-key
conflicts are skipped. One invalid assignment rejects the entire import.

Audit endpoints return the latest 200 visible events; project audit fetches a
bounded candidate window. Organization audit includes all organization/project
events and requires the separate organization audit permission. Audit has no
pagination/streaming or external immutable sink in this release.

## CLI

`SM_AUTH_FILE` selects an owner-only session file. Its parent must be a private
mode-0700 directory, not a shared folder or symlink; the CLI never changes an
existing parent directory’s permissions. Otherwise it is under
`$XDG_CONFIG_HOME/secretmanager/auth.json`, falling back to the user's config
directory. `SM_URL` can supply the login origin. The CLI rejects non-HTTPS remote
origins and redirects. Run logout to revoke the active session and delete the
local session file.

```sh
node src/cli.js get --project PROJECT_ID --environment production --path /app --key EXAMPLE
node src/cli.js export --project PROJECT_ID --environment production --path /app
node src/cli.js run --project PROJECT_ID --environment production --path /app -- node server.js
node src/cli.js request PUT /api/settings < /secure/settings.json
```

`run` requires both secret read and export permissions and starts the executable
directly, without a shell. `get` requires list and read permissions. `request`
reads JSON from stdin for mutations. Its output can include sensitive API
results, such as an invitation URL or one-time machine credential: never send
that output to CI logs. Treat `get` and `export` output as plaintext secrets.

## Dotenv subset

There is no universal dotenv standard. This service accepts `KEY=value`, optional
`export`, blank lines, comments, literal single/backtick-quoted strings, and
multiline quoted values. Double quotes interpret `\n`, `\r`, `\t`, `\\` and `\"`.
Other double-quote escapes retain their backslash. Unquoted `#` starts a comment;
quote a value containing a literal `#`.

Export uses JSON-compatible double quoting so exported values round-trip exactly.
There is no interpolation, variable expansion, shell execution or secret-reference
resolution. Duplicate keys, trailing garbage, invalid keys and unterminated
quotes are errors. Keys use `[A-Za-z_][A-Za-z0-9_]*` up to 128 characters. Values
are UTF-8 text up to 64 KiB with no NUL. Imports are limited to 256 KiB and 500
keys. Convert incompatible source quoting explicitly instead of silently changing
values. Infisical migration uses these key/value files only; users, permissions,
projects, environments and history are not imported.
