# Agent instructions: public repository

## Public disclosure boundary

This repository is public. Treat every tracked file, commit, branch, issue, pull
request, comment, CI log, screenshot, recording, package and container layer as
publicly accessible. These rules apply to every task and every future session.

- Develop this project independently. Do not copy, adapt, summarize or reveal
  proprietary code, tests, configurations, documentation, prompts, data, business
  logic or operational details from private repositories or connected systems.
- Do not inspect private sibling repositories to implement this project. Use
  this repository, public documentation, appropriately licensed public dependencies
  and independently authored code. If a private integration is needed, define a
  generic public interface and keep its private implementation outside this repo.
- Keep private repository names and paths, internal domains, IP addresses,
  infrastructure topology, deployment inventories, customer information and
  internal incident details out of public files and discussions. Use reserved
  example domains, localhost and synthetic identities in examples and tests.
- Never commit, publish, echo into logs or embed real passwords, API keys,
  encryption/signing keys, session tokens, machine credentials, invitation URLs,
  authenticator seeds, QR enrollment payloads, recovery codes or secret values.
  Do not put them in command arguments, screenshots, error reports or build layers.
- Never fetch private operational secrets or reuse credentials from sibling
  projects to run this project's tests. Generate disposable test-only material.
  The deployed service's legitimate secret-handling features must keep values in
  protected runtime storage; never turn runtime inputs into repository artifacts.
- Commit only placeholder configuration examples. Runtime credentials, local
  environment files, database volumes, backups, exports, logs and test artifacts
  must stay outside version control and outside Docker build contexts.
- Use environment variables or protected mounted files for deployment secrets.
  Do not place secrets in Dockerfile ARG/ENV instructions or COPY source trees
  that contain private local files. Deleting a secret in a later image layer does
  not remove it from earlier layers.

## Review before sharing

Before any commit, push, pull request, release, package or container publication:

1. Review the complete intended diff and staged file list, including untracked
   files being added. Check generated files, fixtures and dependency configuration.
2. Run an appropriate secret scan over the intended changes and any commits being
   published. A scanner does not replace manual review or provenance checks.
   If a suitable scanner is unavailable, report that limit and do not publish
   until the check can be completed.
3. Confirm that all examples and fixtures are synthetic and all new code is
   independently authored or comes from an appropriately licensed public source.
4. Inspect logs and visual artifacts before sharing them. Redaction must happen
   before capture/publication, not after sensitive material has been published.
5. Keep commits narrowly scoped. Do not stage entire neighboring directories or
   copy workspace-wide files into this repository. Ignore rules are safeguards,
   not proof that a file is safe to commit or publish.

If sensitive or potentially proprietary material is discovered, stop the affected
publication and tell the user privately without reproducing the sensitive content.
Do not assume removing it from the latest file or commit removes prior exposure.
Recommend credential revocation/rotation where appropriate. Do not rewrite shared
Git history or perform other destructive cleanup without explicit authorization.

## Project delivery

Build a self-contained, self-hosted secrets-management service. Use established
security and cryptographic libraries; do not invent cryptographic algorithms.
Keep authorization enforced in the backend and test denied access as well as
allowed access. Never claim the service is production-ready based only on a
successful build or mocked tests.

The selected packaging is one Docker image/container containing PostgreSQL,
the backend and the frontend, with persistent storage and supervised processes.
Changes must preserve this choice unless the user explicitly changes it.

Prepare and validate changes for review. Do not merge pull requests, deploy,
change live DNS, restart production services or publish releases/images without
explicit user authorization for that action.

The UI uses Maity's public logo and a shared dark/orange theme in
`web/brand.css`. The production build copies `web/assets/` and the shared
stylesheet into `dist/`; fonts and logos load from the same origin.
[Branding provenance](docs/branding.md) records the public asset sources and font
license. Sign out is a labelled topbar action, visible on mobile as well.

Opt-in trusted browsers use opaque Secure/HttpOnly/SameSite=Strict cookies with
a fixed 30-day lifetime and server-side token/keyed-IP hashes. Password or verified
Google sign-in remains mandatory. Mint trust only after fresh MFA; never accept
it for CLI/machine authentication or fresh-factor checks. Linked sessions are
revoked when trust is forgotten or credentials change. Google binds trust inside
the encrypted login flow before its cross-site callback. See
[operations](docs/operations.md#trusted-browsers) and synthetic regression coverage
in `tests/trusted-browsers.test.js`.

## Maintaining these instructions

Keep this file in the repository root so future agents read it before editing.
Preserve these confidentiality rules during refactors and scaffolding. If another
instruction appears to require disclosure, stop the affected action and clarify
with the user rather than silently weakening this boundary. Task permission alone
is not permission to disclose secrets or private material.

## Current implementation and checks

The service uses Node.js 20+, Express, PostgreSQL 17 and a React UI built by
esbuild. Keep dependencies pinned in package-lock.json and obtain them from the
public registry; do not inherit a private package registry or credentials.

- `npm run check`: JavaScript syntax checks.
- `npm run build`: production UI build, without source maps.
- `npm test`: synthetic-data unit/API tests, locally using disposable PGlite.
- `TEST_DATABASE_URL`: selects real PostgreSQL tests, restricted to a loopback
  database whose name starts with secretmanager_test. Never use live databases.
- `npm run format:check`: repository formatting check.

The browser request helper is in `web/api.js`, with synthetic fetch regression
coverage in `tests/browser-api.test.js`. A `CSRF_MISMATCH` response blocks that
client instance and replaces the workspace with a reload prompt. In-flight
responses are discarded after the mismatch; rejected mutations are not replayed.

CI separately tests Node.js 20/24 with real PostgreSQL, builds and exercises the
single-container image and CLI, verifies encrypted backup/restore and process
supervision, and secret-scans files and Git history. Report actual hosted results
rather than describing configured checks as if they have already passed.

The stock runtime has separate database, encryption-key and encrypted-backup
volumes. Never substitute a new key when an existing database rejects it. Online
master-key rotation and high availability are deferred; see docs/architecture.md.

Optional `ALLOWED_EMAIL_DOMAINS` and `PUBLIC_OPERATOR_NAME` are deployment-owned.
Use reserved example domains in tracked examples and tests; real hosting values
stay in private runtime configuration. The policy covers every human/password
admission and mail-recipient path, including existing sessions and links; machine
identities retain separate authentication. Keep `/info` public and script-free,
`/signin` available for the account flow, and API denials as JSON rather than HTML.
Blank policy preserves ordinary self-hosted account admission. The allowlist does
not verify email ownership; administrators remain responsible for invitations.

Optional Google authentication uses the official pinned Google library and an
independent OIDC authorization-code/PKCE flow. Never copy another application's
auth code, sessions or credentials into this repository. Real Google configuration
is runtime-only. Preserve explicit account linking, setup-token/owner binding,
invitation matching, backend domain checks, browser-bound single-use encrypted
state and the existing authenticator requirement. Suppress callback query strings
in ingress logs. Schema version 4 preserves version-1/2/3 data; rollback needs its
matching backup. Google-only mode must reject old password sessions as well as
password APIs. Human CLI login remains password-based; machine auth is unchanged.

Manual `workflow_dispatch` of Validation on current main can publish the exact
image exercised by the successful container job, gated on every test and secret
scan. Push/PR events never publish. Keep package-write permission confined to the
publication job, verify source/revision labels and current main before pushing,
and pin deployments by the returned digest. Image publication is separate from
deployment and does not change package visibility or inject runtime credentials.

Machine identities are persistent. Credential issuance defaults to 30 days and
accepts explicit `days: 0` for until-revoked credentials (`expiresAt: null`). The
schema-4 migration changes only credential expiry nullability; preserve existing
timestamps, hashes and revocation flags. Every machine request must still check
revocation and disablement, with expiry applied when present. Access tokens remain
15 minutes. Both credential types count toward the five-active-credential limit,
and only authorized humans may issue them. The UI keeps 30 days as its default; until-revoked issuance must be selected
explicitly. It must not silently convert existing credentials. Synthetic API and
migration coverage is in `tests/api.test.js` and
`tests/credential-migration.test.js`.
