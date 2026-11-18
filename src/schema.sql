CREATE TABLE IF NOT EXISTS service_state (
  id integer PRIMARY KEY CHECK (id = 1), schema_version integer NOT NULL DEFAULT 0,
  key_fingerprint text, bootstrapped boolean NOT NULL DEFAULT false, require_mfa boolean NOT NULL DEFAULT true,
  mail jsonb NOT NULL DEFAULT '{}'
);
INSERT INTO service_state (id) VALUES (1) ON CONFLICT DO NOTHING;
CREATE TABLE IF NOT EXISTS users (
  id uuid PRIMARY KEY, email text NOT NULL UNIQUE, name text NOT NULL, password_hash text NOT NULL,
  owner boolean NOT NULL DEFAULT false, disabled boolean NOT NULL DEFAULT false,
  totp_box text, totp_pending text, pending_until timestamptz, totp_counter bigint NOT NULL DEFAULT -1,
  recovery_hashes text[] NOT NULL DEFAULT '{}', created_at timestamptz NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX IF NOT EXISTS one_owner ON users(owner) WHERE owner = true;
CREATE TABLE IF NOT EXISTS projects (id uuid PRIMARY KEY, name text NOT NULL UNIQUE, created_at timestamptz NOT NULL DEFAULT now());
CREATE TABLE IF NOT EXISTS environments (
  project_id uuid NOT NULL REFERENCES projects(id), name text NOT NULL, PRIMARY KEY (project_id, name)
);
CREATE TABLE IF NOT EXISTS roles (
  id uuid PRIMARY KEY, project_id uuid REFERENCES projects(id), name text NOT NULL,
  permissions jsonb NOT NULL, builtin boolean NOT NULL DEFAULT false, created_at timestamptz NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX IF NOT EXISTS org_role_name ON roles(name) WHERE project_id IS NULL;
CREATE UNIQUE INDEX IF NOT EXISTS project_role_name ON roles(project_id, name) WHERE project_id IS NOT NULL;
CREATE TABLE IF NOT EXISTS machines (
  id uuid PRIMARY KEY, project_id uuid NOT NULL REFERENCES projects(id), name text NOT NULL,
  disabled boolean NOT NULL DEFAULT false, created_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS bindings (
  id uuid PRIMARY KEY, role_id uuid NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
  principal_type text NOT NULL CHECK (principal_type IN ('user', 'machine')), principal_id uuid NOT NULL,
  environment text, path text NOT NULL DEFAULT '/', created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS principal_bindings ON bindings(principal_type, principal_id);
CREATE TABLE IF NOT EXISTS machine_credentials (
  id uuid PRIMARY KEY, machine_id uuid NOT NULL REFERENCES machines(id), secret_hash text NOT NULL UNIQUE,
  expires_at timestamptz NOT NULL, revoked boolean NOT NULL DEFAULT false, created_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS sessions (
  token_hash text PRIMARY KEY, actor_type text NOT NULL CHECK (actor_type IN ('user', 'machine')),
  actor_id uuid NOT NULL, kind text NOT NULL CHECK (kind IN ('pending', 'full')),
  csrf text NOT NULL, credential_id uuid REFERENCES machine_credentials(id),
  created_at timestamptz NOT NULL DEFAULT now(), expires_at timestamptz NOT NULL
);
CREATE INDEX IF NOT EXISTS actor_sessions ON sessions(actor_type, actor_id);
CREATE TABLE IF NOT EXISTS invitations (
  id uuid PRIMARY KEY, email text NOT NULL, token_hash text NOT NULL UNIQUE,
  kind text NOT NULL CHECK (kind IN ('invite', 'reset')), user_id uuid REFERENCES users(id),
  expires_at timestamptz NOT NULL, used boolean NOT NULL DEFAULT false,
  created_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS secrets (
  id uuid PRIMARY KEY, project_id uuid NOT NULL, environment text NOT NULL, path text NOT NULL, key text NOT NULL,
  version integer NOT NULL, deleted_at timestamptz, updated_at timestamptz NOT NULL DEFAULT now(),
  FOREIGN KEY (project_id, environment) REFERENCES environments(project_id, name),
  UNIQUE (project_id, environment, path, key)
);
CREATE TABLE IF NOT EXISTS secret_versions (
  secret_id uuid NOT NULL REFERENCES secrets(id) ON DELETE CASCADE, version integer NOT NULL,
  box text NOT NULL, actor_type text NOT NULL, actor_id uuid NOT NULL, created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (secret_id, version)
);
CREATE TABLE IF NOT EXISTS audit_events (
  id uuid PRIMARY KEY, actor_type text, actor_id uuid, action text NOT NULL,
  project_id uuid, environment text, path text, resource_id text,
  created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS audit_project_time ON audit_events(project_id, created_at DESC);

-- Version 2: optional Google identities and short-lived browser-bound login flows.
ALTER TABLE users ADD COLUMN IF NOT EXISTS google_subject text;
CREATE UNIQUE INDEX IF NOT EXISTS google_subject_identity ON users(google_subject) WHERE google_subject IS NOT NULL;
ALTER TABLE sessions ADD COLUMN IF NOT EXISTS auth_method text NOT NULL DEFAULT 'password';
CREATE TABLE IF NOT EXISTS google_flows (
  token_hash text PRIMARY KEY, browser_hash text NOT NULL, box text NOT NULL,
  expires_at timestamptz NOT NULL
);
