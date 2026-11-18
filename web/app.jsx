import React, { useEffect, useState, useRef } from "react";
import { createRoot } from "react-dom/client";
import "./style.css";
import { createApi, SESSION_CHANGED_MESSAGE } from "./api.js";
const initialLink = new URLSearchParams(location.hash.slice(1));
const invitation = initialLink.get("invite"),
  reset = initialLink.get("reset");
if (location.hash) history.replaceState(null, "", location.pathname);
const googleFailed = initialLink.get("google") === "failed";
const api = createApi({
  onRestricted: () => location.replace("/info"),
  onSessionChanged: () =>
    window.dispatchEvent(new CustomEvent("sm-session-changed")),
});
async function startGoogle(values = {}) {
  const result = await api("/auth/google/start", "POST", values);
  location.assign(result.url);
}
const date = (value) => new Date(value).toLocaleString();
function Field({ label, children, ...props }) {
  return (
    <label className="field">
      <span>{label}</span>
      {children || <input {...props} />}
    </label>
  );
}
function Button({ children, kind = "", ...props }) {
  return (
    <button className={"button " + kind} {...props}>
      {children}
    </button>
  );
}
function Empty({ title, children }) {
  return (
    <div className="empty">
      <div className="empty-icon">◇</div>
      <h3>{title}</h3>
      <p>{children}</p>
    </div>
  );
}
function Badge({ children, tone = "" }) {
  return <span className={"badge " + tone}>{children}</span>;
}
function Panel({ title, description, action, children }) {
  return (
    <section className="panel">
      <div className="panel-head">
        <div>
          <h2>{title}</h2>
          {description && <p>{description}</p>}
        </div>
        {action}
      </div>
      {children}
    </section>
  );
}
function Dialog({ title, children, onClose }) {
  const ref = useRef();
  const [localError, setLocalError] = useState("");
  useEffect(() => {
    const listener = (event) => setLocalError(event.detail);
    window.addEventListener("sm-error", listener);
    return () => window.removeEventListener("sm-error", listener);
  }, []);
  useEffect(() => {
    const previous = document.activeElement;
    ref.current.showModal();
    return () => previous?.focus();
  }, []);
  return (
    <dialog
      ref={ref}
      onSubmitCapture={() => setLocalError("")}
      onCancel={(event) => {
        event.preventDefault();
        onClose();
      }}
    >
      <div className="dialog-head">
        <h2>{title}</h2>
        <button
          className="icon-button"
          aria-label="Close dialog"
          onClick={onClose}
        >
          ×
        </button>
      </div>
      {localError && (
        <div className="message error" role="alert">
          {localError}
        </div>
      )}
      {children}
    </dialog>
  );
}
function Disclosure({ title, text, onClose }) {
  const [copied, setCopied] = useState(false);
  useEffect(() => {
    const timer = setTimeout(onClose, 180000);
    return () => clearTimeout(timer);
  }, []);
  return (
    <Dialog title={title} onClose={onClose}>
      <p className="muted">
        Store this securely. This view clears when closed and expires after
        three minutes.
      </p>
      <pre className="sensitive">{text}</pre>
      <div className="actions">
        <Button
          onClick={async () => {
            try {
              await navigator.clipboard.writeText(text);
              setCopied(true);
            } catch {
              setCopied(false);
            }
          }}
        >
          {copied ? "Copied" : "Copy"}
        </Button>
        <Button kind="primary" onClick={onClose}>
          Done
        </Button>
      </div>
    </Dialog>
  );
}
function Form({ submit, children, label = "Save", busy }) {
  return (
    <form
      onSubmit={(event) => {
        event.preventDefault();
        submit(new FormData(event.currentTarget), event.currentTarget);
      }}
    >
      {children}
      <div className="actions">
        <Button kind="primary" disabled={busy}>
          {busy ? "Working…" : label}
        </Button>
      </div>
    </form>
  );
}
function App() {
  const [user, setUser] = useState(null),
    [instance, setInstance] = useState(null),
    [boot, setBoot] = useState(false),
    [loading, setLoading] = useState(true),
    [sessionChanged, setSessionChanged] = useState(false),
    [page, setPage] = useState("secrets"),
    [projects, setProjects] = useState([]),
    [canCreate, setCanCreate] = useState(false),
    [projectId, setProjectId] = useState(""),
    [environments, setEnvironments] = useState([]),
    [environment, setEnvironment] = useState("development"),
    [path, setPath] = useState("/"),
    [error, setError] = useState(
      googleFailed
        ? "Google sign-in failed. Use your invited account, or try again."
        : "",
    ),
    [notice, setNotice] = useState(""),
    [busy, setBusy] = useState(false),
    [passwordMode, setPasswordMode] = useState(false),
    [modal, setModal] = useState(null),
    [recovery, setRecovery] = useState(null),
    [enrollment, setEnrollment] = useState(null),
    [tick, setTick] = useState(0),
    [link, setLink] = useState(
      invitation
        ? { token: invitation, kind: "invite" }
        : reset
          ? { token: reset, kind: "reset" }
          : null,
    );
  const selected = projects.find((item) => item.id === projectId);
  const refresh = () => setTick((value) => value + 1);
  const act = async (fn) => {
    setError("");
    setNotice("");
    setBusy(true);
    try {
      return await fn();
    } catch (e) {
      setError(e.message);
      window.dispatchEvent(new CustomEvent("sm-error", { detail: e.message }));
    } finally {
      setBusy(false);
    }
  };
  useEffect(() => {
    const changed = () => {
      setSessionChanged(true);
      setUser(null);
      setProjects([]);
      setProjectId("");
      setModal(null);
      setEnrollment(null);
      setRecovery(null);
    };
    window.addEventListener("sm-session-changed", changed);
    return () => window.removeEventListener("sm-session-changed", changed);
  }, []);
  async function identify() {
    try {
      const value = await api("/auth/me");
      setUser(value);
    } catch {
      setUser(null);
    } finally {
      setLoading(false);
    }
  }
  useEffect(() => {
    let active = true;
    Promise.all([
      api("/instance"),
      api("/bootstrap"),
      api("/auth/me").catch(() => null),
    ])
      .then(([policy, bootstrap, account]) => {
        if (active) {
          setInstance(policy);
          setBoot(bootstrap.required);
          setUser(account);
        }
      })
      .catch((error) => {
        if (active) setError(error.message);
      })
      .finally(() => {
        if (active) setLoading(false);
      });
    return () => {
      active = false;
    };
  }, []);
  const showInfo =
    !!instance?.restricted && !user && !link && location.pathname !== "/signin";
  useEffect(() => {
    if (!loading && !sessionChanged && showInfo) location.replace("/info");
  }, [loading, sessionChanged, showInfo]);
  useEffect(() => {
    if (!user || user.pending) return;
    api("/projects")
      .then((value) => {
        setProjects(value.projects);
        setCanCreate(value.canCreate);
        if (!projectId && value.projects.length) {
          setProjectId(value.projects[0].id);
          const scope = value.projects[0].scopes?.[0];
          setEnvironment(scope?.environment || "development");
          setPath(scope?.path || "/");
        }
      })
      .catch((e) => setError(e.message));
  }, [user, tick]);
  useEffect(() => {
    if (!projectId || !user || user.pending) return;
    api("/projects/" + projectId)
      .then((value) => setEnvironments(value.environments))
      .catch((e) => setError(e.message));
  }, [projectId, user, tick]);
  async function signedIn(value) {
    if (value.recoveryCodes) {
      setRecovery(value.recoveryCodes.join("\n"));
      setEnrollment(null);
    }
    setBoot(false);
    await identify();
  }
  const close = () => setModal(null);
  const errors = error ? (
    <div className="message error" role="alert">
      {error}
      <button aria-label="Dismiss error" onClick={() => setError("")}>
        ×
      </button>
    </div>
  ) : null;
  if (sessionChanged)
    return (
      <main className="auth">
        <div className="auth-card" role="alert">
          <Logo />
          <h1>Reload to confirm your account</h1>
          <p>{SESSION_CHANGED_MESSAGE}</p>
          <p className="muted">
            The rejected action was not retried. Use a separate browser profile
            or private window to keep two accounts signed in.
          </p>
          <Button kind="primary" onClick={() => location.reload()}>
            Reload workspace
          </Button>
        </div>
      </main>
    );
  if (loading || showInfo)
    return <div className="loading">Opening your workspace…</div>;
  if (!instance)
    return (
      <main className="auth">
        <div className="auth-card">
          <Logo />
          <h1>Workspace unavailable</h1>
          <p className="muted">
            The instance policy could not be loaded. Reload to try again.
          </p>
          {errors}
          <Button onClick={() => location.reload()}>Reload</Button>
        </div>
      </main>
    );
  if (link)
    return (
      <main className="auth">
        <div className="auth-card">
          <Logo />
          <h1>
            {link.kind === "invite"
              ? "You’re invited."
              : "Reset your password."}
          </h1>
          <p className="muted">
            {instance.googleEnabled && !passwordMode && link.kind === "invite"
              ? "Accept with your invited Google account, then connect an authenticator app."
              : "Choose a strong password. Two-factor authentication will be required at sign-in."}
          </p>
          {errors}
          {instance.googleOnly && link.kind === "reset" ? (
            <p>
              Use Google account recovery, or contact your administrator for
              authenticator recovery. <a href="/signin">Return to sign-in</a>
            </p>
          ) : (
            <Form
              busy={busy}
              label={
                instance.googleEnabled &&
                !passwordMode &&
                link.kind === "invite"
                  ? "Accept with Google"
                  : "Save and sign in"
              }
              submit={(data) =>
                act(async () => {
                  if (
                    instance.googleEnabled &&
                    !passwordMode &&
                    link.kind === "invite"
                  )
                    return startGoogle({
                      action: "invite",
                      token: link.token,
                      name: data.get("name"),
                    });
                  await api("/accept-invitation", "POST", {
                    token: link.token,
                    password: data.get("password"),
                    name: data.get("name"),
                  });
                  setLink(null);
                  if (instance.restricted && location.pathname !== "/signin") {
                    location.replace("/signin");
                    return;
                  }
                  setNotice("Account updated. Sign in to continue.");
                })
              }
            >
              {link.kind === "invite" && (
                <Field
                  label="Your name"
                  name="name"
                  required
                  maxLength="80"
                  autoComplete="name"
                />
              )}
              {(!instance.googleEnabled ||
                passwordMode ||
                link.kind === "reset") && (
                <Field
                  label="New password · at least 14 characters"
                  name="password"
                  type="password"
                  required
                  minLength="14"
                  maxLength="256"
                  autoComplete="new-password"
                />
              )}
            </Form>
          )}
          {instance.googleEnabled &&
            !instance.googleOnly &&
            link.kind === "invite" && (
              <Button onClick={() => setPasswordMode(!passwordMode)}>
                {passwordMode ? "Use Google instead" : "Use a password instead"}
              </Button>
            )}
        </div>
      </main>
    );
  if (!user)
    return (
      <main className="auth">
        <div className="auth-intro">
          <Logo />
          <h1>
            Your secrets.
            <br />
            Your infrastructure.
          </h1>
          <p>
            One place to manage application secrets and give every person and
            machine precisely the access they need.
          </p>
          <div className="auth-note">
            SELF-HOSTED · SCOPED ACCESS · AUDIT HISTORY
          </div>
        </div>
        <div className="auth-card">
          <div className="eyebrow">
            {boot ? "INITIAL SETUP" : "WORKSPACE ACCESS"}
          </div>
          <h2>{boot ? "Create your owner account" : "Welcome back"}</h2>
          <p className="muted">
            {boot
              ? "Initialize your service, then connect an authenticator app."
              : "Sign in to your secrets workspace."}
          </p>
          {errors}
          {notice && <div className="message">{notice}</div>}
          {instance.googleEnabled && !boot && !passwordMode && (
            <Button
              kind="primary"
              disabled={busy}
              onClick={() => act(() => startGoogle())}
            >
              Continue with Google
            </Button>
          )}
          {(boot || !instance.googleEnabled || passwordMode) && (
            <Form
              busy={busy}
              label={
                boot && instance.googleEnabled && !passwordMode
                  ? "Initialize with Google"
                  : boot
                    ? "Initialize workspace"
                    : "Continue"
              }
              submit={(data) =>
                act(async () => {
                  if (boot && instance.googleEnabled && !passwordMode)
                    return startGoogle({
                      action: "bootstrap",
                      ...Object.fromEntries(data),
                    });
                  return signedIn(
                    await api(
                      boot ? "/bootstrap" : "/auth/login",
                      "POST",
                      Object.fromEntries(data),
                    ),
                  );
                })
              }
            >
              {boot && (
                <>
                  <Field
                    label="Setup token"
                    name="setupToken"
                    type="password"
                    required
                    autoComplete="off"
                  />
                  <Field
                    label="Your name"
                    name="name"
                    required
                    maxLength="80"
                  />
                </>
              )}
              <Field
                label={
                  instance.restricted
                    ? "Company email address"
                    : "Email address"
                }
                name="email"
                type="email"
                required
                autoComplete="username"
              />
              {(!instance.googleEnabled || passwordMode) && (
                <Field
                  label="Password"
                  name="password"
                  type="password"
                  required
                  minLength={boot ? 14 : 1}
                  maxLength="256"
                  autoComplete={boot ? "new-password" : "current-password"}
                />
              )}
            </Form>
          )}
          {instance.googleEnabled && !instance.googleOnly && (
            <Button onClick={() => setPasswordMode(!passwordMode)}>
              {passwordMode ? "Use Google instead" : "Use a password instead"}
            </Button>
          )}
          {instance.restricted && (
            <p className="small muted">
              This instance accepts{" "}
              {instance.emailDomains.map((domain) => "@" + domain).join(", ")}{" "}
              accounts only.
            </p>
          )}
          <p className="small muted">
            <a href="/info">About this instance &amp; self-hosting</a>
          </p>
          <p className="small muted">
            No invitation email? Your administrator can share a single-use
            invitation link directly.
          </p>
        </div>
      </main>
    );
  if (user.pending)
    return (
      <main className="auth">
        <div className="auth-card">
          <Logo />
          <h1>Secure your sign-in</h1>
          {errors}
          {!user.mfaEnabled && !enrollment ? (
            <>
              <p className="muted">
                Connect an authenticator app before accessing your workspace.
              </p>
              <Button
                kind="primary"
                onClick={() =>
                  act(async () =>
                    setEnrollment(await api("/auth/mfa/start", "POST", {})),
                  )
                }
              >
                Set up authenticator
              </Button>
            </>
          ) : enrollment ? (
            <>
              <img
                className="qr"
                src={enrollment.qr}
                alt="Authenticator enrollment QR code"
              />
              <details>
                <summary>Enter a setup key manually</summary>
                <code className="sensitive">{enrollment.manualKey}</code>
              </details>
              <Form
                busy={busy}
                label="Verify and continue"
                submit={(data) =>
                  act(async () =>
                    signedIn(
                      await api("/auth/mfa/confirm", "POST", {
                        code: data.get("code"),
                      }),
                    ),
                  )
                }
              >
                <Field
                  label="Authenticator code"
                  name="code"
                  required
                  autoComplete="one-time-code"
                  inputMode="numeric"
                />
              </Form>
            </>
          ) : (
            <Form
              busy={busy}
              label="Verify sign-in"
              submit={(data) =>
                act(async () =>
                  signedIn(
                    await api("/auth/mfa/verify", "POST", {
                      code: data.get("code"),
                    }),
                  ),
                )
              }
            >
              <Field
                label="Authenticator code or recovery code"
                name="code"
                required
                autoComplete="one-time-code"
              />
            </Form>
          )}
          <Button
            kind="quiet"
            onClick={() =>
              act(async () => {
                await api("/auth/logout", "POST", {});
                setEnrollment(null);
                setUser(null);
              })
            }
          >
            Back to sign-in
          </Button>
        </div>
      </main>
    );
  const projectScope = { projectId, environment, path };
  const rootProjectPermission = (permission) =>
    user.owner ||
    selected?.scopes?.some(
      (scope) =>
        !scope.environment &&
        scope.path === "/" &&
        scope.permissions?.includes(permission),
    );
  const navigationPermission = (id) => {
    const permission = {
      users: "org.users.manage",
      roles: "org.roles.manage",
      settings: "org.settings.manage",
      audit: "org.audit.read",
    }[id];
    return (
      user.owner ||
      !permission ||
      user.permissions.includes(permission) ||
      (id === "audit" &&
        projects.some((project) =>
          project.scopes?.some((scope) =>
            scope.permissions?.includes("project.audit.read"),
          ),
        ))
    );
  };
  return (
    <div className="layout">
      <aside className="sidebar">
        <Logo />
        <div className="workspace-label">YOUR WORKSPACE</div>
        <nav aria-label="Project navigation">
          {[
            ["secrets", "▦", "Secrets"],
            ["access", "◈", "Project access"],
            ["machines", "⌘", "Machine identities"],
          ]
            .filter(([id]) =>
              id === "access"
                ? rootProjectPermission("project.roles.manage")
                : id === "machines"
                  ? rootProjectPermission("project.machines.manage")
                  : true,
            )
            .map(([id, icon, label]) => (
              <button
                key={id}
                className={page === id ? "active" : ""}
                onClick={() => setPage(id)}
              >
                <span>{icon}</span>
                {label}
              </button>
            ))}
        </nav>
        <div className="workspace-label">ORGANIZATION</div>
        <nav aria-label="Organization navigation">
          {[
            ["users", "♙", "People & invitations"],
            ["roles", "◇", "Organization roles"],
            ["audit", "≡", "Audit trail"],
            ["settings", "⚙", "Settings"],
            ["security", "◎", "Account security"],
          ]
            .filter(([id]) => navigationPermission(id))
            .map(([id, icon, label]) => (
              <button
                key={id}
                className={page === id ? "active" : ""}
                onClick={() => setPage(id)}
              >
                <span>{icon}</span>
                {label}
              </button>
            ))}
        </nav>
        <div className="sidebar-bottom">
          <div className="avatar">{user.name.slice(0, 1)}</div>
          <div>
            <strong>{user.name}</strong>
            <small>{user.owner ? "Owner" : user.email}</small>
          </div>
          <button
            className="logout"
            aria-label="Sign out"
            onClick={() =>
              act(async () => {
                await api("/auth/logout", "POST", {});
                setUser(null);
                setProjects([]);
                setProjectId("");
              })
            }
          >
            ↗
          </button>
        </div>
      </aside>
      <div className="main">
        <header className="topbar">
          <div>
            <span className="breadcrumb">Workspace</span>
            <span className="slash">/</span>
            <strong>{selected?.name || "Organization"}</strong>
          </div>
          <Badge tone="green">● Self-hosted</Badge>
        </header>
        <main className="content">
          <div className="page-title">
            <div>
              <div className="eyebrow">SECRET MANAGER</div>
              <h1>
                {
                  {
                    secrets: "Application secrets",
                    access: "Project access",
                    machines: "Machine identities",
                    users: "People & invitations",
                    roles: "Organization roles",
                    audit: "Audit trail",
                    settings: "Workspace settings",
                    security: "Account security",
                  }[page]
                }
              </h1>
              <p className="muted">
                {
                  {
                    secrets:
                      "Keep configuration organized. Give access intentionally.",
                    access:
                      "Custom roles, explicit permissions, and bounded access.",
                    machines:
                      "Separate identities for services, servers, and CI jobs.",
                    users: "Invite your team and manage account access.",
                    roles: "Define what organization administrators can do.",
                    audit:
                      "A record of access, changes, and administrative actions.",
                    settings:
                      "Configure authentication policy and transactional email.",
                    security:
                      "Manage your authenticator, password, and active sessions.",
                  }[page]
                }
              </p>
            </div>
            {canCreate && (
              <Button onClick={() => setModal({ kind: "project" })}>
                ＋ New project
              </Button>
            )}
          </div>
          {errors}
          {notice && (
            <div className="message" role="status">
              {notice}
            </div>
          )}
          {["secrets", "access", "machines"].includes(page) && (
            <div className="scope-bar">
              <Field label="Project">
                <select
                  value={projectId}
                  onChange={(event) => {
                    const id = event.target.value;
                    setProjectId(id);
                    const scope = projects.find((p) => p.id === id)
                      ?.scopes?.[0];
                    setEnvironment(scope?.environment || "development");
                    setPath(scope?.path || "/");
                  }}
                >
                  <option value="">Select project</option>
                  {projects.map((project) => (
                    <option key={project.id} value={project.id}>
                      {project.name}
                    </option>
                  ))}
                </select>
              </Field>
              {page === "secrets" && (
                <>
                  <Field label="Environment">
                    <select
                      value={environment}
                      onChange={(event) => setEnvironment(event.target.value)}
                    >
                      {environments.map((item) => (
                        <option key={item.name}>{item.name}</option>
                      ))}
                    </select>
                  </Field>
                  <Field label="Folder">
                    <input
                      value={path}
                      onChange={(event) => setPath(event.target.value)}
                      placeholder="/"
                    />
                  </Field>
                </>
              )}
              <div className="scope-actions">
                <Button kind="quiet" onClick={refresh}>
                  ↻ Refresh
                </Button>
                {page === "secrets" && projectId && (
                  <Button
                    kind="quiet"
                    onClick={() => setModal({ kind: "environment" })}
                  >
                    Add environment
                  </Button>
                )}
              </div>
            </div>
          )}
          {page === "secrets" &&
            (projectId ? (
              <Secrets
                {...{ scope: projectScope, tick, act, setModal, setNotice }}
              />
            ) : (
              <Empty title="A clean start">
                Create a project or ask an administrator to grant you project
                access.
              </Empty>
            ))}
          {page === "access" &&
            (projectId ? (
              <Roles
                {...{
                  prefix: "/projects/" + projectId,
                  projectId,
                  tick,
                  act,
                  setModal,
                  refresh,
                }}
              />
            ) : (
              <Empty title="Select a project">
                Project roles are independent of organization administration.
              </Empty>
            ))}
          {page === "roles" && (
            <Roles {...{ prefix: "", tick, act, setModal, refresh }} />
          )}
          {page === "machines" &&
            (projectId ? (
              <Machines {...{ projectId, tick, act, setModal, refresh }} />
            ) : (
              <Empty title="Select a project">
                Create identities scoped to an application’s project.
              </Empty>
            ))}
          {page === "users" && (
            <Users
              {...{ tick, act, setModal, refresh }}
              googleOnly={instance.googleOnly}
            />
          )}
          {page === "settings" && <Settings {...{ tick, act, setNotice }} />}
          {page === "audit" && <Audit {...{ act, projects, user }} />}
          {page === "security" && (
            <Security {...{ user, act, setEnrollment, setModal, setUser }} />
          )}
        </main>
        <footer>
          SecretManager <span>Explicit access. Private by default.</span>
        </footer>
      </div>
      {recovery && (
        <Disclosure
          title="Save your recovery codes"
          text={recovery}
          onClose={() => setRecovery(null)}
        />
      )}
      {modal?.kind === "disclosure" && (
        <Disclosure title={modal.title} text={modal.text} onClose={close} />
      )}
      {modal?.kind === "project" && (
        <Dialog title="Create a project" onClose={close}>
          <Form
            busy={busy}
            label="Create project"
            submit={(data) =>
              act(async () => {
                const value = await api("/projects", "POST", {
                  name: data.get("name"),
                });
                setProjectId(value.id);
                setEnvironment("development");
                setPath("/");
                refresh();
                close();
              })
            }
          >
            <Field label="Project name" name="name" required maxLength="80" />
            <p className="muted">
              Development, staging, and production environments are created
              automatically.
            </p>
          </Form>
        </Dialog>
      )}
      {modal?.kind === "environment" && (
        <Dialog title="Add environment" onClose={close}>
          <Form
            busy={busy}
            label="Add environment"
            submit={(data) =>
              act(async () => {
                await api("/projects/" + projectId + "/environments", "POST", {
                  name: data.get("name"),
                });
                setEnvironment(data.get("name"));
                refresh();
                close();
              })
            }
          >
            <Field
              label="Environment name"
              name="name"
              required
              pattern="[a-z][a-z0-9_-]*"
              maxLength="40"
            />
          </Form>
        </Dialog>
      )}
      {modal?.kind === "secret" && (
        <Dialog
          title={modal.key ? "Update secret" : "Create secret"}
          onClose={close}
        >
          <Form
            busy={busy}
            label="Save secret"
            submit={(data) =>
              act(async () => {
                await api("/projects/" + projectId + "/secrets", "POST", {
                  environment,
                  path,
                  key: modal.key || data.get("key"),
                  value: data.get("value"),
                });
                refresh();
                close();
              })
            }
          >
            <Field
              label="Key"
              name="key"
              defaultValue={modal.key}
              readOnly={!!modal.key}
              required
              pattern="[A-Za-z_][A-Za-z0-9_]*"
              maxLength="128"
            />
            <Field label="Value">
              <textarea
                name="value"
                rows="6"
                autoComplete="off"
                spellCheck="false"
              />
            </Field>
            <p className="muted">Saving creates a new encrypted version.</p>
          </Form>
        </Dialog>
      )}
      {modal?.kind === "import" && (
        <ImportDialog {...{ scope: projectScope, act, close, refresh }} />
      )}
      {modal?.kind === "history" && (
        <History {...{ ...modal, projectId, act, close, refresh }} />
      )}
      {modal?.kind === "role" && (
        <RoleDialog {...{ ...modal, act, close, refresh }} />
      )}
      {modal?.kind === "binding" && (
        <BindingDialog {...{ ...modal, act, close, refresh }} />
      )}
      {modal?.kind === "machine" && (
        <Dialog title="Create machine identity" onClose={close}>
          <Form
            busy={busy}
            label="Create identity"
            submit={(data) =>
              act(async () => {
                await api("/projects/" + projectId + "/machines", "POST", {
                  name: data.get("name"),
                });
                refresh();
                close();
                setNotice(
                  "Identity created. Assign it a project role before use.",
                );
              })
            }
          >
            <Field label="Identity name" name="name" required maxLength="80" />
          </Form>
        </Dialog>
      )}
      {modal?.kind === "invite" && (
        <Dialog
          title={modal.email ? "Reset account password" : "Invite a teammate"}
          onClose={close}
        >
          <Form
            busy={busy}
            label="Create link"
            submit={(data) =>
              act(async () => {
                const value = await api("/admin/invitations", "POST", {
                  email: modal.email || data.get("email"),
                  kind: modal.email ? "reset" : "invite",
                  sendEmail: data.get("send") === "on",
                });
                refresh();
                setModal({
                  kind: "disclosure",
                  title: "Single-use link · email " + value.emailStatus,
                  text: value.url,
                });
              })
            }
          >
            <Field
              label="Email address"
              name="email"
              type="email"
              defaultValue={modal.email}
              readOnly={!!modal.email}
              required
            />
            <label className="check">
              <input name="send" type="checkbox" />
              Send through configured email provider
            </label>
            <p className="muted">
              You can copy the link and send it manually. Password reset
              preserves existing two-factor authentication.
            </p>
          </Form>
        </Dialog>
      )}
      {enrollment && user && !user.pending && (
        <Dialog
          title="Replace your authenticator"
          onClose={() => setEnrollment(null)}
        >
          <img
            className="qr"
            src={enrollment.qr}
            alt="New authenticator QR code"
          />
          <Form
            busy={busy}
            label="Confirm replacement"
            submit={(data) =>
              act(async () =>
                signedIn(
                  await api("/auth/mfa/confirm", "POST", {
                    code: data.get("code"),
                  }),
                ),
              )
            }
          >
            <Field
              label="Code from the new authenticator"
              name="code"
              required
              autoComplete="one-time-code"
            />
          </Form>
        </Dialog>
      )}
    </div>
  );
}
function Logo() {
  return (
    <div className="logo">
      <span className="logo-mark">S</span>
      <strong>
        Secret<span>Manager</span>
      </strong>
    </div>
  );
}
function useData(load, deps, act) {
  const [data, setData] = useState(null);
  useEffect(() => {
    setData(null);
    let active = true;
    act(async () => {
      const value = await load();
      if (active) setData(value);
    });
    return () => {
      active = false;
    };
  }, deps);
  return data;
}
function Secrets({ scope, tick, act, setModal, setNotice }) {
  const [data, setData] = useState(null),
    [search, setSearch] = useState("");
  const base = "/projects/" + scope.projectId,
    query =
      "?" +
      new URLSearchParams({ environment: scope.environment, path: scope.path });
  useEffect(() => {
    setData(null);
    let active = true;
    act(async () => {
      const value = await api(base + "/secrets" + query);
      if (active) setData(value);
    });
    return () => {
      active = false;
    };
  }, [scope.projectId, scope.environment, scope.path, tick]);
  const rows = data?.secrets.filter((row) =>
    row.key.toLowerCase().includes(search.toLowerCase()),
  );
  return (
    <Panel
      title="Secrets"
      description="Values are encrypted at rest and revealed only on request."
      action={
        <div className="actions">
          <Button onClick={() => setModal({ kind: "import" })}>
            Import .env
          </Button>
          <Button
            onClick={() =>
              act(async () => {
                const text = await api(base + "/export" + query);
                const url = URL.createObjectURL(
                  new Blob([text], { type: "text/plain" }),
                );
                const a = document.createElement("a");
                a.href = url;
                a.download = "secrets.env";
                a.click();
                setTimeout(() => URL.revokeObjectURL(url), 1000);
                setNotice(
                  "Export downloaded. Store the plaintext file securely.",
                );
              })
            }
          >
            Export
          </Button>
          <Button kind="primary" onClick={() => setModal({ kind: "secret" })}>
            ＋ Add secret
          </Button>
        </div>
      }
    >
      <div className="table-toolbar">
        <input
          aria-label="Search keys"
          className="search"
          value={search}
          onChange={(event) => setSearch(event.target.value)}
          placeholder="Search secret keys…"
        />
        <span className="muted small">
          {data?.secrets.length ?? "—"} secrets
        </span>
      </div>
      {!data ? (
        <p className="loading">Loading secrets…</p>
      ) : !rows.length ? (
        <Empty title="No secrets here yet">
          Add a secret or import an environment file into this folder.
        </Empty>
      ) : (
        <div className="table-wrap">
          <table>
            <thead>
              <tr>
                <th>Key</th>
                <th>Value</th>
                <th>Version</th>
                <th>Updated</th>
                <th>Actions</th>
              </tr>
            </thead>
            <tbody>
              {rows.map((row) => (
                <tr key={row.id}>
                  <td>
                    <code>{row.key}</code>
                    {row.deleted_at && <Badge tone="red">Deleted</Badge>}
                  </td>
                  <td className="masked">••••••••••••</td>
                  <td>
                    <Badge>v{row.version}</Badge>
                  </td>
                  <td className="small muted">{date(row.updated_at)}</td>
                  <td>
                    <div className="actions">
                      {!row.deleted_at && (
                        <>
                          <Button
                            kind="quiet"
                            onClick={() =>
                              act(async () => {
                                const value = await api(
                                  base + "/secrets/" + row.id + "/value",
                                );
                                setModal({
                                  kind: "disclosure",
                                  title: row.key,
                                  text: value.value,
                                });
                              })
                            }
                          >
                            Reveal
                          </Button>
                          <Button
                            kind="quiet"
                            onClick={() =>
                              setModal({ kind: "secret", key: row.key })
                            }
                          >
                            Update
                          </Button>
                        </>
                      )}
                      <Button
                        kind="quiet"
                        onClick={() =>
                          setModal({
                            kind: "history",
                            id: row.id,
                            secretKey: row.key,
                          })
                        }
                      >
                        History
                      </Button>
                      {!row.deleted_at && (
                        <Button
                          kind="danger quiet"
                          onClick={() =>
                            act(async () => {
                              if (
                                !confirm(
                                  "Delete this secret? Recovery is available for 30 days.",
                                )
                              )
                                return;
                              await api(
                                base + "/secrets/" + row.id,
                                "DELETE",
                                {},
                              );
                              setData(await api(base + "/secrets" + query));
                            })
                          }
                        >
                          Delete
                        </Button>
                      )}
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </Panel>
  );
}
function ImportDialog({ scope, act, close, refresh }) {
  const [preview, setPreview] = useState(null),
    [content, setContent] = useState(""),
    [conflicts, setConflicts] = useState("skip");
  const body = { ...scope, content, conflicts };
  return (
    <Dialog title="Import an environment file" onClose={close}>
      <p className="muted">
        Import into {scope.environment} · {scope.path}. Values are never
        executed or interpolated.
      </p>
      <Field label="Choose a .env file">
        <input
          type="file"
          accept=".env,text/plain"
          onChange={(event) =>
            act(async () => {
              const file = event.target.files[0];
              if (!file) return;
              if (file.size > 256 * 1024)
                throw new Error("File must be at most 256 KiB.");
              setContent(await file.text());
              setPreview(null);
            })
          }
        />
      </Field>
      <Field label="Or paste environment content">
        <textarea
          rows="8"
          value={content}
          onChange={(event) => {
            setContent(event.target.value);
            setPreview(null);
          }}
          spellCheck="false"
          autoComplete="off"
        />
      </Field>
      <Field label="Existing keys">
        <select
          value={conflicts}
          onChange={(event) => setConflicts(event.target.value)}
        >
          <option value="skip">Skip existing keys</option>
          <option value="overwrite">
            Create new versions for existing keys
          </option>
        </select>
      </Field>
      {preview && (
        <div className="message">
          {preview.keys.length} keys · {preview.conflicts.length} conflicts.
          Deleted keys are skipped.
          <p className="small">{preview.keys.join(", ")}</p>
        </div>
      )}
      <div className="actions">
        <Button
          onClick={() =>
            act(async () =>
              setPreview(
                await api(
                  "/projects/" + scope.projectId + "/import/preview",
                  "POST",
                  body,
                ),
              ),
            )
          }
        >
          Preview
        </Button>
        <Button
          kind="primary"
          disabled={!preview}
          onClick={() =>
            act(async () => {
              await api(
                "/projects/" + scope.projectId + "/import",
                "POST",
                body,
              );
              refresh();
              close();
            })
          }
        >
          Apply import
        </Button>
      </div>
    </Dialog>
  );
}
function History({ projectId, id, secretKey, act, close, refresh }) {
  const data = useData(
    () => api("/projects/" + projectId + "/secrets/" + id + "/versions"),
    [id],
    act,
  );
  return (
    <Dialog title={"History · " + secretKey} onClose={close}>
      <p className="muted">
        Restoring creates a new version and recovers a deleted secret within 30
        days.
      </p>
      {data?.versions.map((row) => (
        <div className="list-row" key={row.version}>
          <div>
            <strong>Version {row.version}</strong>
            <small>{date(row.created_at)}</small>
          </div>
          <Button
            onClick={() =>
              act(async () => {
                await api(
                  "/projects/" + projectId + "/secrets/" + id + "/restore",
                  "POST",
                  { version: row.version },
                );
                refresh();
                close();
              })
            }
          >
            Restore
          </Button>
        </div>
      ))}
    </Dialog>
  );
}
function Roles({ prefix, projectId, tick, act, setModal, refresh }) {
  const data = useData(() => api(prefix + "/roles"), [prefix, tick], act);
  return (
    <>
      <Panel
        title="Roles"
        description={
          projectId
            ? "Project roles can be restricted by environment and folder."
            : "Organization roles manage administration; secret access is granted separately per project."
        }
        action={
          <Button
            kind="primary"
            onClick={() =>
              setModal({
                kind: "role",
                prefix,
                available: data?.availablePermissions || [],
              })
            }
          >
            ＋ Create role
          </Button>
        }
      >
        {!data ? (
          <p className="loading">Loading roles…</p>
        ) : (
          data.roles.map((role) => (
            <div className="role-row" key={role.id}>
              <div>
                <h3>
                  {role.name} {role.builtin && <Badge>Built-in</Badge>}
                </h3>
                <p className="small muted">
                  {role.permissions.join(" · ") || "No permissions"}
                </p>
              </div>
              {!role.builtin && (
                <div className="actions">
                  <Button
                    onClick={() =>
                      setModal({
                        kind: "role",
                        prefix,
                        available: data.availablePermissions,
                        role,
                      })
                    }
                  >
                    Edit
                  </Button>
                  <Button
                    kind="danger quiet"
                    onClick={() =>
                      act(async () => {
                        if (confirm("Delete this role and its assignments?")) {
                          await api(prefix + "/roles/" + role.id, "DELETE", {});
                          refresh();
                        }
                      })
                    }
                  >
                    Delete
                  </Button>
                </div>
              )}
            </div>
          ))
        )}
      </Panel>
      <Panel
        title="Assignments"
        description="No assignment means no access."
        action={
          <Button
            onClick={() =>
              setModal({
                kind: "binding",
                prefix,
                roles: data?.roles || [],
                projectId,
              })
            }
          >
            Assign a role
          </Button>
        }
      >
        {data?.bindings.length ? (
          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>Identity</th>
                  <th>Role</th>
                  <th>Scope</th>
                  <th>Actions</th>
                </tr>
              </thead>
              <tbody>
                {data.bindings.map((binding) => (
                  <tr key={binding.id}>
                    <td>
                      {binding.principal || binding.principal_id}
                      <small>{binding.principal_type}</small>
                    </td>
                    <td>
                      {
                        data.roles.find((role) => role.id === binding.role_id)
                          ?.name
                      }
                    </td>
                    <td>
                      {binding.environment || "All environments"} ·{" "}
                      {binding.path}
                    </td>
                    <td>
                      <Button
                        kind="danger quiet"
                        onClick={() =>
                          act(async () => {
                            if (confirm("Remove this access assignment?")) {
                              await api(
                                prefix + "/bindings/" + binding.id,
                                "DELETE",
                                {},
                              );
                              refresh();
                            }
                          })
                        }
                      >
                        Remove
                      </Button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          <Empty title="No role assignments">
            Assign an existing teammate or a machine identity.
          </Empty>
        )}
      </Panel>
    </>
  );
}
function RoleDialog({ prefix, available, role, act, close, refresh }) {
  const [permissions, setPermissions] = useState(role?.permissions || []);
  return (
    <Dialog
      title={role ? "Edit custom role" : "Create custom role"}
      onClose={close}
    >
      <Form
        label="Save role"
        submit={(data) =>
          act(async () => {
            await api(
              prefix + "/roles" + (role ? "/" + role.id : ""),
              role ? "PATCH" : "POST",
              { name: data.get("name"), permissions },
            );
            refresh();
            close();
          })
        }
      >
        <Field
          label="Role name"
          name="name"
          required
          defaultValue={role?.name}
          maxLength="80"
        />
        <div className="permission-grid">
          {available.map((permission) => (
            <label className="check" key={permission}>
              <input
                type="checkbox"
                checked={permissions.includes(permission)}
                onChange={(event) =>
                  setPermissions(
                    event.target.checked
                      ? [...permissions, permission]
                      : permissions.filter((item) => item !== permission),
                  )
                }
              />
              <code>{permission}</code>
            </label>
          ))}
        </div>
      </Form>
    </Dialog>
  );
}
function BindingDialog({ prefix, roles, projectId, act, close, refresh }) {
  const [type, setType] = useState("user");
  return (
    <Dialog title="Assign a scoped role" onClose={close}>
      <Form
        label="Grant access"
        submit={(data) =>
          act(async () => {
            await api(prefix + "/bindings", "POST", {
              roleId: data.get("roleId"),
              principalType: type,
              ...(type === "user"
                ? { email: data.get("identity") }
                : { principalId: data.get("identity") }),
              environment: data.get("environment") || null,
              path: data.get("path") || "/",
            });
            refresh();
            close();
          })
        }
      >
        <Field label="Role">
          <select name="roleId" required>
            <option value="">Select a role</option>
            {roles.map((role) => (
              <option key={role.id} value={role.id}>
                {role.name}
              </option>
            ))}
          </select>
        </Field>
        {projectId && (
          <Field label="Identity type">
            <select
              value={type}
              onChange={(event) => setType(event.target.value)}
            >
              <option value="user">Person</option>
              <option value="machine">Machine</option>
            </select>
          </Field>
        )}
        <Field
          label={
            type === "user" ? "Existing user email" : "Machine identity ID"
          }
          name="identity"
          required
          type={type === "user" ? "email" : "text"}
        />
        {projectId && (
          <>
            <Field
              label="Environment · leave empty for all"
              name="environment"
              placeholder="production"
            />
            <Field label="Folder scope" name="path" defaultValue="/" />
          </>
        )}
        <p className="muted">
          You can only grant permissions you hold at this scope.
        </p>
      </Form>
    </Dialog>
  );
}
function Machines({ projectId, tick, act, setModal, refresh }) {
  const data = useData(
    () => api("/projects/" + projectId + "/machines"),
    [projectId, tick],
    act,
  );
  return (
    <Panel
      title="Machine identities"
      description="Credential rotation supports overlapping credentials. Revocation also invalidates existing access tokens."
      action={
        <Button kind="primary" onClick={() => setModal({ kind: "machine" })}>
          ＋ Create identity
        </Button>
      }
    >
      {data?.machines.length ? (
        data.machines.map((machine) => (
          <div className="machine-card" key={machine.id}>
            <div className="role-row">
              <div>
                <h3>
                  {machine.name}{" "}
                  <Badge tone={machine.disabled ? "red" : "green"}>
                    {machine.disabled ? "Disabled" : "Active"}
                  </Badge>
                </h3>
                <code className="small">{machine.id}</code>
              </div>
              <div className="actions">
                <Button
                  onClick={() =>
                    act(async () => {
                      const value = await api(
                        "/projects/" +
                          projectId +
                          "/machines/" +
                          machine.id +
                          "/credentials",
                        "POST",
                        { days: 30 },
                      );
                      refresh();
                      setModal({
                        kind: "disclosure",
                        title: "Machine credential · shown once",
                        text: JSON.stringify(value, null, 2),
                      });
                    })
                  }
                  disabled={machine.disabled}
                >
                  Issue 30-day credential
                </Button>
                <Button
                  kind="quiet"
                  onClick={() =>
                    act(async () => {
                      await api(
                        "/projects/" + projectId + "/machines/" + machine.id,
                        "PATCH",
                        { disabled: !machine.disabled },
                      );
                      refresh();
                    })
                  }
                >
                  {machine.disabled ? "Enable" : "Disable"}
                </Button>
              </div>
            </div>
            {data.credentials
              .filter((row) => row.machine_id === machine.id)
              .map((row) => (
                <div className="list-row small" key={row.id}>
                  <div>
                    <code>{row.id}</code>
                    <small>
                      Expires {date(row.expires_at)}{" "}
                      {row.revoked ? "· Revoked" : ""}
                    </small>
                  </div>
                  {!row.revoked && (
                    <Button
                      kind="danger quiet"
                      onClick={() =>
                        act(async () => {
                          await api(
                            "/projects/" + projectId + "/credentials/" + row.id,
                            "DELETE",
                            {},
                          );
                          refresh();
                        })
                      }
                    >
                      Revoke
                    </Button>
                  )}
                </div>
              ))}
          </div>
        ))
      ) : (
        <Empty title="No machine identities">
          Create an identity, assign a project role, and issue its first
          credential.
        </Empty>
      )}
    </Panel>
  );
}
function Users({ tick, act, setModal, refresh, googleOnly }) {
  const data = useData(() => api("/admin/users"), [tick], act);
  return (
    <>
      <Panel
        title="People"
        action={
          <Button kind="primary" onClick={() => setModal({ kind: "invite" })}>
            ＋ Invite teammate
          </Button>
        }
      >
        {data && (
          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>Person</th>
                  <th>Authentication</th>
                  <th>Status</th>
                  <th>Actions</th>
                </tr>
              </thead>
              <tbody>
                {data.users.map((user) => (
                  <tr key={user.id}>
                    <td>
                      <strong>{user.name}</strong>
                      <small>{user.email}</small>
                    </td>
                    <td>
                      <Badge tone={user.mfa_enabled ? "green" : ""}>
                        {user.mfa_enabled ? "2FA enabled" : "Not enrolled"}
                      </Badge>
                    </td>
                    <td>
                      {user.owner
                        ? "Owner"
                        : user.disabled
                          ? "Disabled"
                          : "Active"}
                    </td>
                    <td>
                      <div className="actions">
                        {!googleOnly && (
                          <Button
                            kind="quiet"
                            onClick={() =>
                              setModal({ kind: "invite", email: user.email })
                            }
                          >
                            Reset password
                          </Button>
                        )}
                        <Button
                          kind="quiet"
                          onClick={() =>
                            act(async () => {
                              await api(
                                "/admin/users/" + user.id + "/sessions",
                                "DELETE",
                                {},
                              );
                              refresh();
                            })
                          }
                        >
                          Revoke sessions
                        </Button>
                        {!user.owner && (
                          <Button
                            kind="danger quiet"
                            onClick={() =>
                              act(async () => {
                                await api("/admin/users/" + user.id, "PATCH", {
                                  disabled: !user.disabled,
                                });
                                refresh();
                              })
                            }
                          >
                            {user.disabled ? "Enable" : "Disable"}
                          </Button>
                        )}
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Panel>
      <Panel
        title="Invitation & reset links"
        description="Links are single-use. Creating a new link for an email revokes previous outstanding links."
      >
        {data?.invitations.length ? (
          data.invitations.map((invite) => (
            <div className="list-row" key={invite.id}>
              <div>
                <strong>{invite.email}</strong>
                <small>
                  {invite.kind} · Expires {date(invite.expires_at)} ·{" "}
                  {invite.used ? "Used or revoked" : "Pending"}
                </small>
              </div>
              {!invite.used && (
                <Button
                  kind="danger quiet"
                  onClick={() =>
                    act(async () => {
                      await api(
                        "/admin/invitations/" + invite.id,
                        "DELETE",
                        {},
                      );
                      refresh();
                    })
                  }
                >
                  Revoke
                </Button>
              )}
            </div>
          ))
        ) : (
          <Empty title="No outstanding links">
            Invitation URLs appear once when created, with or without email
            configured.
          </Empty>
        )}
      </Panel>
    </>
  );
}
function Settings({ tick, act, setNotice }) {
  const data = useData(() => api("/settings"), [tick], act);
  const [force, setForce] = useState(true),
    [enabled, setEnabled] = useState(false);
  useEffect(() => {
    if (data) {
      setForce(data.requireMfa);
      setEnabled(data.mail.enabled);
    }
  }, [data]);
  if (!data) return <p className="loading">Loading settings…</p>;
  return (
    <Panel
      title="Authentication & email"
      description="Resend is optional. Invitation links work without an email service."
    >
      <Form
        label="Save settings"
        submit={(form, element) =>
          act(async () => {
            await api("/settings", "PUT", {
              requireMfa: force,
              ...(data.mail.source === "environment"
                ? {}
                : {
                    mail: {
                      enabled,
                      from: form.get("from"),
                      key: form.get("key"),
                    },
                  }),
            });
            element.elements.key && (element.elements.key.value = "");
            setNotice("Settings saved.");
          })
        }
      >
        <label className="check">
          <input
            type="checkbox"
            checked={force}
            onChange={(event) => setForce(event.target.checked)}
          />
          Require authenticator-app 2FA for every person
        </label>
        <hr />
        <div className="role-row">
          <div>
            <h3>Resend email delivery</h3>
            <p className="muted small">
              Configuration source: {data.mail.source}
            </p>
          </div>
          <Badge>
            {data.mail.keyConfigured ? "Key configured" : "No API key"}
          </Badge>
        </div>
        <fieldset disabled={data.mail.source === "environment"}>
          <label className="check">
            <input
              type="checkbox"
              checked={enabled}
              onChange={(event) => setEnabled(event.target.checked)}
            />
            Enable email delivery
          </label>
          <Field
            label="Sender email · verify its domain in Resend"
            name="from"
            type="email"
            defaultValue={data.mail.from}
          />
          <Field
            label="Resend API key · leave empty to preserve the saved key"
            name="key"
            type="password"
            autoComplete="new-password"
          />
        </fieldset>
      </Form>
      <hr />
      <Form
        label="Send test email"
        submit={(form) =>
          act(async () => {
            const result = await api("/settings/test-email", "POST", {
              email: form.get("email"),
            });
            setNotice("Test email: " + result.emailStatus);
          })
        }
      >
        <Field label="Test recipient" name="email" type="email" required />
      </Form>
    </Panel>
  );
}
function Audit({ act, projects, user }) {
  const canOrg = user.owner || user.permissions.includes("org.audit.read");
  const choices = canOrg
    ? projects
    : projects.filter((project) =>
        project.scopes?.some((scope) =>
          scope.permissions?.includes("project.audit.read"),
        ),
      );
  const [project, setProject] = useState(canOrg ? "" : choices[0]?.id || ""),
    [data, setData] = useState(null);
  useEffect(() => {
    setData(null);
    act(async () =>
      setData(
        await api(
          "/audit" +
            (() => {
              if (!project) return "";
              const scope = projects
                .find((item) => item.id === project)
                ?.scopes?.find((item) =>
                  item.permissions?.includes("project.audit.read"),
                );
              const query = new URLSearchParams({
                projectId: project,
                path: scope?.path || "/",
              });
              if (scope?.environment)
                query.set("environment", scope.environment);
              return "?" + query;
            })(),
        ),
      ),
    );
  }, [project]);
  return (
    <Panel
      title="Recent activity"
      description="Most recent 200 events. Secret values and credentials are never included."
      action={
        <select
          aria-label="Audit scope"
          value={project}
          onChange={(event) => setProject(event.target.value)}
        >
          {canOrg && <option value="">Organization</option>}
          {choices.map((row) => (
            <option value={row.id} key={row.id}>
              {row.name}
            </option>
          ))}
        </select>
      }
    >
      {data?.events.length ? (
        <div className="table-wrap">
          <table>
            <thead>
              <tr>
                <th>Action</th>
                <th>Identity</th>
                <th>Scope</th>
                <th>Time</th>
              </tr>
            </thead>
            <tbody>
              {data.events.map((row) => (
                <tr key={row.id}>
                  <td>
                    <code>{row.action}</code>
                  </td>
                  <td>
                    {row.actor_type || "Anonymous"}
                    <small>{row.actor_id?.slice(0, 8) || "—"}</small>
                  </td>
                  <td>
                    {row.environment || "—"} {row.path || ""}
                  </td>
                  <td className="small muted">{date(row.created_at)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ) : (
        <Empty title="No activity to display">
          Events appear as people and machines use the service.
        </Empty>
      )}
    </Panel>
  );
}
function Security({ user, act, setEnrollment, setModal, setUser }) {
  const data = useData(() => api("/auth/sessions"), [], act);
  return (
    <>
      <Panel
        title="Authenticator app"
        description={
          user.primaryMethod === "google"
            ? "Sign in again with Google, then replace your authenticator within five minutes using a current code or recovery code."
            : "Replacing your authenticator requires your password and a current code or unused recovery code."
        }
      >
        <Badge tone={user.mfaEnabled ? "green" : ""}>
          {user.mfaEnabled
            ? "Authenticator enabled"
            : "Authenticator not enrolled"}
        </Badge>
        <Form
          label={
            user.mfaEnabled ? "Replace authenticator" : "Enroll authenticator"
          }
          submit={(form) =>
            act(async () =>
              setEnrollment(
                await api("/auth/mfa/start", "POST", {
                  password: form.get("password"),
                  code: form.get("code"),
                }),
              ),
            )
          }
        >
          {user.mfaEnabled && (
            <>
              {user.primaryMethod !== "google" && (
                <Field
                  label="Current password"
                  name="password"
                  type="password"
                  required
                  autoComplete="current-password"
                />
              )}
              <Field
                label="Current authenticator or recovery code"
                name="code"
                required
                autoComplete="one-time-code"
              />
            </>
          )}
        </Form>
      </Panel>
      {user.googleEnabled && (
        <Panel
          title="Google sign-in"
          description="Existing password accounts must link Google explicitly after verifying their password and authenticator."
        >
          {user.googleLinked ? (
            <Badge tone="green">Google account linked</Badge>
          ) : (
            <Form
              label="Link Google account"
              submit={(form) =>
                act(() =>
                  startGoogle({ action: "link", ...Object.fromEntries(form) }),
                )
              }
            >
              <Field
                label="Current password"
                name="password"
                type="password"
                required
                autoComplete="current-password"
              />
              {user.mfaEnabled && (
                <Field
                  label="Authenticator or recovery code"
                  name="code"
                  required
                  autoComplete="one-time-code"
                />
              )}
            </Form>
          )}
        </Panel>
      )}
      {user.hasPassword && !user.googleOnly && (
        <Panel
          title="Change password"
          description="Changing your password revokes all existing sessions."
        >
          <Form
            label="Change password"
            submit={(form) =>
              act(async () => {
                await api("/auth/password", "POST", Object.fromEntries(form));
                setUser(null);
              })
            }
          >
            <Field
              label="Current password"
              name="currentPassword"
              type="password"
              required
              autoComplete="current-password"
            />
            <Field
              label="New password · at least 14 characters"
              name="password"
              type="password"
              required
              minLength="14"
              maxLength="256"
              autoComplete="new-password"
            />
            {user.mfaEnabled && (
              <Field
                label="Authenticator or recovery code"
                name="code"
                required
                autoComplete="one-time-code"
              />
            )}
          </Form>
        </Panel>
      )}
      <Panel
        title="Active sessions"
        action={
          <Button
            kind="danger"
            onClick={() =>
              act(async () => {
                await api("/auth/sessions", "DELETE", {});
                setUser(null);
              })
            }
          >
            Revoke all sessions
          </Button>
        }
      >
        {data?.sessions.map((row, index) => (
          <div className="list-row" key={index}>
            <div>
              <strong>
                {row.current ? "This session" : "Another session"}
              </strong>
              <small>
                Created {date(row.created_at)} · Expires {date(row.expires_at)}
              </small>
            </div>
          </div>
        ))}
      </Panel>
    </>
  );
}
createRoot(document.getElementById("root")).render(<App />);
