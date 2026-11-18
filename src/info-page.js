export const PROJECT_REPOSITORY = "https://github.com/maity-co/secretManager";
const escape = (value) =>
  String(value).replace(
    /[&<>"']/g,
    (char) =>
      ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[
        char
      ],
  );

export function publicInfoPage({ restricted, emailDomains, operatorName }) {
  const heading = operatorName
    ? `This instance is for ${escape(operatorName)} accounts.`
    : "This instance is for its internal team.";
  const access = restricted
    ? `<div class="info-access"><span class="info-status">Private workspace</span><h2>${heading}</h2><p>Account access, password setup and email delivery are limited to ${emailDomains.map((domain) => `<strong>@${escape(domain)}</strong>`).join(", ")} addresses.</p><a class="info-team" href="/signin">Team sign-in <span aria-hidden="true">→</span></a></div>`
    : `<div class="info-access"><span class="info-status">Self-hosted workspace</span><h2>Your instance. Your accounts.</h2><p>Host a separate instance and configure access for your own organization.</p><a class="info-team" href="/signin">Open workspace <span aria-hidden="true">→</span></a></div>`;
  return `<!doctype html>
<html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1"><meta name="color-scheme" content="light"><meta name="description" content="Maity develops SecretManager for internal use. Anyone can self-host their own instance."><title>SecretManager · Self-hosted secrets</title><link rel="stylesheet" href="/info.css"></head>
<body class="info-body"><div class="info-shell"><header class="info-header"><a class="info-logo" href="/info"><span class="info-mark">S</span><span>Secret<strong>Manager</strong></span></a><a class="info-header-link" href="${PROJECT_REPOSITORY}" rel="noreferrer">GitHub <span aria-hidden="true">↗</span></a></header>
<main><section class="info-hero"><div class="info-intro"><p class="info-eyebrow">DEVELOPED BY MAITY · OPEN SOURCE</p><h1>Host your own<br>secrets manager.</h1><p class="info-lead">Maity develops SecretManager for internal use. Anyone is welcome to host their own instance and use the software.</p><div class="info-actions"><a class="info-primary" href="${PROJECT_REPOSITORY}" rel="noreferrer">View source on GitHub <span aria-hidden="true">↗</span></a><a class="info-secondary" href="${PROJECT_REPOSITORY}/blob/main/README.md" rel="noreferrer">Self-hosting guide</a></div><p class="info-note">A web UI, an API and a CLI. One container on your infrastructure.</p></div>${access}</section>
<section class="info-features" aria-label="Included capabilities"><article><span class="info-feature-icon" aria-hidden="true">◈</span><h2>Explicit access</h2><p>Custom roles with project, environment and folder scopes. Access is denied until granted.</p></article><article><span class="info-feature-icon" aria-hidden="true">⌘</span><h2>People &amp; machines</h2><p>Authenticator-app verification for people and separate credentials for applications and CI jobs.</p></article><article><span class="info-feature-icon" aria-hidden="true">▦</span><h2>Self-contained hosting</h2><p>PostgreSQL, the backend and the frontend in one container, with separate persistent storage.</p></article></section>
<section class="info-start"><div><h2>Run it for your own team.</h2><p>Clone the repository and follow the setup and recovery guide.</p></div><code>docker compose up --build -d</code></section></main>
<footer class="info-footer"><span>Built by Maity. Available for anyone to self-host.</span><a href="${PROJECT_REPOSITORY}/blob/main/LICENSE" rel="noreferrer">License</a></footer></div></body></html>`;
}
