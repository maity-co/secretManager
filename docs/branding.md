# Maity visual identity

SecretManager uses Maity's public orange wordmark, dark surfaces, orange primary
actions and locally hosted Geist type. The sign-in, owner setup, authenticator,
workspace, dialogs and script-free information page share the same theme.
Theme tokens live in [brand.css](../web/brand.css).

Assets are bundled in the application image and served from the same origin.
Loading these pages requires no external font service, analytics or logo host.
Branding does not configure an account domain, owner email or hosting endpoint.

## Public asset provenance

- [Maity wordmark](https://maity.pro/maity-logo.png), downloaded unchanged from
  Maity's public website at the owner's request.
  SHA-256: `c596c7b1e0a2c33a4d4dc6e3187feae2e5538f76749871feea4b0845ed784321`.
- [Maity icon](https://maity.pro/maity-icon.png), downloaded unchanged from
  the same public website.
  SHA-256: `fc2759323e97c7d383f5f97f18e38a3fd66447df90898ca5ca170e99321ed433`.
- [Geist variable WOFF2](https://github.com/vercel/geist-font/blob/ef2597cfc42f4797676df105517ccc0a1cfa6569/fonts/Geist/webfonts/Geist%5Bwght%5D.woff2),
  unmodified from upstream revision
  `ef2597cfc42f4797676df105517ccc0a1cfa6569`.
  SHA-256: `2ffebe993e969069a9789d15164b7715d42491b5835516c5e3b935d5f81b05f1`.
  Copyright 2026 The Geist Project Authors. Distributed under the
  [SIL Open Font License 1.1](../web/assets/geist-OFL.txt), also included in the
  built assets.

All layout and styling changes are independently authored in this repository.
No private application source or configuration is included.
