<div align="center">

# 🔐 2FA Offline

**TOTP codes generated entirely in your browser — no ads, no server, no network requests**

[![Live demo](https://img.shields.io/badge/demo-totp.io.vn-2ea44f?style=flat-square&logo=vercel&logoColor=white)](https://totp.io.vn)
[![License](https://img.shields.io/badge/license-MIT-yellow?style=flat-square)](LICENSE)
[![Dependencies](https://img.shields.io/badge/dependencies-0-brightgreen?style=flat-square)](#project-layout)
[![Build step](https://img.shields.io/badge/build%20step-none-brightgreen?style=flat-square)](#running-it)
[![JavaScript](https://img.shields.io/badge/JavaScript-vanilla-F7DF1E?style=flat-square&logo=javascript&logoColor=black)](#project-layout)
[![PWA](https://img.shields.io/badge/PWA-offline%20ready-5A0FC8?style=flat-square)](#offline-behaviour)
[![RFC 6238](https://img.shields.io/badge/RFC%206238-verified-success?style=flat-square)](#totp)
[![Vault](https://img.shields.io/badge/AES--256--GCM-encrypted%20vault-informational?style=flat-square)](#vault-encryption)

***English** · [Tiếng Việt](README.vi.md)*

</div>

A TOTP generator (compatible with Google Authenticator / Authy) that runs **entirely in
the browser**. No ads, no server, no network requests — enforced by the browser, not
promised by me.

Written from scratch: no dependencies, no build step, nothing loaded from a CDN.

## Why this exists

Web-based 2FA tools are convenient but usually ad-supported and opaque about what leaves
your machine. This one takes the opposite position: the page declares
`connect-src 'none'`, so the browser physically refuses to let it send a request
anywhere. You can confirm that yourself in DevTools instead of taking my word for it.

## Running it

**Open the file directly** — double-click `index.html`. Works with the network cable
unplugged.

**Or serve it locally** (needed for PWA install and SHA-512 secrets):

```bash
python -m http.server 8791
```

Then open http://localhost:8791

## Implementation notes

### TOTP

`js/totp.js` implements RFC 6238 and `js/base32.js` implements RFC 4648 decoding.
Both are verified against **the complete RFC 6238 test vector set** (SHA-1, SHA-256 and
SHA-512) and cross-checked against Node's `crypto` module.

The browser's Web Crypto is used when available. When it isn't — some browsers withhold
`crypto.subtle` from `file://` origins — the app falls back to a pure-JavaScript
HMAC-SHA1/SHA256 implementation in `js/sha.js`, which produces byte-identical results.
SHA-512 requires Web Crypto. A line in the footer tells you which path is active.

### Vault encryption

Off by default. When enabled, accounts are encrypted with **AES-256-GCM** before they
touch `localStorage`. The key is derived with **PBKDF2-HMAC-SHA256 at 600,000 iterations**
(the OWASP recommendation), a random 16-byte salt, and a fresh 12-byte IV on **every**
write — reusing an IV would break GCM.

The key is non-extractable and lives only in memory. There is no password hash stored
anywhere: a wrong password simply makes AES-GCM's authentication tag fail, which is what
the lock screen reports. That also means **there is no recovery path**, by design.

When locked, the UI behind the overlay is genuinely inert, not merely covered — every
control gets `disabled`, `<main>` and `<footer>` get `inert`, and the handlers carry
their own `if (locked) return` guards. Three independent layers, so one failing still
leaves two.

### Content Security Policy

```
default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self';
manifest-src 'self'; worker-src 'self'; connect-src 'none';
base-uri 'none'; form-action 'none'
```

`connect-src 'none'` was verified by attacking the page from its own console: `fetch`
(both cross-origin and same-origin), `XMLHttpRequest`, `WebSocket`,
`navigator.sendBeacon`, and an image request to an external host with a secret in the
query string — all blocked, all producing CSP violation reports.

The policy sits in a `<meta>` tag rather than an HTTP header on purpose: the service
worker *needs* `fetch` to cache for offline use, and a header would apply to `sw.js` too.
A `<meta>` policy only governs the document.

`vercel.json` adds the transport-level headers a meta tag cannot express — HSTS,
`X-Content-Type-Options`, `X-Frame-Options: DENY`, `Referrer-Policy: no-referrer`,
`Permissions-Policy`, COOP/CORP, and `frame-ancestors 'none'`.

### Offline behaviour

The service worker precaches all 13 assets and uses stale-while-revalidate, so updates
still reach users instead of being pinned to the first version they ever loaded.

This was verified by shutting the local server down entirely and reloading: the page
rendered, TOTP generation returned the expected code, saving worked, and enabling
AES-GCM vault encryption worked — with nothing listening on the port.

## Input format

One account per line; paste as many lines as you like.

| Form | Example |
|---|---|
| `email\|password\|secret` | `abc@icloud.com\|Pw#123\|JBSWY3DPEHPK3PXP` |
| `email\|secret` | `abc@icloud.com\|JBSWY3DPEHPK3PXP` |
| `secret` | `JBSWY3DPEHPK3PXP` |
| otpauth URI | `otpauth://totp/GitHub:abc?secret=...&digits=8&period=60` |

The parsing rule is **first field is the label, last field is the secret**, and
everything between them is the password. That is what lets passwords contain the `|`
character without escaping — and it is also why groups are *not* a fourth field.

Secrets are case-insensitive; whitespace and `=` padding are stripped.

## Features

- Live codes for many accounts at once, each with its own countdown ring
- The **next code** is shown ahead of time, so a 2-second window is not a problem
- Persistent list with search, edit, delete and drag-to-reorder
- **Groups** — assign on bulk paste, filter chips with counts, multi-select for bulk
  reassign and delete, rename and delete groups
- Configurable `digits` (6/7/8), `period`, and algorithm (SHA-1/256/512)
- Optional **master password** with lock screen and idle auto-lock
- Click to copy code, email, secret or password
- `.json` and `.txt` export/import
- Secrets and passwords masked by default
- Manual clock offset, for offline machines whose time has drifted
- **Bilingual (English / Tiếng Việt)** — follows the browser language on first
  visit, switchable from the toolbar, remembered afterwards
- Light/dark theme, responsive, installable as a PWA

### Localisation

All strings live in `js/i18n.js` as two dictionaries; nothing is fetched at runtime, so
the offline guarantee and `connect-src 'none'` still hold. Static text is marked up with
`data-i18n` (textContent), `data-i18n-html` (strings containing `<b>`/`<code>`) and
`data-i18n-attr` (placeholder, title, aria-label); dynamic strings go through `t()`.

Default labels are deliberately *not* baked into stored data — an account with no label
is stored as an empty string and rendered as "Untitled"/"Không tên" at display time, so
switching language re-labels existing records.

### Guide modal

The how-to panel is a `<dialog>` that springs in on a
`cubic-bezier(0.34, 1.56, 0.64, 1)` curve over a blurred backdrop, with its steps
staggered in. The entry animation is a `@keyframes` rule bound to `.modal[open]` rather
than `@starting-style`, because a dialog is only rendered while `[open]` is present — so
the animation fires at the right moment in every browser that supports `<dialog>`.
Closing waits for the exit animation before calling `close()`, which otherwise removes
the element from the rendering tree instantly. `prefers-reduced-motion` disables all of
it without affecting behaviour.

Groups are derived from the accounts themselves rather than kept in a separate registry,
so orphaned or out-of-sync groups are impossible. Group colours are derived
deterministically from the group name by hash — deliberately not stored, because a colour
map in `settings` would leave group names readable in plaintext even with the vault
encrypted.

## Project layout

```
index.html               UI
css/style.css
js/base32.js             Base32 decoding (RFC 4648)
js/sha.js                Pure-JS SHA-1 / SHA-256 + HMAC (fallback path)
js/totp.js               TOTP (RFC 6238), Web Crypto preferred
js/parser.js             email|password|secret and otpauth:// parsing
js/crypto.js             AES-GCM + PBKDF2 vault encryption
js/storage.js            localStorage read/write
js/app.js                rendering, timers, copy, groups, import/export
sw.js                    service worker (stale-while-revalidate)
```

## Security limitations

Please read these before trusting the tool with anything important.

**Without a master password**, secrets sit in `localStorage` as plaintext. Anyone with
access to the browser profile, and any extension with permission to read the page, can
retrieve them.

**With a master password**, encryption protects data at rest only. While the vault is
unlocked the secrets are in memory and in the DOM. Exported backups are always plaintext.
Encryption does nothing against a keylogger or a malicious extension running alongside.

**If you host this publicly, you become a trusted party.** The browser re-downloads the
JavaScript on every visit, so whoever controls the server, domain or deploy account can
ship a version that exfiltrates secrets, and users cannot tell by looking. A master
password does not help — hostile code in the page reads it as it is typed. This is
inherent to delivering cryptography over the web, and it is the reason this repository is
public: so the code can be compared against what is served, and so anyone who prefers can
download it and run it locally instead.

For high-value accounts — banking, primary email — a dedicated mobile app such as Aegis,
Ente Auth or 2FAS remains the better choice.

## Not implemented

- **QR scanning.** `BarcodeDetector` is unavailable in Chrome/Edge on Windows, so the
  feature would be dead exactly where it was needed. The alternatives were vendoring a QR
  library, which breaks the zero-dependency property, or writing a decoder (~800 lines:
  finder-pattern detection, perspective transform, Reed–Solomon over GF(256)). Pasting is
  faster anyway for the `email|password|secret` format.
- **Cross-device sync.** Deliberately absent — it would require a server and a completely
  different trust model.

## Optional donation block

The footer contains a donation block that appears **only if `icons/donate-qr.png`
exists**. Without the file it stays hidden rather than showing a broken image, so forks
get a clean page by default.

It is deliberately absent from the `ASSETS` list in `sw.js`: `cache.addAll()` rejects
entirely if any entry 404s, which would break the service worker for anyone without the
image. Stale-while-revalidate caches it once it exists.

## License

[MIT](LICENSE) © Tống Huỳnh Hồng Phúc
