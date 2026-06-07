# Outreach Tracker

A multi-user donor-outreach tracking app for managing an annual fundraising
campaign. A small Node/Express service serves the browser frontend and a JSON API,
authenticates users, enforces per-contact access control, and persists everything to
a file-backed store on a Docker volume. Mobile-first, with a sidebar + master/detail
layout above 900px.

## Architecture

- **`server.js`** — Express service. Serves `public/index.html`, exposes `/api/*`,
  hashes passwords (`crypto.scrypt`), issues a signed `HttpOnly` session cookie, and
  reads/writes a single JSON document at `$DATA_DIR/db.json` (atomic writes).
- **`public/index.html`** — the whole frontend (vanilla HTML/CSS/JS, SheetJS from a
  CDN for Excel parsing). Loads/saves through the API; `localStorage` is only an
  offline cache.

## Users & access control

- **Per-user accounts.** Everyone signs in with an email + password.
- **Roles:** `admin` and `user`.
- **Per-contact access.** A user sees only contacts they **own** (created/imported) or
  are **assigned** to. Admins see everything.
- **Assignment.** Admins can assign any contact; a contact's **owner** can also share
  it with teammates (from the contact's *Access* card). User account management
  (create / delete / role / password reset) is **admin-only**, in the **Team** tab.

## Run it (local, with Docker)

```bash
SESSION_SECRET=$(openssl rand -hex 32) \
ADMIN_EMAIL=you@example.com ADMIN_PASSWORD=changeme \
PUBLIC_BASE_PATH= \
docker compose up --build
```

Then open http://localhost (the compose file routes through Traefik in production; for
a quick local run you can also `docker build -t outreach . && docker run -p 3000:3000
-e ADMIN_EMAIL=you@example.com -e ADMIN_PASSWORD=changeme -v $PWD/data:/data outreach`
and open http://localhost:3000).

The first boot creates an admin from `ADMIN_EMAIL` / `ADMIN_PASSWORD` **only if no
users exist yet**. Add the rest of your team from the Team tab.

## Configuration (environment variables)

| Var | Purpose |
| --- | --- |
| `SESSION_SECRET` | Signs session cookies. Set a long random value. If unset, a random secret is generated and persisted to the data volume. |
| `ADMIN_EMAIL` / `ADMIN_PASSWORD` | First-boot admin account (ignored once any user exists). |
| `ADMIN_NAME` | Display name for the bootstrap admin (default `Admin`). |
| `PUBLIC_BASE_PATH` | Path the app is served under behind the proxy (e.g. `/outreach`). Empty for root. |
| `DATA_DIR` | Where `db.json` lives (default `/data`). |
| `PORT` | Listen port (default `3000`). |

In Coolify, set `SESSION_SECRET`, `ADMIN_EMAIL`, and `ADMIN_PASSWORD` as environment
variables; `docker-compose.yml` wires them in and persists data to the `outreach-data`
volume.

## Features

- **Excel import** — reads a Salesforce/Chabad.org `.xlsx` export; unknown columns are
  captured as custom fields. Imported contacts are owned by the importer. Export to a
  Salesforce-ready CSV.
- **Households, tiers, two tabs (Courting / Pledged), journey arcs, pledge tracking,
  touchpoints, today's dashboard with goal ring + streak, interaction logging with
  voice-to-text, and follow-up tasks** — see the in-app UI.
- Hebrew verses from Pirkei Avot (Rabbi Tarfon) under the progress bars.

## Tech

Node 22 + Express, no database server (JSON document store). Frontend is plain
HTML/CSS/JS, no framework. Inter + Frank Ruhl Libre via Google Fonts; SheetJS via CDN.

## Notes

This tool manages donor PII. Donor data lives only on the server's data volume (it is
**not** committed to this repo — see `.gitignore`). Keep this repository **private**
and always run behind HTTPS.
