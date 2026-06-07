# Outreach Tracker

A personal donor-outreach tracking app for managing an annual fundraising campaign.
Single self-contained HTML file — no build step, no backend. Mobile-first, with a
two-pane desktop layout above 900px. All data is stored locally in the browser
(`localStorage`).

## Run it

Open `outreach-tracker.html` in any modern browser (Safari on iPhone, Chrome on
Android/desktop). To serve it from the web server, it can be renamed to
`index.html` or pointed at directly.

## Features

- **Excel import** — reads a Salesforce/Chabad.org `.xlsx` export directly; unknown
  columns are captured as custom fields. Export to a Salesforce-ready CSV.
- **Households** — one entry per household with primary and secondary contacts; log
  which spouse you spoke to.
- **Donor tiers** — Top Future / Major / Mid / General, each with default personal
  ("retail") and report/newsletter ("wholesale") touchpoint targets, overridable per
  donor.
- **Two tabs** — Courting (active ask list) and Pledged/Donated (auto-moves on pledge).
- **Journey arcs** — a pre-commitment campaign track and a post-commitment
  appreciation/stewardship track.
- **Pledge tracking** — amount, payment plan, individual payments, fulfillment bar.
- **Touchpoints** — personal vs. report/newsletter, with progress bars; bulk-log a
  wholesale touchpoint to many donors at once.
- **Today's dashboard** — daily call goal with progress ring, streak counter, and a
  tap-to-call list.
- **Interaction logging** — call/text/email/meeting/etc. with date, notes
  (voice-to-text), and an optional follow-up task.
- **Tasks** — due dates with overdue/today/upcoming grouping.
- Hebrew verses from Pirkei Avot (Rabbi Tarfon) under the progress bars.

## Tech

Plain HTML/CSS/JavaScript, no framework. Uses SheetJS (loaded from a CDN) for Excel
parsing. Data persists in `localStorage` on the same device/browser.

## Roadmap

- Warm Editorial visual redesign (in progress).
- Server/database sync so data persists across devices.
- Optional AI-assisted voice logging.

## Notes

This tool is for managing donor relationships. Although donor data lives only in the
browser (it is **not** committed to this repo), keep this repository **private**.
