# Console settings, accounts, and logging mode

Approved on 17 November 2026. Built and verified the same day; see `docs/test-report.md`.

## Settings

A `settings` table stores values changed in the console:

| Key | Values |
| --- | --- |
| `blocked_rcode` | `REFUSED`, `NXDOMAIN`, `SERVFAIL` |
| `upstream` | `host:port` |
| `upstream_timeout_seconds` | 1–30 |
| `retention_days` | 1–3650 |
| `feed_sync_interval_hours` | 1–720 |
| `log_mode` | `all`, `blocked`, `none` |

A key that has never been saved falls back to `config.json` (`log_mode` falls back to `all`). A saved key wins over the file. The Settings page shows where each value comes from. Listen addresses and the database path stay in the file.

Saving applies at once: the DNS handler reads the current values for every query, and the feed scheduler and retention loop re-read their intervals.

## Feeds

Until the first add or delete in the console, feeds are reconciled from `config.json` as before. The first console change sets `feeds_source = console`; from then on the database is the list and the file's feeds are ignored, with a startup log line and a note on the Feeds page.

## Accounts

- Empty database: create `admin` / `admin` with `must_change_password = 1` and log a warning. If the bootstrap environment variables are set, use them instead (no forced change).
- While `must_change_password` is set, only `GET /api/v1/me`, `POST /api/v1/auth/logout`, and `POST /api/v1/account/password` are allowed. Everything else returns 403.
- Account page: change your own password (current password required, new one at least 8 characters). Other sessions of that user are ended.
- Users page (admin): list, add with a temporary password (forced change), reset to a temporary password (forced change, sessions ended), delete (not yourself, not the last admin).

## Logging

The Events page becomes Logs at `/logs`; `/events` redirects. Modes: `all` keeps every row; `blocked` keeps `BLOCKED` rows; `none` keeps no rows.

`query_counts(day, action, count)` is incremented for every query in every mode and holds no names or addresses. Overview totals and the block ratio come from it over the retention window. Top-name lists come from logged rows. Retention deletes old counter days too.

## Audit actions

`password_change`, `password_reset`, `user_create`, `user_delete`, `settings_update`, `feed_create`, `feed_delete`.

## Deliberate departures from the original specification

- Default `admin` / `admin` credentials, mitigated by the forced change.
- A local-path feed added in the console can point at any file the process can read; only accepted and rejected line counts are shown.
