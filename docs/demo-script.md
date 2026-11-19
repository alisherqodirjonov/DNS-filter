# Demonstration script

About six minutes. Use a machine where you can run the filter and `dig` against it. The names below are synthetic `.test` names plus `example.com`. Do not substitute a real malicious domain.

## Before you start

Start from an empty database so the first sign-in can be shown.

```sh
rm -rf data
make run
```

If `config.json` does not exist yet, the first run writes it from `config.example.json`. If startup says a port is already in use, change that port in `config.json` and use the new DNS port in the `dig` commands.

## 0:00 — What this is

Say that the filter sits in front of a normal resolver. Clients send DNS here. Names on the demo list are blocked and are not forwarded. Other names go upstream. Every query is counted, and the query log keeps what the operator chooses.

The log line `admin panel listening` means the console is up. Point at the warning just above it: the database was empty, so the filter created `admin` with the password `admin`. The demo feed has already loaded `malware-demo.test`, `phishing-demo.test`, and `c2-demo.test`.

## 0:30 — First sign-in

Open <http://127.0.0.1:8080> and sign in as `admin` with `admin`. The console opens on Account with only that page available: the default password has to be replaced first. Choose `lab-admin-pass`. The overview and the full navigation appear.

## 1:00 — An allowed query

```sh
dig @127.0.0.1 -p 5354 example.com A
```

Point at `NOERROR` and the address records. Refresh the overview. The query is Allowed, the response is `NOERROR`, and the match column is empty because no rule applied.

Repeat over TCP so the TCP listener is visible:

```sh
dig @127.0.0.1 -p 5354 example.com A +tcp
```

## 1:40 — A blocked query

```sh
dig @127.0.0.1 -p 5354 malware-demo.test A
dig @127.0.0.1 -p 5354 phishing-demo.test A
```

Both answers are `REFUSED` with an empty answer section. On the Logs page, filter the name to `malware-demo.test` and the decision to Blocked. The match column names the feed, `demo-local`.

Then show the label boundary:

```sh
dig @127.0.0.1 -p 5354 notmalware-demo.test A
```

That name is not on the list. It is forwarded. Upstream will usually answer `NXDOMAIN`, and the row is Allowed.

## 2:20 — The blocked answer, without restarting

Open Settings. Each field says it comes from `config.json`. Change Blocked answer to NXDOMAIN and save. The field now says who set it and when, and what the file has.

```sh
dig @127.0.0.1 -p 5354 malware-demo.test A
```

The answer is `NXDOMAIN` straight away. Set it back to REFUSED if you prefer.

## 2:50 — What gets logged

On Logs, choose Blocked only. Then:

```sh
dig @127.0.0.1 -p 5354 example.com A
dig @127.0.0.1 -p 5354 c2-demo.test A
```

Only the `c2-demo.test` row appears in the log, but the overview's query count rose by two. Say that the counts never hold names or addresses, so Nothing still leaves an accurate overview. Choose All queries again.

## 3:30 — A rule

On Rules, add a deny rule for `lab-block.test`, exact match, with a short note. Then:

```sh
dig @127.0.0.1 -p 5354 lab-block.test A
dig @127.0.0.1 -p 5354 www.lab-block.test A
```

The exact name is blocked immediately. The subdomain is still forwarded, because the rule is exact. Say that a suffix rule would have covered the subdomain, and that an allow rule would forward a name even when a feed lists it.

Delete the rule from the same page.

## 4:10 — Feeds

Open Feeds. The demo source shows three names and status `ok`. Click Sync now. The timestamp changes and the three names remain.

Say that a feed can be added here from an absolute file path or an `https` address, and that doing so moves the feed list from `config.json` to the console. Skip it if the demo should keep following the file.

## 4:40 — An analyst account

Open Users and add `analyst` with the role Analyst and a temporary password such as `analyst-temp-pass`. The row says Temporary.

Open Audit. The rows are the password change, the settings, the rule, the sync, and the new account. No password and no session token appear there.

Sign out and sign in as `analyst`. Account asks for a new password first. After that, Overview, Logs, Rules, Feeds, and Settings are readable, with every control disabled or absent. Users and Audit are not in the navigation. The process is still the same DNS listener; signing in does not reload policy.

Stop the filter with Ctrl+C. It closes the console, then the DNS listeners, and leaves the SQLite file in `data/` for the next start, including the console settings.
