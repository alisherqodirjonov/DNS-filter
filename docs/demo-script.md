# Demonstration script

About four minutes. Use a machine where you can run the filter and `dig` against it. The names below are synthetic `.test` names plus `example.com`. Do not substitute a real malicious domain.

## Before you start

```sh
go build -o dnsfilter ./cmd/dnsfilter
cp config.example.json config.json
export DNSFILTER_BOOTSTRAP_ADMIN_USER=admin
export DNSFILTER_BOOTSTRAP_ADMIN_PASSWORD='lab-admin-pass'
export DNSFILTER_BOOTSTRAP_ANALYST_USER=analyst
export DNSFILTER_BOOTSTRAP_ANALYST_PASSWORD='lab-analyst-pass'
./dnsfilter -config config.json
```

If port 5353 is already in use, change `listen_udp` and `listen_tcp` together, for example to `127.0.0.1:5354`, and use that port in the `dig` commands. Leave the console on `127.0.0.1:8080`.

These passwords are for a lab database. Choose different ones if anyone else can reach the console.

## 0:00 — What this is

Say that the filter sits in front of a normal resolver. Clients send DNS here. Names on the demo list are refused and are not forwarded. Other names go upstream, and both outcomes are written to the log.

The log line `admin panel listening` means the console is up. The demo feed has already loaded `malware-demo.test`, `phishing-demo.test`, and `c2-demo.test`.

## 0:30 — Sign in

Open <http://127.0.0.1:8080> and sign in as `admin`. The overview is empty until the first queries, or it shows whatever this database has already recorded.

## 1:00 — An allowed query

```sh
dig @127.0.0.1 -p 5353 example.com A
```

Point at `NOERROR` and the address records. Refresh the overview. The query is Allowed, the response is `NOERROR`, and the match column is empty because no rule applied.

Repeat over TCP so the TCP listener is visible:

```sh
dig @127.0.0.1 -p 5353 example.com A +tcp
```

## 1:40 — A blocked query

```sh
dig @127.0.0.1 -p 5353 malware-demo.test A
dig @127.0.0.1 -p 5353 phishing-demo.test A
```

Both answers are `REFUSED` with an empty answer section. On the Events page, filter the name to `malware-demo.test` and the action to Blocked. The match column names the feed, `demo-local`.

Then show the label boundary:

```sh
dig @127.0.0.1 -p 5353 notmalware-demo.test A
```

That name is not on the list. It is forwarded. Upstream will usually answer `NXDOMAIN`, and the event is Allowed.

## 2:30 — A rule, without restarting

On Rules, add a deny rule for `lab-block.test`, exact match, with a short note. Then:

```sh
dig @127.0.0.1 -p 5353 lab-block.test A
dig @127.0.0.1 -p 5353 www.lab-block.test A
```

The exact name is `REFUSED` immediately. The subdomain is still forwarded, because the rule is exact. Say that a suffix rule would have covered the subdomain, and that an allow rule would forward a name even when a feed lists it.

Delete the rule from the same page. Query `lab-block.test` again and show that it is forwarded.

## 3:20 — Feeds and the audit log

Open Feeds. The demo source shows three names and status `ok`. Click Sync now. The timestamp changes and the three names remain.

Open Audit. The rows are the sign-in, the rule, and the sync. No password and no session token appear there.

## 3:50 — The analyst

Sign out. Sign in as `analyst`. Overview, Events, Rules, and Feeds are readable. Rules has no add form, Feeds has no Sync button, and Audit is not in the navigation. The process is still the same DNS listener; signing in does not reload policy.

Stop the filter with Ctrl+C. It closes the console, then the DNS listeners, and leaves the SQLite file in `data/` for the next start.
