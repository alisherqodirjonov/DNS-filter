# Test report

First recorded on 15 November 2026 and brought up to date on 17 November 2026, after the console settings, Logs page, and accounts were added. Both runs were on this machine with Go 1.27.4 (`GOTOOLCHAIN=local`). The suite uses a local stand-in resolver. It does not query public malicious names. The demonstration names are `example.com`, `example.org`, `example.net`, and synthetic `.test` names.

## Commands

```text
$ go version
go version go1.27.4 linux/amd64

$ gofmt -l .
$ go vet ./...
$ go test -race ./... -count=1 -timeout 300s
?   	dnsfilter/cmd/dnsfilter	[no test files]
ok  	dnsfilter/internal/app	20.115s
ok  	dnsfilter/internal/auth	60.036s
ok  	dnsfilter/internal/config	1.180s
ok  	dnsfilter/internal/dnsserver	1.871s
?   	dnsfilter/internal/dnstest	[no test files]
ok  	dnsfilter/internal/feeds	1.960s
ok  	dnsfilter/internal/httpapi	74.071s
ok  	dnsfilter/internal/policy	1.128s
ok  	dnsfilter/internal/reporting	1.291s
ok  	dnsfilter/internal/settings	1.357s
ok  	dnsfilter/internal/store	2.440s
ok  	dnsfilter/internal/upstream	1.657s
?   	dnsfilter/migrations	[no test files]
?   	dnsfilter/web	[no test files]

$ go build -o dnsfilter ./cmd/dnsfilter
```

`gofmt -l` printed nothing. `go vet` printed nothing. The race detector reported no races. The build succeeded.

The end-to-end test in `internal/app` starts the real process against the stand-in resolver. It checks UDP and TCP allowed queries, a feed block that does not call upstream, a name that must not match by spelling, a truncated UDP answer retried over TCP, a garbage datagram that does not stop the server, an analyst forbidden from creating a rule, an admin allow rule that takes effect without a restart, and both the blocked and allowed events for that name. It then saves NXDOMAIN and the logging choice Nothing through the settings API: blocked queries answer `NXDOMAIN`, no rows are stored, and the overview total still rises. With Blocked only, only the blocked row is stored.

Other tests added with the console settings cover: upgrading a version 1 database, with daily counts filled from the existing rows; saved settings winning over the file and invalid saved values being ignored; a changed sync interval moving the next feed sync; the default administrator being limited to the password change; account creation, reset, and deletion rules, including the last administrator; and console feeds being added, synced, and removed.

## Live process

UDP port 5353 on this machine is bound on `0.0.0.0` by mDNS, so the example config has since moved to `127.0.0.1:5354`. The live check used `127.0.0.1:5354` for DNS and `127.0.0.1:8080` for the console, with a new SQLite file and upstream `1.1.1.1:53`.

First start, empty database:

```text
msg="configuration loaded" dns_udp=127.0.0.1:5354 dns_tcp=127.0.0.1:5354 upstream=1.1.1.1:53 http=127.0.0.1:8080 blocked_rcode=REFUSED
msg="database ready"
msg="created bootstrap user" username=admin role=admin
msg="created bootstrap user" username=analyst role=analyst
msg="dns listening" udp=127.0.0.1:5354 tcp=127.0.0.1:5354
msg="admin panel listening" addr=127.0.0.1:8080
```

The same binary, started again with the same database and the same bootstrap variables, did not create users again:

```text
msg="database ready"
msg="dns listening" udp=127.0.0.1:5354 tcp=127.0.0.1:5354
msg="admin panel listening" addr=127.0.0.1:8080
```

`GET /api/v1/health` returned `{"status":"ok"}`.

SQLite contained `users`, `sessions`, `rules`, `feeds`, `feed_domains`, `query_events`, `audit_events`, and `schema_migrations`. The two users are `admin` and `analyst`. Only bcrypt hashes are stored (60 characters). The feed `demo-local` loaded with status `ok`, 3 names, and 0 rejected lines.

## dig

Against the live filter on port 5354:

| Query | Result |
| --- | --- |
| `example.com` A, UDP | `NOERROR`, two A records, flags `qr ra ad` |
| `example.com` A, TCP | `NOERROR`, two A records |
| `malware-demo.test` A, UDP and TCP | `REFUSED`, empty answer, flags `qr rd ra` |
| `phishing-demo.test` A | `REFUSED` |
| `c2-demo.test` A | `REFUSED` |
| `notmalware-demo.test` A | `NXDOMAIN` from upstream (forwarded) |
| `lab-block.test` after an exact deny rule was added in the console | `REFUSED`, without restarting |
| `www.lab-block.test` while that exact rule existed | `NXDOMAIN` (forwarded) |
| `lab-block.test` after the rule was deleted | `NXDOMAIN` (forwarded) |

After the second start, `malware-demo.test` was still `REFUSED` and `example.com` was still `NOERROR`.

## Console

Signed in through the browser as `admin` and as `analyst`. This check predates the Logs and Settings pages, when the log page was called Events.

- `/` redirected to the sign-in page, then to the overview after sign-in.
- The overview counts matched the log: 9 queries, 4 allowed, 5 blocked, block ratio 55.6%, 3 feed names. Later queries increased those counts.
- The log filter for `malware-demo.test` and Blocked returned only those rows, over UDP and TCP.
- Adding the deny rule for `lab-block.test` changed DNS behavior on the next query. Deleting it restored forwarding.
- Sync now reloaded `demo-local` and left the status at `ok` with 3 names.
- The audit log showed `login_success`, `rule_create`, and `feed_sync`. It did not show a password or a session token.
- The analyst could read the overview, events, rules, and feeds. Audit was hidden. The rules page had no add form, and the feeds page had no Sync button. Opening `/audit` directly showed “This action is limited to an administrator.”
- Signing out returned to the sign-in page.
- On a narrow window the sidebar becomes a top bar and the overview panels stack into one column. Wide tables scroll inside their own box.

## Console settings, logs, and accounts

Checked on 17 November 2026 against two live processes on loopback (console on 8081 and 8082, DNS on 5354 and 5355, upstream `1.1.1.1:53`).

- An empty database logged `created the default administrator; sign in as admin with password admin and choose a new password`. Signing in as `admin`/`admin` opened Account with the navigation hidden. `/dashboard` and the other API routes returned to Account until a new password was set. Mismatched new passwords were caught on the form.
- Settings showed every value as “From config.json”. An upstream of `1.1.1.1` without a port was rejected with `Upstream resolver "1.1.1.1" must be host:port.` and the field was marked. NXDOMAIN was saved, and the next `dig` for `phishing-demo.test` answered `NXDOMAIN` with no restart. Saving with no change said “Nothing changed.”
- On Logs, Blocked only was saved. Two `dig` queries, one allowed and one blocked, raised the overview total by two and stored one row.
- Users: an analyst was added with a temporary password, reset, then signed in, was sent to Account, and chose a password. The analyst saw the logging choice and settings as disabled controls, with no Users or Audit pages. `PUT /api/v1/settings`, `GET /api/v1/users`, and `POST /api/v1/feeds` returned 403 for the analyst. Deleting the analyst asked for confirmation and removed the row.
- Feeds: adding `/tmp/dnsfilter-ui/extra.txt` loaded 2 names and blocked `tracker-demo.test` at once, and the page said the list is now managed in the console. Removing `demo-local` asked for confirmation; `malware-demo.test` was then counted as allowed and forwarded.
- After a restart the console feed list, NXDOMAIN, and Blocked only were all still in effect, and the process log said `console settings in effect ... feeds_from=console` and that the feeds in the config file are not applied.
- Audit listed each step in plain words: changed their password, changed settings (Logging, Blocked answer), added and reset an account, added and removed a feed, deleted an account.
- At 390 pixels wide, no page scrolls sideways.

Screenshots: `docs/screenshots/login.png`, `account-first-sign-in.png`, `dashboard.png`, `logs.png`, `logs-narrow.png`, `rules.png`, `feeds.png`, `settings.png`, `users.png`, `audit.png`.

## Packet capture

`tcpdump -i lo` failed with `You don't have permission to perform this capture on that device (socket: Operation not permitted)`. The `dig` headers above are the packet-level evidence available on this machine: allowed answers carry upstream flags and addresses, and blocked answers are `REFUSED` with an empty answer section.

## Security checks covered by the suite

- No password is written to the log, including a rejected password.
- Session tokens are stored as SHA-256 only, and the raw token is not returned after login except as the cookie.
- Mutating routes require an administrator, a CSRF header, and a matching `Origin` when the browser sends one.
- SQL is parameterized. Page size above 100 is rejected.
- The console assets do not use `innerHTML` and do not load a remote script or stylesheet.
- Feed downloads are bounded to 10 MiB and 30 seconds, refuse plain HTTP, and refuse a redirect off HTTPS.
- A failed feed sync does not replace the last good list.
- A failed DNS bind stops the background workers before the database is closed.
