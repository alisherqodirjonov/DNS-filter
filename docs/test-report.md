# Test report

Recorded on 15 November 2026, on this machine, with Go 1.27.4 (`GOTOOLCHAIN=local`). The suite uses a local stand-in resolver. It does not query public malicious names. The demonstration names are `example.com` and the `.test` names in `testdata/demo-blocklist.txt`.

## Commands

```text
$ go version
go version go1.27.4 linux/amd64

$ gofmt -l .
$ go vet ./...
$ go test -race ./... -count=1 -timeout 180s
?   	dnsfilter/cmd/dnsfilter	[no test files]
ok  	dnsfilter/internal/app	15.517s
ok  	dnsfilter/internal/auth	18.130s
ok  	dnsfilter/internal/config	1.084s
ok  	dnsfilter/internal/dnsserver	1.546s
?   	dnsfilter/internal/dnstest	[no test files]
ok  	dnsfilter/internal/feeds	1.363s
ok  	dnsfilter/internal/httpapi	14.559s
ok  	dnsfilter/internal/policy	1.068s
ok  	dnsfilter/internal/reporting	1.123s
ok  	dnsfilter/internal/store	1.269s
ok  	dnsfilter/internal/upstream	1.437s
?   	dnsfilter/migrations	[no test files]
?   	dnsfilter/web	[no test files]

$ go build -o dnsfilter ./cmd/dnsfilter
```

`gofmt -l` printed nothing. `go vet` printed nothing. The race detector reported no races. The build succeeded.

The end-to-end test in `internal/app` starts the real process against the stand-in resolver. It checks UDP and TCP allowed queries, a feed block that does not call upstream, a name that must not match by spelling, a truncated UDP answer retried over TCP, a garbage datagram that does not stop the server, an analyst forbidden from creating a rule, an admin allow rule that takes effect without a restart, and both the blocked and allowed events for that name.

## Live process

UDP port 5353 on this machine is already bound on `0.0.0.0`, so `config.example.json` cannot bind it here. The example file still uses `127.0.0.1:5353`, which is the right default on a machine where that port is free. The live check used `127.0.0.1:5354` for DNS and `127.0.0.1:8080` for the console, with a new SQLite file and upstream `1.1.1.1:53`.

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

Signed in through the browser as `admin` and as `analyst`.

- `/` redirected to the sign-in page, then to the overview after sign-in.
- The overview counts matched the log: 9 queries, 4 allowed, 5 blocked, block ratio 55.6%, 3 feed names. Later queries increased those counts.
- The events filter for `malware-demo.test` and Blocked returned only those rows, over UDP and TCP.
- Adding the deny rule for `lab-block.test` changed DNS behavior on the next query. Deleting it restored forwarding.
- Sync now reloaded `demo-local` and left the status at `ok` with 3 names.
- The audit log showed `login_success`, `rule_create`, and `feed_sync`. It did not show a password or a session token.
- The analyst could read the overview, events, rules, and feeds. Audit was hidden. The rules page had no add form, and the feeds page had no Sync button. Opening `/audit` directly showed “This action is limited to an administrator.”
- Signing out returned to the sign-in page.
- At a 390px width the console stacks into one column and does not scroll sideways.

Screenshots: `docs/screenshots/login.png`, `dashboard.png`, `events.png`, `rules.png`, `feeds.png`, `audit.png`.

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
