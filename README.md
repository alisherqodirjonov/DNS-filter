# DNS Filter

DNS Filter is a protective DNS forwarder for a lab. One Go process receives queries, refuses names that match a manual rule or a threat feed, and forwards everything else to an upstream resolver. It records each query in SQLite and serves a small console for the people operating it.

It is not a recursive resolver, and it does not cache answers. It does not speak DNS over HTTPS, TLS, or QUIC, and it does not intercept traffic on the path. Clients are pointed at it, or a lab resolver forwards to it.

The demonstration blocklist uses only names under the reserved `.test` domain. `example.com` is the name used to show an allowed query. Do not add real malicious domains to the demo list, and do not look those names up while trying the filter.

## Architecture

```
                 UDP/TCP DNS                         UDP, then TCP if truncated
 test client  ----------------->  dnsfilter  ------------------------------>  upstream resolver
                                       |  |
                                       |  +-- policy snapshot (allow, deny, feeds)
                                       |
                                       +-- SQLite: events, rules, feeds, users, audit
                                       |
 operator browser  -- HTTP on loopback --> console (embedded HTML, CSS, and JS)
```

A query is decided in this order:

1. Manual allow, exact name.
2. Manual allow, name and subdomains.
3. Manual deny, exact name.
4. Manual deny, name and subdomains.
5. Feed name, including subdomains.
6. Otherwise the query is forwarded.

A suffix matches on a label boundary. `example.test` matches `example.test` and `a.example.test`. It does not match `notexample.test`. The longest matching suffix wins. If two feeds list the same name, the first feed in configuration order is the one recorded.

Names that are not valid DNS names are not compared with the blocklist. The filter answers `FORMERR` and logs the query as `ERROR`.

## What you need

Go 1.26 or newer. The SQLite driver in this module, `modernc.org/sqlite` v1.62, does not build with older toolchains. The commands below were run with Go 1.27.4.

`dig` is useful for the demonstration. The console is served by the filter itself. There is no Node.js step and no separate database server.

## Build

From the project directory:

```sh
go build -o dnsfilter ./cmd/dnsfilter
```

## Configuration

```sh
cp config.example.json config.json
```

`config.example.json` listens for DNS on `127.0.0.1:5353`, forwards to `1.1.1.1:53`, answers blocked names with `REFUSED`, and serves the console on `127.0.0.1:8080`. The database file is `./data/dnsfilter.db`. The demo feed is `./testdata/demo-blocklist.txt`.

Paths in the file are resolved from the directory that contains the config file. They are not resolved from the shell’s current directory. A feed is either a local `path` or an `https` URL, not both, and not plain HTTP. Feed names are a short token such as `demo-local`. The format is `domains` (one name per line) or `hosts` (`0.0.0.0 name` or `127.0.0.1 name`).

`upstream_timeout_seconds` is 1 to 30. `logging.retention_days` is 1 to 3650. `feeds.sync_interval_hours` is 1 to 720. `blocked_rcode` is `REFUSED`, `SERVFAIL`, or `NXDOMAIN`.

## First start

Accounts are created only when the database has no users. Set the environment for that first start. Passwords must be at least 8 characters. The analyst pair is optional; set both variables or neither.

```sh
export DNSFILTER_BOOTSTRAP_ADMIN_USER=admin
export DNSFILTER_BOOTSTRAP_ADMIN_PASSWORD='choose-a-password'
export DNSFILTER_BOOTSTRAP_ANALYST_USER=analyst
export DNSFILTER_BOOTSTRAP_ANALYST_PASSWORD='choose-another-password'
./dnsfilter -config config.json
```

A later start ignores these variables. Passwords are stored as bcrypt hashes. The process log records the username and role, not the password. If the admin variables are missing on an empty database, the process exits and says which variable to set.

## Run it locally

`127.0.0.1:5353` does not need extra privileges. Leave the console on `127.0.0.1:8080`.

On some machines UDP port 5353 is already taken, often by mDNS. If startup reports `address already in use`, choose another loopback port and set both `listen_udp` and `listen_tcp` to it, for example `127.0.0.1:5354`.

Open the console at <http://127.0.0.1:8080>. An administrator can add and delete rules and can refresh a feed. An analyst can read the overview, events, rules, and feeds. The audit log and every change are limited to an administrator. Signing out clears the session cookie.

## Run it on port 53

Use port 53 only on an isolated lab network. Grant the binary permission to bind that port, then change the listen addresses in `config.json`. Keep the console on loopback unless the lab explicitly needs it elsewhere. If the console is not on loopback, the process logs a warning.

```sh
sudo setcap cap_net_bind_service=+ep ./dnsfilter
```

Point the test client’s DNS server at the lab address of this machine. A system resolver always uses port 53, so a filter on port 5353 is queried with `dig` rather than by changing the whole computer’s DNS.

## Queries to try

Allowed name, UDP:

```sh
dig @127.0.0.1 -p 5353 example.com A
```

The status is `NOERROR` and the answer comes from upstream.

The same query over TCP:

```sh
dig @127.0.0.1 -p 5353 example.com A +tcp
```

A name on the demo feed:

```sh
dig @127.0.0.1 -p 5353 malware-demo.test A
```

The status is `REFUSED`, the answer section is empty, and the filter does not ask upstream. `phishing-demo.test` and `c2-demo.test` behave the same way. A name that only shares a suffix by spelling, such as `notmalware-demo.test`, is forwarded.

If upstream does not answer before `upstream_timeout_seconds`, the filter returns `SERVFAIL` and logs the query as `ERROR`. If the upstream UDP answer is truncated, the filter retries that query over TCP and returns the TCP answer.

## Console pages

| Page | What it shows |
| --- | --- |
| Overview | Counts, block ratio, top blocked names and clients, recent queries |
| Events | The query log, filtered by name and by allowed, blocked, or error |
| Rules | Manual allow and deny rules |
| Feeds | Configured feeds, how many names loaded, and the last sync |
| Audit | Sign-ins, rule changes, and feed syncs |

Screenshots from a local run are in `docs/screenshots/`. A timed walk-through is in `docs/demo-script.md`.

## What is stored for a query

The action is `ALLOWED`, `BLOCKED`, or `ERROR`. There is no separate action for an allow exception. When an allow rule is the reason a name was forwarded, the row is `ALLOWED` with match source `manual` and the rule’s domain in the match column. A normal forward leaves the match empty. A manual deny uses match source `manual`. A feed block uses the feed’s name as the source and the feed’s domain, which may be a parent of the name that was queried.

The block ratio on the overview is blocked queries divided by all queries still inside the retention window, shown to one decimal place.

## Feeds

Blank lines and lines that start with `#` are ignored. In `hosts` files, a `#` comment may follow the name. A line that does not match the format is counted as rejected. If a sync finds no valid names and at least one rejected line, the previous list stays in place and the feed status becomes `error`. An empty file, or a file that is only comments, replaces the list with nothing. A missing file, a body over 10 MiB, a non-HTTPS URL, or an HTTP error does the same: the last good list remains.

The console’s Sync button reloads that feed’s configured source. It does not accept an arbitrary URL. Feeds are fetched again on the configured interval. The first sync runs at startup and does not stop the process if it fails.

## Sessions, cookies, and limits

A session lasts 12 hours. The cookie is `dnsfilter_session`. It is `HttpOnly`, `SameSite=Strict`, and `Secure` when the console itself is served over HTTPS. The browser sends `X-CSRF-Token` on any request that changes state. If the request includes an `Origin` header, that origin must match the console’s host.

Five failed sign-ins from the same client address within 10 minutes are rejected until the window passes. The limit uses the connection address, not `X-Forwarded-For`.

The events and audit APIs accept a page size from 1 to 100. A larger `limit` is rejected. Query rows older than `logging.retention_days` are deleted at startup and then once an hour. Expired sessions are deleted every 10 minutes.

## Tests

```sh
gofmt -w .
go vet ./...
go test -race ./...
go build -o dnsfilter ./cmd/dnsfilter
```

DNS tests use a local stand-in resolver. They do not query public malicious names. The command output from the verification run is in `docs/test-report.md`.

## Project layout

```
cmd/dnsfilter          process entrypoint
internal/config        JSON configuration
internal/store         SQLite and migrations
internal/policy        normalization and the decision order
internal/upstream      UDP query, TCP retry when truncated
internal/dnsserver     UDP and TCP listeners
internal/feeds         feed files and HTTPS downloads
internal/auth          passwords, sessions, roles
internal/httpapi       JSON API and console pages
internal/reporting     overview queries
internal/app           startup and shutdown
web                    HTML, CSS, and JS embedded in the binary
testdata               the .test demonstration list
```

## Left for later

Transparent redirection, encrypted DNS, a recursive resolver, a cache, detection models, SIEM or metrics export, containers, and a block page are out of scope for this version. They need their own plan. The filter’s job here is to refuse the configured names, forward the rest, and show what it did.
