# TECHNICAL SPECIFICATION (TS)

## DNS Filter MVP — Protective DNS Filter for an Educational Lab

**Version:** 1.0  
**Date:** November 15, 2026  
**Purpose:** Cybersecurity coursework project  
**Implementation Timeline:** 7–14 calendar days  
**Primary Language:** Go  
**Product Type:** A single Go service (single executable binary) with a DNS forwarding plane, HTTP API, and a lightweight web panel.

---

## 1. Project Goal

Develop a lightweight DNS filter that accepts DNS queries from devices in an internal test network, checks the requested domain name against local rules and downloaded threat-intelligence feeds, blocks matches, and forwards allowed queries to an upstream DNS resolver.

The service must log DNS query events, display statistics, and provide a simple management panel with authentication and role-based access control.

The project is intended to demonstrate the **Protective DNS** principle. This is an educational MVP, not a production-grade NGFW or enterprise DNS security appliance.

### 1.1. Primary User Scenario

1. A test network client uses DNS Filter as its DNS server.
2. The client sends a standard DNS query over UDP or TCP to port 53 of DNS Filter.
3. The filter normalizes the requested domain name.
4. The filter checks the name against the allowlist, manual deny rules, and loaded threat-intelligence feeds.
5. If the domain is allowed, the query is forwarded to the configured upstream DNS resolver.
6. If the domain is blocked, the filter returns a `REFUSED` DNS response and does not send the query upstream.
7. The result is recorded in the event log.
8. An administrator opens the web panel to view statistics, events, rules, and feed statuses.

### 1.2. Project Success Criteria

During the demonstration, it must be evident that the same DNS service:

- successfully resolves normal allowed domains via upstream;
- blocks domains from the local test list and threat feed;
- does not send blocked queries upstream;
- logs both allowed and blocked queries;
- allows an administrator to modify rules via the web panel;
- prevents a user with the `analyst` role from modifying settings or rules.

---

## 2. Project Scope and Architectural Decisions

### 2.1. Mandatory Operating Model: Forwarding DNS Resolver

The MVP is implemented as a **forwarding DNS resolver**. Clients are explicitly configured to use the DNS Filter's address. The service itself does not perform recursive traversal of the DNS hierarchy: allowed queries are forwarded to a single configured upstream resolver, such as `1.1.1.1:53`.

This is a deliberate architectural choice: it allows focusing on DNS filtering, threat intelligence, logging, and management without implementing a full recursive DNS resolver.

### 2.2. Out of Scope for MVP

The following features are prohibited from being quietly added to the core scope. They may be described in the Future Work section, but must not be implemented until all mandatory requirements are completed:

- transparent inline DNS interception / NAT redirect;
- spoofing responses on behalf of a public resolver, such as `1.1.1.1`;
- full recursive DNS resolver;
- built-in DNS cache;
- DNS-over-HTTPS (DoH), DNS-over-TLS (DoT), or DNS-over-QUIC (DoQ) server or proxy;
- active downgrade of encrypted DNS, TLS interception, or MITM;
- DPI, TLS decryption, or packet inspection outside of DNS;
- ML models, DGA detection, or DNS tunneling detection;
- Kubernetes, microservice architecture, Redis, Kafka, Elasticsearch, or Prometheus/Grafana;
- multi-tenant SaaS, HA cluster, or distributed database;
- automatic modification of firewall/router configurations;
- full SIEM integration.

**Important:** The service filters DNS queries that are actually directed to it. If a client independently uses a third-party DoH/DoT/DoQ resolver, this MVP will not be able to inspect domain names inside the encrypted connection. The project must not attempt to decrypt or downgrade the security of such connections.

---

## 3. Architecture

### 3.1. Logical Architecture

The application must be a single Go process with logically separated packages:

```text
                         TEST CLIENTS
                    (Linux / Windows / VM)
                              |
                       UDP/TCP port 53
                              |
                              v
+--------------------------------------------------------------+
|                         DNS FILTER                            |
|                                                              |
|  +----------------------- DATA PLANE ----------------------+  |
|  | DNS UDP Listener | DNS TCP Listener | Query Handler     |  |
|  |                         |                                |  |
|  |             Domain Normalization                         |  |
|  |                         |                                |  |
|  |                  Policy Engine                           |  |
|  |             /        |          \                        |  |
|  |          Allow     Manual       Threat Feed              |  |
|  |          Rules     Deny Rules   Domains                   |  |
|  |             \        |          /                        |  |
|  |               Forward / Block                           |  |
|  |                         |                                |  |
|  |                 Upstream DNS Client                       |  |
|  +----------------------------------------------------------+  |
|                              |                               |
|  +----------------------- CONTROL PLANE -------------------+  |
|  | HTTP API | Authentication | RBAC | Feed Sync | Reports   |  |
|  +----------------------------------------------------------+  |
|                              |                               |
|  +----------------------- MANAGEMENT UI ------------------+  |
|  | Embedded HTML | CSS | Vanilla JavaScript                 |  |
|  +----------------------------------------------------------+  |
|                              |                               |
|  +----------------------- STORAGE -------------------------+  |
|  | SQLite: users, sessions, rules, feeds, events, audit     |  |
|  +----------------------------------------------------------+  |
+--------------------------------------------------------------+
|                         |                                    |
|                    Upstream DNS                              |
+------------------------|-------------------------------------+
                         v
                  1.1.1.1:53 (example)
```

These are not three separate products or processes. The data plane, control plane, and management UI are logical components of a single application to keep building and deployment simple.

### 3.2. Deployment Topology

Recommended lab layout:

```text
+----------------+        +---------------------+        +------------------+
| Client VM      |------->| DNS Filter VM       |------->| Upstream Resolver|
| 192.168.56.10  | DNS    | 192.168.56.20       | DNS    | 1.1.1.1:53       |
|                | :53    | DNS :53             |        |                  |
+----------------+        | Admin UI :8080      |        +------------------+
                          +---------------------+
```

The client is configured manually or via DHCP to use the DNS Filter's IP address. For local development, it can listen on `127.0.0.1:5353` to avoid requiring a privileged port. For the lab network, once verified, the service must be able to listen on `0.0.0.0:53` or a specific interface IP.

**Do not implement transparent interception of third-party DNS queries.** The term "inline" is not used as a requirement in this TS: the chosen model is a DNS forwarder explicitly assigned to clients.

### 3.3. DNS Query Processing

The processing order must be as follows:

1. Receive a DNS message over UDP or TCP.
2. Verify that the query contains a single Question and uses the supported `QUERY` opcode. Handle malformed messages with a proper DNS error response without panicking.
3. Extract `QNAME`, `QTYPE`, `QCLASS`, and the transport protocol.
4. Normalize the domain name: strip the trailing dot for internal comparison, convert to lowercase, and perform IDNA-to-ASCII conversion. For unsupported/malformed names, do not perform blocking comparison; handle the query gracefully according to the implementation and tests.
5. Perform an allowlist check.
6. If the allowlist matches, forward the query upstream, even if there is a match in deny rules or feeds. This administrative exception must be logged as `ALLOW_RULE`.
7. If the allowlist does not match, check manual deny rules.
8. Next, check threat-intelligence feed domains.
9. On a match, return `REFUSED` without contacting the upstream resolver.
10. If there are no matches, forward the original DNS message upstream.
11. If the upstream resolver does not respond within the configured timeout, return `SERVFAIL` to the client.
12. Log the event along with the processing outcome.

### 3.4. Domain Matching

Two match types must be supported:

- `exact`: blocks or allows only the exact specified name;
- `suffix`: a rule for a domain also applies to all of its subdomains.

Matching must respect DNS label boundaries. For example, a `suffix` rule for `example.com` matches `a.example.com`, but does not match `notexample.com`.

Feed entries are treated as `suffix` rules by default. Manual allow/deny rules allow selecting either `exact` or `suffix`.

Policy precedence:

1. allowlist;
2. manual deny rules;
3. threat-intelligence feed rules;
4. upstream forwarding.

When a feed matches, the event must record the feed name and the matched domain. When a manual rule matches, it must record the rule ID or domain.

### 3.5. Upstream DNS

- Default upstream: `1.1.1.1:53`, configurable via the config file.
- The MVP uses standard DNS over UDP to the upstream resolver.
- If a query arrives over TCP, the service may still send it upstream over UDP; if `TC=1` (truncated) is received from upstream, the query must be retried over TCP.
- If a query is sent over UDP and upstream returns `TC=1`, retry the upstream query over TCP before sending the response to the client.
- Default upstream timeout: 3 seconds.
- Do not modify the DNS transaction ID or Question unnecessarily. Use the capabilities of the `miekg/dns` client/server.
- Preserve proper handling of EDNS0 and DNSSEC-related request flags for queries forwarded upstream.
- Do not implement a built-in DNS cache in the MVP.
- On upstream failure, return `SERVFAIL`; do not hang or substitute the error with a fabricated answer.

The `miekg/dns` library provides UDP/TCP DNS server/client APIs, EDNS0, and DNSSEC-related functions. However, its `Client.Exchange` does not automatically perform a TCP retry after a truncated UDP response—this behavior must be implemented explicitly and covered by a test.

### 3.6. Blocking Behavior

For a blocked query, return a DNS response with RCODE `REFUSED`.

Rationale: this explicitly informs the client that the DNS server refused to process the query. In the MVP, there is no need to generate fake A/AAAA records or an HTTP block page.

Requirements for a blocked response:

- Question matches the original query;
- RCODE is `REFUSED`;
- the response contains no upstream answer;
- upstream is not queried;
- the event is logged with `action=BLOCKED` and `rcode=REFUSED`.

---

## 4. Technology Stack

### 4.1. Recommended Stack

| Area | Choice | Rationale |
|---|---|---|
| Primary Language | Go | Single binary executable, concurrent query handling, simple deployment |
| DNS Protocol | `github.com/miekg/dns` | Ready-to-use DNS messages, UDP/TCP server/client, EDNS0, DNSSEC-related support |
| HTTP/API | Go standard library `net/http` | No need to introduce a separate web framework |
| HTML Templates | `html/template` | Server-side output escaping |
| Frontend | HTML + CSS + Vanilla JavaScript | Lightweight panel without React/Vue/npm build chains |
| Static Assets | `embed` + `embed.FS` | CSS/JS/templates can be embedded directly into the binary |
| Database | SQLite | Single-file storage ideal for an educational MVP |
| SQLite Driver | `modernc.org/sqlite` | Pure Go, does not require CGO |
| Password Hashing | `golang.org/x/crypto/bcrypt` | Passwords are never stored in plaintext |
| Domain Normalization | `golang.org/x/net/idna` | Normalizes IDN domains into ASCII representation |
| Configuration | JSON config file | Simple structure supported by the standard library |
| Logging | `log/slog` | Structured application logs |
| Tests | `testing`, `httptest`, test DNS server | Built-in Go testing tools |
| Packaging | `go build` | Compiles into a single executable binary |

Do not add extra libraries without a genuine necessity. Do not use Gin, Fiber, React, Node.js, Redis, or PostgreSQL in the MVP.

### 4.2. Why Not Use a Ready-Made DNS Firewall Out of the Box

CoreDNS, Unbound, dnsmasq, AdGuard Home, and Technitium DNS Server are capable off-the-shelf solutions, but this project must demonstrate the implementation of a custom DNS filtering flow, policy engine, feed ingestion, event logging, and lightweight control plane. Therefore, building a custom Go forwarder using `miekg/dns` aligns better with the educational objective.

### 4.3. Storage

SQLite is the sole database for the MVP. Do not use a separate database server.

Recommended tables:

- `users` — username, password hash, role, created_at;
- `sessions` — session token hash, user_id, expiry;
- `rules` — domain, rule type (`allow`/`deny`), match type (`exact`/`suffix`), description, created_by, created_at;
- `feeds` — source name, URL/path from config, status, last_sync_at, last_error, domains_count;
- `feed_domains` — feed_id, normalized_domain;
- `query_events` — timestamp, client_ip, qname, qtype, transport, action, rcode, upstream_latency_ms, matched_source, matched_domain;
- `audit_events` — timestamp, username, action, object_type, object_id, result.

Configure foreign keys and a busy timeout. SQLite is sufficient for a small educational workload. Do not store full raw DNS response payloads.

---

## 5. Threat Intelligence Feed

### 5.1. MVP Requirements

Implement a simple feed loader capable of:

- downloading a feed from an HTTPS URL pre-configured by the administrator in `config.json`;
- supporting the `domains` format: one domain per line;
- supporting the `hosts` format: `0.0.0.0 domain` or `127.0.0.1 domain`;
- ignoring blank lines and comments starting with `#`;
- normalizing domain names;
- rejecting malformed lines and counting them separately;
- limiting the downloaded response size (e.g., 10 MB);
- enforcing an HTTP timeout;
- loading data transactionally: a new feed version replaces the old one only after successful download and parsing;
- retaining the last successfully loaded version if an error occurs;
- storing the last sync timestamp, entry count, and any error message;
- providing a manual sync trigger from the UI/API;
- performing automatic synchronization at startup and periodically thereafter (default interval: 24 hours).

Feed URLs are defined via the configuration file rather than arbitrary URLs submitted from a browser. This reduces the SSRF attack surface and simplifies the MVP. The UI only displays configured sources and allows triggering synchronization for them.

Do not implement Adblock syntax, wildcard expressions, URL parsing, IP reputation, ASN feeds, STIX/TAXII, or complex API integrations in the first version.

### 5.2. Sources and Constraints

For the demonstration, you must use a custom local feed from `testdata/demo-blocklist.txt` containing domains from the reserved `.test` TLD. Real malicious domains must not be visited or used during the demonstration.

As an optional external source, HaGeZi Threat Intelligence Feeds may be considered. The HaGeZi repository specifies a GPL-3.0 license for its published lists, while upstream third-party sources included in them may have their own terms. Before redistributing any list or including it in a public release, verify the license of both the list itself and its upstream sources.

The ThreatFox Community API is a potential option for a future adapter: it requires an API key, operates under fair-use terms, and uses a custom JSON format. Do not include it in the mandatory MVP, as it would add a separate API schema, secret management, and IOC normalization.

Do not use generic URLhaus network feeds as a ready-made domain blocklist: the official URLhaus page explicitly warns that those feeds are not intended for direct blocking or IOC use. For future expansion, evaluate an appropriate dataset/API and its terms of use.

A feed is a source of threat signals, not absolute truth. Always display the origin of a block in the UI and logs. Do not claim that a domain's presence on a single list proves host compromise.

---

## 6. Control Plane and Management UI

### 6.1. General Requirements

- The HTTP server runs on a separate address/port, defaulting to `127.0.0.1:8080`.
- The UI is accessible via a web browser.
- The frontend uses only HTML, CSS, and Vanilla JavaScript.
- Both backend and frontend are served by the single Go process.
- Static assets are embedded into the binary via `embed`.
- The API returns JSON and uses a consistent error format.
- Do not enable CORS; the API is intended for the same-origin UI.

### 6.2. Authentication and RBAC

Support two roles:

**admin**
- view dashboard, DNS events, feeds, and audit events;
- create, modify, and delete manual allow/deny rules;
- manually trigger synchronization for configured feeds;
- view service status.

**analyst**
- view dashboard;
- view DNS events;
- view rules and feed statuses;
- cannot create, modify, or delete rules;
- cannot trigger feed sync;
- cannot modify configuration.

Public self-registration is not needed. Initial accounts are created via bootstrap environment variables on first startup if the `users` table is empty:

- `DNSFILTER_BOOTSTRAP_ADMIN_USER`
- `DNSFILTER_BOOTSTRAP_ADMIN_PASSWORD`
- optional: `DNSFILTER_BOOTSTRAP_ANALYST_USER`
- optional: `DNSFILTER_BOOTSTRAP_ANALYST_PASSWORD`

After initial account creation, credentials must never be displayed in the UI or logs. If bootstrap credentials are missing and the database is empty, the service must output clear setup instructions and exit with a configuration error.

Passwords are stored exclusively as bcrypt hashes. Use server-side sessions with a cryptographically random token. In the browser, the token is transmitted via a cookie with `HttpOnly`, `SameSite=Strict`, `Path=/`, and `Secure` when served over HTTPS. Store the hash of the session token in the database rather than the raw token itself. Implement session expiration and logout.

For state-changing requests, enforce CSRF protection: a CSRF token tied to the session state and passed via a custom request header, or an equivalent strict server-side `Origin`/`Host` check. Do not rely solely on client-side JavaScript role checks: all permissions must be enforced on the backend.

Rate-limit login attempts. Do not use hardcoded default credentials.

### 6.3. UI Pages

Minimum required pages:

1. **Login** — sign-in form.
2. **Dashboard** — total queries, blocked/allowed counts, block ratio, active feed domain count, recent events.
3. **DNS Events** — paginated event table with filters by domain and action.
4. **Rules** — view allow/deny rules; `admin` can add or delete rules.
5. **Threat Feeds** — list of configured feeds, status, last sync timestamp, domain count, and a "Sync Now" button for `admin`.

Do not build complex visualizations. Tables, counters, and simple summary cards are sufficient.

### 6.4. Minimum API Endpoints

All endpoints, except login and the minimal health-check, require an active authenticated session.

| Method | Path | Role | Purpose |
|---|---|---|---|
| `POST` | `/api/v1/auth/login` | Public | Log in |
| `POST` | `/api/v1/auth/logout` | Authenticated | Log out |
| `GET` | `/api/v1/me` | Authenticated | Current user, role, and CSRF token |
| `GET` | `/api/v1/health` | Public (minimal data) | Liveness status |
| `GET` | `/api/v1/dashboard/summary` | admin, analyst | Summary statistics |
| `GET` | `/api/v1/events` | admin, analyst | List DNS events with limit/offset/filter |
| `GET` | `/api/v1/rules` | admin, analyst | View rules |
| `POST` | `/api/v1/rules` | admin | Create a rule |
| `DELETE` | `/api/v1/rules/{id}` | admin | Delete a rule |
| `GET` | `/api/v1/feeds` | admin, analyst | Feed source statuses |
| `POST` | `/api/v1/feeds/{id}/sync` | admin | Trigger feed synchronization |
| `GET` | `/api/v1/audit` | admin | View administrative audit log |

Do not implement public API keys, OAuth, SSO, or complex user management systems.

### 6.5. Audit Logging

Log at least the following actions:

- successful and failed login attempts;
- logout;
- rule creation and deletion;
- manual feed synchronization;
- administrative operation errors.

Never log passwords, cookie values, session tokens, or API secrets.

---

## 7. Event Logging and Reporting

### 7.1. Minimum DNS Event Schema

| Field | Type / Example | Description |
|---|---|---|
| `id` | integer | Event ID |
| `timestamp` | UTC RFC3339 | Query timestamp |
| `client_ip` | string | Client IP extracted from the DNS connection remote address |
| `qname` | string | Normalized queried domain name |
| `qtype` | string | A, AAAA, MX, TXT, etc. |
| `transport` | `udp` / `tcp` | DNS transport used by the client |
| `action` | `ALLOWED` / `BLOCKED` / `ERROR` | Filter decision |
| `rcode` | `NOERROR`, `REFUSED`, `SERVFAIL`, etc. | DNS response code |
| `upstream_latency_ms` | integer / null | Upstream response latency, if upstream was queried |
| `matched_source` | `manual` / feed name / null | Source of the policy match |
| `matched_domain` | string / null | Rule or feed domain that triggered the match |

### 7.2. Dashboard Metrics

Display at minimum:

- total DNS queries;
- allowed queries;
- blocked queries;
- block ratio (%);
- top blocked domains;
- top clients by blocked query count;
- last feed sync time/status;
- current number of loaded feed domains.

Calculate statistics using SQL queries against SQLite. Do not add a separate time-series database.

### 7.3. Retention and Privacy

- Retain query events for 7 days by default.
- The retention interval must be configurable.
- Do not log full raw DNS packet payloads.
- Query event logs contain client IP addresses and queried domain names, and are therefore considered sensitive network telemetry.
- Restrict access to events via RBAC.
- State in the documentation that a dedicated test network is used for the university demonstration and participants are notified of logging.

SIEM export is not a mandatory feature. For the MVP, the JSON API and optional CSV/JSON download are sufficient. Generic syslog/webhook support is deferred to future work.

---

## 8. Configuration and Startup

### 8.1. Configuration Format

Use `config.json`. Include fields structured approximately as follows:

```json
{
  "dns": {
    "listen_udp": "127.0.0.1:5353",
    "listen_tcp": "127.0.0.1:5353",
    "upstream": "1.1.1.1:53",
    "upstream_timeout_seconds": 3,
    "blocked_rcode": "REFUSED"
  },
  "http": {
    "listen": "127.0.0.1:8080"
  },
  "database": {
    "path": "./data/dnsfilter.db"
  },
  "logging": {
    "retention_days": 7
  },
  "feeds": {
    "sync_interval_hours": 24,
    "sources": [
      {
        "name": "demo-local",
        "path": "./testdata/demo-blocklist.txt",
        "format": "domains"
      }
    ]
  }
}
```

Each feed source must specify exactly one origin: either a local `path` or an HTTPS `url`. Plain HTTP feeds must be rejected. Local paths must be resolved relative to the configuration file's directory or a clearly documented working directory.

Configuration is validated on startup. If a listen address, upstream address, feed format, or blocked RCODE is invalid, the service must output a clear error message and exit.

### 8.2. Ports

- DNS UDP: 53 for lab deployment; 5353 for local development.
- DNS TCP: 53 for lab deployment; 5353 for local development.
- Admin HTTP: 8080, bound to loopback by default.

On Linux, port 53 is a privileged port. For the demonstration, you may apply `setcap cap_net_bind_service=+ep` to the binary or use another restricted system mechanism. Do not run the entire application as `root` unnecessarily. When running on port `5353`, test using `dig @127.0.0.1 -p 5353 ...`.

The Admin UI must not be exposed to an untrusted network. Use an isolated lab network for network access; for non-lab deployment, an HTTPS reverse proxy is required.

---

## 9. Non-Functional Requirements

### 9.1. Reliability

- A failure in a single DNS handler goroutine must not crash the entire service.
- Malformed DNS packets or malformed feed lines must never cause panics.
- Upstream timeouts must be bounded.
- Feed updates must be atomic: a failed update must not delete last-known-good data.
- If the upstream resolver is unreachable, return `SERVFAIL` and log the event.
- If the service restarts, rules and events must persist in SQLite.

### 9.2. Performance

The MVP is not a high-performance DNS appliance. Target baseline for educational verification:

- 100 queries/sec in a local lab environment without panics or loss of functionality;
- local block decisions must not contact the upstream resolver;
- rule evaluation must use in-memory maps/sets and must not linearly scan all feed domains on every query.

Any reported performance measurement must state the test environment parameters (VM resources, rule count, client tool, test duration). Do not claim performance numbers without actual measurement.

### 9.3. Security

- All SQL queries must use parameterized statements.
- HTML templates must use `html/template` with safe context-aware escaping.
- All state-changing API endpoints must require the `admin` role.
- Passwords must be hashed with `bcrypt`.
- Session tokens must be generated via `crypto/rand`; only the token hash is stored in the DB.
- Never log credentials or secrets.
- Rate-limit login attempts.
- Enable CSRF protection for state-changing API requests.
- Do not enable permissive CORS.
- Embedded JS/CSS must be served locally without external CDNs.
- Feed URLs are defined in the config file, never accepted as arbitrary input from unauthenticated users.
- Enforce HTTP download timeouts and maximum feed body sizes.
- Perform feed updates transactionally.
- Enforce a reasonable maximum page size on the events API (e.g., 100).
- Bind the administrative interface to `127.0.0.1` by default.

---

## 10. Source Code Structure Requirements

Preferred minimal directory structure:

```text
dnsfilter/
├── cmd/
│   └── dnsfilter/
│       └── main.go
├── internal/
│   ├── config/
│   ├── dnsserver/
│   ├── policy/
│   ├── upstream/
│   ├── feeds/
│   ├── store/
│   ├── auth/
│   ├── httpapi/
│   └── reporting/
├── web/
│   ├── templates/
│   └── static/
│       ├── css/
│       └── js/
├── migrations/
├── testdata/
│   └── demo-blocklist.txt
├── docs/
├── config.example.json
├── go.mod
├── go.sum
└── README.md
```

Do not create a separate package for every minor helper function. Package boundaries should aid testability rather than inflate abstraction layers.

### 10.1. Component Responsibilities

- `config`: reading and validating the JSON configuration.
- `dnsserver`: UDP/TCP listeners, DNS request handler, response construction.
- `policy`: domain normalization and matching for allow/deny/feed rules.
- `upstream`: DNS forwarding, timeouts, UDP-to-TCP retry on truncation.
- `feeds`: downloading, parsing, validation, and atomic feed updates.
- `store`: SQLite migrations and data repositories.
- `auth`: password verification, sessions, CSRF, and RBAC middleware helpers.
- `httpapi`: REST API endpoints.
- `reporting`: summary queries for the dashboard.
- `web`: HTML templates and embedded CSS/JS assets.

---

## 11. Testing and Acceptance Criteria

All automated tests must run locally without requiring access to real malicious domains.

### 11.1. Unit Tests

Mandatory tests:

1. Domain normalization: uppercase, trailing dot, IDNA input.
2. Exact match: exact domain matches; a different hostname does not.
3. Suffix match: `a.example.test` matches `example.test`.
4. Boundary test: `notexample.test` does not match `example.test`.
5. Allowlist precedence: an allow rule permits a domain even if it exists in a feed.
6. Feed parser: plain domain, hosts-file line, comment, blank line, malformed line.
7. Block response: returns `REFUSED` and preserves the original Question.
8. Invalid DNS question: malformed or multi-question packet is handled gracefully.

### 11.2. DNS Integration Tests

Create a fake upstream DNS server inside Go tests. Do not use public DNS servers in integration tests.

Verify:

- allowed queries reach the fake upstream;
- upstream answers are returned to the client;
- blocked queries never reach upstream;
- UDP DNS works;
- TCP DNS works;
- upstream timeout results in `SERVFAIL`;
- truncated UDP upstream responses trigger a retry over TCP;
- the event log records the expected client, query, action, and RCODE.

### 11.3. API/UI Tests

- an invalid password does not create a session;
- a valid login creates a session;
- logout invalidates the session;
- `analyst` can read events and dashboard data;
- `analyst` receives `403 Forbidden` when attempting to modify rules or trigger feed sync;
- `admin` can create and delete rules;
- after a rule change, the DNS data plane applies it immediately without a restart;
- feed sync status is displayed accurately;
- a feed download failure preserves the last-known-good feed data.

### 11.4. Manual Demonstration

Use only benign test indicators:

- allowed domain: `example.com`;
- local blocked names: `malware-demo.test`, `phishing-demo.test`, `c2-demo.test`.

Example commands for local port 5353:

```bash
dig @127.0.0.1 -p 5353 example.com A
dig @127.0.0.1 -p 5353 malware-demo.test A
dig +tcp @127.0.0.1 -p 5353 phishing-demo.test A
```

Verify that a blocked query receives `REFUSED`, does not appear in upstream packet captures, and is recorded in the event log. For an allowed query, demonstrate upstream forwarding. Capture a brief packet trace on the local interface or display DNS packets in Wireshark.

At no point during the demonstration should you open malicious URLs in a browser or attempt to connect to real C2, malware, or phishing infrastructure.

### 11.5. Definition of Done

The MVP is accepted when:

- [ ] the application builds with `go build ./...`;
- [ ] `go test ./...` passes;
- [ ] DNS UDP and TCP listeners operate properly;
- [ ] allowed queries are forwarded upstream;
- [ ] deny rules and the demo feed block matching domains;
- [ ] blocked requests are not forwarded upstream;
- [ ] allowlist rules take precedence;
- [ ] events are persisted in SQLite;
- [ ] the dashboard and events pages display live data;
- [ ] login and both roles (`admin` and `analyst`) function properly;
- [ ] `analyst` cannot modify rules;
- [ ] feeds can be synchronized, and last-known-good data is preserved on failure;
- [ ] `README.md` includes setup, run, and demo instructions;
- [ ] no real malicious domain lookups are used in tests or demonstrations.

---

## 12. Implementation Phases

Target a 10-step implementation plan. Detailed task breakdowns are provided in `TODO_DNS_Filter_MVP.md`.

| Step | Deliverable |
|---|---|
| 1 | Go project skeleton, config, SQLite migrations |
| 2 | DNS UDP/TCP forwarding |
| 3 | Policy engine and manual rules |
| 4 | Feed loader and demo feed |
| 5 | DNS event logging and dashboard queries |
| 6 | Login, sessions, RBAC |
| 7 | REST API and web UI |
| 8 | Integration tests and failure tests |
| 9 | Security review and bug fixes |
| 10 | README, architecture diagram, demo script |

---

## 13. Optional / Future Work

Only after full completion of the Definition of Done may the following be considered:

- JSON/CSV export or generic syslog output;
- additional threat-intel feed adapters (e.g., ThreatFox Community API);
- simple DNS cache with TTL-aware eviction;
- configurable multiple upstream resolvers and health checks;
- DoH/DoT to the service's own upstream resolver (not intercepting client encrypted DNS);
- policy enforcement for managed clients and network perimeters;
- DNS query anomaly analytics;
- DGA scoring as a research module with separate false-positive evaluation;
- Prometheus metrics;
- client groups and distinct policy profiles.

None of these features may be included in the MVP at the expense of reducing mandatory tests, authentication, rule matching, or logging.

---

## 14. Instructions for the AI Developer

Use this section as mandatory rules when generating source code:

1. Read this TS and `TODO_DNS_Filter_MVP.md` completely before starting.
2. Implement the application in small, complete stages following the TODO list. After each stage, run `gofmt`, `go test ./...`, and `go build ./...`.
3. Do not generate files as large stubs. Every endpoint and UI action must be genuinely functional.
4. Do not change the chosen architecture to React, Node.js, Python, PostgreSQL, Redis, CoreDNS, or microservices.
5. Do not implement inline interception, DoH/DoT downgrade, TLS MITM, or a full recursive resolver.
6. All DNS integration tests must use a local fake upstream server, never public malicious indicators.
7. Include clear error messages, contexts/timeouts, and graceful shutdown handling.
8. Parameterize all SQL queries. Enforce all permissions on the server side.
9. Never store passwords or raw session tokens in SQLite or logs.
10. Do not consider a task complete simply because code was generated. Run tests and report exact commands, results, and known limitations in the final summary.
11. Where an implementation detail is not specified by the TS, choose the simplest solution that satisfies requirements and testability. Do not expand scope unnecessarily.
12. At the end, provide: full source code, `README.md`, `config.example.json`, test report, brief architecture overview, startup commands, and a sequence for the university demonstration.

---

## 15. Useful Technical References

These references describe the underlying protocols and chosen libraries; they must not be interpreted as requirements to implement every feature of their respective standards.

1. [miekg/dns — Go DNS library](https://github.com/miekg/dns) — DNS UDP/TCP server/client, message handling, EDNS0, and DNSSEC-related features.
2. [miekg/dns package documentation](https://pkg.go.dev/github.com/miekg/dns) — `Client.Exchange` API; documentation notes that the caller must handle TCP fallback upon truncation.
3. [modernc.org/sqlite](https://modernc.org/sqlite) — pure-Go SQLite driver without CGO.
4. [Go `embed` package](https://pkg.go.dev/embed) — embedding HTML/CSS/JS assets into the executable binary.
5. [RFC 1035](https://www.rfc-editor.org/rfc/rfc1035) — core specification for DNS messages and UDP/TCP DNS.
6. [RFC 5452](https://www.rfc-editor.org/rfc/rfc5452) — measures for making DNS more resilient against forged responses.
7. [RFC 6761](https://www.rfc-editor.org/rfc/rfc6761) — special-use domain names, including `.test` for testing.
8. [RFC 7858](https://www.rfc-editor.org/rfc/rfc7858) — DNS over TLS.
9. [RFC 8484](https://www.rfc-editor.org/rfc/rfc8484) — DNS over HTTPS.
10. [RFC 9250](https://www.rfc-editor.org/rfc/rfc9250) — DNS over QUIC.
11. [RFC 9499](https://www.rfc-editor.org/rfc/rfc9499) — DNS terminology.
12. [OWASP Session Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html) — best practices for session identifiers, cookie attributes, and server-side session management.
13. [HaGeZi DNS Blocklists](https://github.com/hagezi/dns-blocklists) — community blocklists; published lists are licensed under GPL-3.0, while upstream sources may have separate terms.
14. [ThreatFox Community API](https://threatfox.abuse.ch/api/) — potential IOC API source for future integration; requires an Auth-Key and adherence to fair-use terms.
15. [URLhaus Feeds](https://urlhaus.abuse.ch/feeds/) — official warning noting that listed network feeds are not intended for direct blacklisting/IOC use.