# DNS Filter MVP — Implementation TODO

**Related Document:** `TZ_DNS_Filter_MVP.md`  
**Target Timeline:** 7–14 days  
**Recommended Order:** Execute tasks from top to bottom; do not move on to optional features until the Definition of Done is completely closed.

## Working Rule

After every logical task:

```bash
gofmt -w .
go test ./...
go build ./...
```

Each stage must conclude with a working, verifiable result. Do not leave endpoints, UI buttons, or DNS handlers as mock/stub implementations.

---

## Phase 0 — Project Setup

### Day 1 — Skeleton, Configuration, Persistence

- [ ] Initialize Go module `dnsfilter`.
- [ ] Create the directory structure defined in the TS.
- [ ] Add `github.com/miekg/dns`.
- [ ] Add `modernc.org/sqlite`.
- [ ] Add `golang.org/x/crypto/bcrypt`.
- [ ] Add `golang.org/x/net/idna`.
- [ ] Implement `config.json` parsing.
- [ ] Implement validation for listen addresses, upstream, timeout, RCODE, and feed format.
- [ ] Create `config.example.json`.
- [ ] Implement SQLite connection setup and startup migrations.
- [ ] Create tables: `users`, `sessions`, `rules`, `feeds`, `feed_domains`, `query_events`, `audit_events`.
- [ ] Configure foreign keys and busy timeout.
- [ ] Configure structured logging via `log/slog`.
- [ ] Add graceful shutdown skeleton.

**Stage Verification:** `go test ./...` and `go build ./...` pass; the application starts up, reads config, and initializes the SQLite DB.

---

## Phase 1 — DNS Data Plane

### Day 2 — UDP/TCP DNS Forwarding

- [ ] Implement DNS UDP listener.
- [ ] Implement DNS TCP listener.
- [ ] Start listeners independently with proper startup error handling.
- [ ] Implement DNS request handler.
- [ ] Support standard `QUERY` requests with a single Question.
- [ ] Handle malformed and unsupported queries without panicking.
- [ ] Implement upstream DNS client.
- [ ] Configure upstream timeout.
- [ ] Implement UDP-to-TCP retry if the upstream UDP response sets `TC=1`.
- [ ] Return `SERVFAIL` on upstream timeout/error.
- [ ] Add unit/integration tests using a fake upstream DNS server.

**Stage Verification:** An allowed query sent through the local DNS Filter reaches the fake upstream and receives the expected response. UDP and TCP tests pass.

### Day 3 — Domain Normalization and Policy Engine

- [ ] Implement domain name normalization: lowercase, trailing dot handling, IDNA-to-ASCII.
- [ ] Implement an in-memory policy snapshot structure.
- [ ] Implement `exact` matching.
- [ ] Implement `suffix` matching with label boundary verification.
- [ ] Implement allow rules.
- [ ] Implement manual deny rules.
- [ ] Implement feed deny rules (test data can be used initially).
- [ ] Implement precedence: allow > manual deny > feed deny > forward.
- [ ] Ensure thread-safe updates to the policy snapshot upon rule changes without restarting DNS listeners.
- [ ] Return `REFUSED` on deny matches.
- [ ] Verify that blocked requests do not call upstream.
- [ ] Add unit tests for match boundaries and allowlist precedence.

**Stage Verification:** `malware-demo.test` is blocked locally, `example.com` is forwarded upstream, and `notexample.test` does not match a suffix rule for `example.test`.

---

## Phase 2 — Threat Intelligence and Events

### Day 4 — Feed Ingestion

- [ ] Create `testdata/demo-blocklist.txt`.
- [ ] Add benign domains: `malware-demo.test`, `phishing-demo.test`, `c2-demo.test`.
- [ ] Implement feed config entries: `name`, `path`/`url`, `format`.
- [ ] Implement local file source loader.
- [ ] Implement HTTPS source loader with timeout and maximum response body limit.
- [ ] Reject plain HTTP feed URLs.
- [ ] Implement parser for the `domains` format.
- [ ] Implement parser for the `hosts` format.
- [ ] Ignore comments and blank lines.
- [ ] Validate and normalize every domain.
- [ ] Preserve feed provenance.
- [ ] Perform feed updates inside an SQLite transaction.
- [ ] Retain the last successful feed version on failed sync.
- [ ] Persist `last_sync_at`, `status`, `error`, and loaded domains count.
- [ ] Implement sync-on-start and a periodic scheduler (24-hour interval).
- [ ] Add unit tests for the parser and failed update recovery behavior.

**Stage Verification:** The local demo feed loads; its domains are blocked; a malformed feed does not wipe out previously loaded entries.

### Day 5 — DNS Event Logging and Reporting Queries

- [ ] Generate an event record for every DNS query.
- [ ] Record timestamp in UTC.
- [ ] Record client IP from the remote address.
- [ ] Record `qname`, `qtype`, `transport`, `action`, and `rcode`.
- [ ] Record upstream latency for forwarded requests.
- [ ] Record matched source/domain for blocked requests.
- [ ] Persist events to SQLite.
- [ ] Implement pagination for query events.
- [ ] Implement filtering by `qname` and `action`.
- [ ] Implement summary SQL queries: total, allowed, blocked, block ratio.
- [ ] Implement top blocked domains and top clients queries.
- [ ] Implement cleanup of events older than the configured retention period (default: 7 days).
- [ ] Ensure passwords, session tokens, or full DNS packets are never logged.

**Stage Verification:** After a series of `dig` queries, SQLite contains events with accurate actions, RCODEs, and client IPs.

---

## Phase 3 — Control Plane and Web UI

### Day 6 — Authentication, Sessions, RBAC

- [ ] Implement bootstrap admin account creation via environment variables.
- [ ] Implement optional bootstrap analyst account creation.
- [ ] Create bootstrap users only when the `users` table is empty.
- [ ] Hash passwords using `bcrypt`.
- [ ] Implement login endpoint.
- [ ] Generate session tokens via `crypto/rand`.
- [ ] Store only the hash of the session token in SQLite.
- [ ] Implement session expiration.
- [ ] Implement logout and session invalidation.
- [ ] Set cookie attributes: `HttpOnly`, `SameSite=Strict`, `Path=/`; `Secure` over HTTPS.
- [ ] Implement CSRF token/header validation or strict server-side `Origin`/`Host` verification.
- [ ] Implement RBAC middleware/helpers.
- [ ] Rate-limit login attempts.
- [ ] Implement audit logging for login success/failure and logout.
- [ ] Test that `analyst` receives `403` on mutating endpoints.

**Stage Verification:** `admin` can log in and perform administrative actions; `analyst` can log in and only read data; unauthenticated users cannot access protected APIs.

### Day 7 — REST API and HTML/CSS/JS UI

- [ ] Implement `GET /api/v1/health`.
- [ ] Implement `POST /api/v1/auth/login`.
- [ ] Implement `POST /api/v1/auth/logout`.
- [ ] Implement `GET /api/v1/me`.
- [ ] Implement `GET /api/v1/dashboard/summary`.
- [ ] Implement `GET /api/v1/events` with pagination and filters.
- [ ] Implement `GET /api/v1/rules`.
- [ ] Implement `POST /api/v1/rules` (`admin` only).
- [ ] Implement `DELETE /api/v1/rules/{id}` (`admin` only).
- [ ] Implement `GET /api/v1/feeds`.
- [ ] Implement `POST /api/v1/feeds/{id}/sync` (`admin` only).
- [ ] Implement `GET /api/v1/audit` (`admin` only).
- [ ] Create the login page.
- [ ] Create the dashboard page.
- [ ] Create the DNS events table and filters.
- [ ] Create the rules page with add/delete forms for `admin`.
- [ ] Create the feed status page with "Sync Now" for `admin`.
- [ ] Hide admin controls from `analyst` in the UI, while enforcing permissions on the backend.
- [ ] Add clear loading, error, and empty states.
- [ ] Embed HTML/CSS/JS assets via `embed`.
- [ ] Ensure no external JS/CSS CDNs are loaded.

**Stage Verification:** Users can log into the UI, view DNS events, add a deny rule, and verify its enforcement with a new DNS query without restarting the service.

---

## Phase 4 — Integration Checks and Preparation

### Day 8 — End-to-End Tests and Resilience

- [ ] Set up an integration test fixture with a local fake upstream DNS server.
- [ ] Verify UDP allowed query.
- [ ] Verify TCP allowed query.
- [ ] Verify blocked query and absence of upstream calls.
- [ ] Verify allowlist precedence.
- [ ] Verify upstream timeout -> `SERVFAIL`.
- [ ] Verify truncated UDP upstream response -> TCP retry.
- [ ] Verify query event persistence.
- [ ] Verify rule creation/deletion and live in-memory policy updates.
- [ ] Verify feed update success and failure handling.
- [ ] Verify `analyst` vs. `admin` authorization.
- [ ] Verify logout and session expiration.
- [ ] Verify that malformed DNS packets and malformed feed lines do not cause panics.
- [ ] Run `go test -race ./...` and fix any detected race conditions.

**Stage Verification:** The entire test suite passes without using any public malicious domains.

### Day 9 — Security Review and Quality Pass

- [ ] Verify absence of hardcoded credentials.
- [ ] Verify passwords are never written to logs.
- [ ] Verify raw session tokens are neither stored in the DB nor logged.
- [ ] Verify RBAC enforcement on every mutating endpoint.
- [ ] Verify all SQL queries are parameterized.
- [ ] Verify HTML escaping and absence of unsafe user input injection via `innerHTML`.
- [ ] Verify CSRF controls.
- [ ] Verify absence of permissive CORS headers.
- [ ] Verify the admin listener binds to loopback by default.
- [ ] Verify feed download timeout and body size limits.
- [ ] Verify transactional feed updates.
- [ ] Verify maximum page size limits on the events API.
- [ ] Verify retention cleanup logic.
- [ ] Add clear startup error messages.
- [ ] Run `go vet ./...`.
- [ ] Run `go test ./...` and `go build ./...`.

**Stage Verification:** No known critical bugs remain in the project, and all mandatory tests pass.

### Day 10 — Documentation and University Demonstration

- [ ] Write `README.md` with a concise overview and architecture description.
- [ ] Document Go toolchain requirements and build instructions.
- [ ] Include `config.example.json`.
- [ ] Document bootstrap admin/analyst environment variables.
- [ ] Document running on `127.0.0.1:5353` for local testing.
- [ ] Document running on port `53` in an isolated lab network.
- [ ] Document how to configure DNS on a test client.
- [ ] Document `dig` commands for allowed and blocked queries.
- [ ] Add an architecture diagram.
- [ ] Add a brief test report with executed commands and actual outputs.
- [ ] Capture screenshots of the dashboard, events, rules, and feed pages.
- [ ] Prepare a Wireshark/tcpdump packet capture or pre-captured screenshot.
- [ ] Prepare a 3–5 minute demonstration script.
- [ ] Test the project with a clean SQLite DB on a fresh startup.
- [ ] Verify that `README.md` contains no real malicious domains or instructions to visit them.

**Stage Verification:** Another person can follow `README.md` and reproduce the demonstration on their own local test machine.

---

## MVP Checklist — Must-Have Items

### Core DNS
- [ ] UDP/53 listener
- [ ] TCP/53 listener
- [ ] Forward allowed requests to a configurable upstream resolver
- [ ] TCP retry after truncated UDP upstream response
- [ ] Timeout and `SERVFAIL` behavior
- [ ] `REFUSED` response for blocked names

### Policy and Feeds
- [ ] Exact matching
- [ ] Suffix matching with label boundary
- [ ] Allowlist precedence
- [ ] Manual deny rules
- [ ] At least one feed source supporting `domains`/`hosts` formats
- [ ] Atomic feed update and last-known-good preservation

### Logs and Web Panel
- [ ] SQLite query event log
- [ ] Dashboard counters
- [ ] Events table and filters
- [ ] Add/delete manual rules
- [ ] Feed status and manual sync
- [ ] `admin` and `analyst` roles

### Engineering Quality
- [ ] Unit tests
- [ ] DNS integration tests with fake upstream
- [ ] API/RBAC tests
- [ ] README and reproducible demo

---

## Do Not Start Before Completing the MVP

The following features often look appealing but will almost certainly delay completion:

- [ ] Transparent DNS redirection / inline interception
- [ ] DoH/DoT/DoQ interception or downgrade
- [ ] Full recursive resolver
- [ ] DNS cache implementation
- [ ] ML/DGA detection
- [ ] DNS tunneling detection
- [ ] SIEM connectors
- [ ] Prometheus/Grafana
- [ ] Docker orchestration / Kubernetes
- [ ] Multi-node HA
- [ ] Per-device policy groups
- [ ] Block page / HTTP interception

These may only be added after the full MVP is completed, with a separate plan and tests.

---

## Recommended Prompt for AI Coding Agent

Provide both documents to the agent and use the following prompt:

> Read `TZ_DNS_Filter_MVP.md` and `TODO_DNS_Filter_MVP.md` completely. Implement the project strictly according to the TS, using Go as the primary language, `miekg/dns` for DNS, `net/http` for the API, SQLite via a pure-Go driver, and HTML/CSS/Vanilla JavaScript for the UI. Work through the TODO list phase by phase without skipping ahead. After each phase, run `gofmt`, `go test ./...`, and `go build ./...`; fix any errors before moving to the next stage. Do not add React, Node.js, Python, PostgreSQL, Redis, microservices, inline interception, encrypted DNS downgrade, or TLS MITM. For DNS integration tests, use only a local fake upstream server. Use exclusively `.test` synthetic names for the demo blocklist; do not visit or query real malicious domains. Do not leave fake endpoints, mock buttons, or TODO stubs. Where implementation details are unspecified, choose the minimal solution that satisfies the TS and document the decision in `README.md`. At the end, deliver the full source code, `README.md`, example configuration, list of completed TODO items, test commands with actual outputs, and a brief demonstration script.