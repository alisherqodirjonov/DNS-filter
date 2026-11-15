CREATE TABLE schema_migrations (
    version INTEGER PRIMARY KEY,
    applied_at TEXT NOT NULL
);

CREATE TABLE users (
    id INTEGER PRIMARY KEY,
    username TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL CHECK (role IN ('admin', 'analyst')),
    created_at TEXT NOT NULL
);

CREATE TABLE sessions (
    id INTEGER PRIMARY KEY,
    token_hash TEXT NOT NULL UNIQUE,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    csrf_token TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE TABLE rules (
    id INTEGER PRIMARY KEY,
    domain TEXT NOT NULL,
    rule_type TEXT NOT NULL CHECK (rule_type IN ('allow', 'deny')),
    match_type TEXT NOT NULL CHECK (match_type IN ('exact', 'suffix')),
    description TEXT NOT NULL DEFAULT '',
    created_by TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE UNIQUE INDEX idx_rules_identity ON rules(domain, rule_type, match_type);

CREATE TABLE feeds (
    id INTEGER PRIMARY KEY,
    name TEXT NOT NULL UNIQUE,
    source TEXT NOT NULL,
    format TEXT NOT NULL,
    status TEXT NOT NULL,
    last_sync_at TEXT,
    last_error TEXT NOT NULL DEFAULT '',
    domains_count INTEGER NOT NULL DEFAULT 0,
    rejected_count INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE feed_domains (
    id INTEGER PRIMARY KEY,
    feed_id INTEGER NOT NULL REFERENCES feeds(id) ON DELETE CASCADE,
    domain TEXT NOT NULL,
    UNIQUE (feed_id, domain)
);

CREATE INDEX idx_feed_domains_domain ON feed_domains(domain);

CREATE TABLE query_events (
    id INTEGER PRIMARY KEY,
    timestamp TEXT NOT NULL,
    client_ip TEXT NOT NULL,
    qname TEXT NOT NULL,
    qtype TEXT NOT NULL,
    transport TEXT NOT NULL,
    action TEXT NOT NULL,
    rcode TEXT NOT NULL,
    upstream_latency_ms INTEGER,
    matched_source TEXT,
    matched_domain TEXT
);

CREATE INDEX idx_query_events_timestamp ON query_events(timestamp);
CREATE INDEX idx_query_events_qname ON query_events(qname);
CREATE INDEX idx_query_events_action ON query_events(action);

CREATE TABLE audit_events (
    id INTEGER PRIMARY KEY,
    timestamp TEXT NOT NULL,
    username TEXT NOT NULL,
    action TEXT NOT NULL,
    object_type TEXT NOT NULL,
    object_id TEXT NOT NULL DEFAULT '',
    result TEXT NOT NULL
);

CREATE INDEX idx_audit_events_timestamp ON audit_events(timestamp);
