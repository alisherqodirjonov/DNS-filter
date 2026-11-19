ALTER TABLE users ADD COLUMN must_change_password INTEGER NOT NULL DEFAULT 0;

CREATE TABLE settings (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    updated_by TEXT NOT NULL
);

CREATE TABLE query_counts (
    day TEXT NOT NULL,
    action TEXT NOT NULL,
    count INTEGER NOT NULL,
    PRIMARY KEY (day, action)
);

INSERT INTO query_counts(day, action, count)
SELECT substr(timestamp, 1, 10), action, COUNT(*)
FROM query_events
GROUP BY substr(timestamp, 1, 10), action;
