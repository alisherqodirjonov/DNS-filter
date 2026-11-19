// Package migrations holds the SQLite schema shipped inside the binary.
package migrations

import _ "embed"

// Migration is one schema step. Versions are applied in order and recorded in schema_migrations.
type Migration struct {
	Version int
	SQL     string
}

//go:embed 001_init.sql
var initSQL string

//go:embed 002_console_settings.sql
var consoleSettingsSQL string

// All lists every migration. A new schema change gets a new file and the next version.
var All = []Migration{
	{Version: 1, SQL: initSQL},
	{Version: 2, SQL: consoleSettingsSQL},
}
