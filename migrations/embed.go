// Package migrations holds the SQLite schema shipped inside the binary.
package migrations

import _ "embed"

// SQL is the initial schema. Later changes get a new file and a new version.
//
//go:embed 001_init.sql
var SQL string
