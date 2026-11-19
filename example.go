// Package dnsfilter holds files embedded from the project root.
package dnsfilter

import _ "embed"

// ExampleConfig is config.example.json. It is written out as config.json on a first run.
//
//go:embed config.example.json
var ExampleConfig []byte
