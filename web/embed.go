// Package web holds the embedded console assets.
package web

import "embed"

// Files contains the HTML templates and the local CSS and JavaScript.
//
//go:embed templates static
var Files embed.FS
