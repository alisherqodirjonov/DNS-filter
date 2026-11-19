package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"dnsfilter"
	"dnsfilter/internal/app"
	"dnsfilter/internal/config"
)

const defaultConfigPath = "config.json"

func main() {
	os.Exit(run())
}

func run() int {
	configPath := flag.String("config", defaultConfigPath, "path to the JSON configuration file")
	flag.Parse()

	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))
	if !flagSet("config") {
		created, err := ensureConfig(*configPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "dnsfilter: %v\n", err)
			return 1
		}
		if created {
			abs, _ := filepath.Abs(*configPath)
			logger.Info("created config.json from the built-in example; edit it to change listen addresses or feeds", "path", abs)
		}
	}
	cfg, err := config.Load(*configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "dnsfilter: %v\n", err)
		return 1
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := app.Run(ctx, cfg, logger); err != nil {
		fmt.Fprintf(os.Stderr, "dnsfilter: %v\n", err)
		return 1
	}
	return 0
}

// ensureConfig writes the example configuration to path unless a file is already there.
// An explicit -config path is never created, so a mistyped path still fails.
func ensureConfig(path string) (bool, error) {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
	if errors.Is(err, fs.ErrExist) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("create %s: %w", path, err)
	}
	if _, err := f.Write(dnsfilter.ExampleConfig); err != nil {
		f.Close()
		return false, fmt.Errorf("write %s: %w", path, err)
	}
	return true, f.Close()
}

func flagSet(name string) bool {
	set := false
	flag.Visit(func(f *flag.Flag) {
		if f.Name == name {
			set = true
		}
	})
	return set
}
