// Package app wires the DNS Filter process together.
package app

import (
	"context"
	"log/slog"
	"net"
	"net/http"
	"os"
	"sync"
	"time"

	"dnsfilter/internal/auth"
	"dnsfilter/internal/config"
	"dnsfilter/internal/dnsserver"
	"dnsfilter/internal/feeds"
	"dnsfilter/internal/httpapi"
	"dnsfilter/internal/policy"
	"dnsfilter/internal/store"
	"dnsfilter/internal/upstream"
)

// Run opens the database, starts the DNS listeners, and blocks until ctx is cancelled.
func Run(ctx context.Context, cfg *config.Config, logger *slog.Logger) error {
	if logger == nil {
		logger = slog.Default()
	}
	logger.Info("configuration loaded",
		"dns_udp", cfg.DNS.ListenUDP,
		"dns_tcp", cfg.DNS.ListenTCP,
		"upstream", cfg.DNS.Upstream,
		"http", cfg.HTTP.Listen,
		"blocked_rcode", cfg.DNS.BlockedRCode,
	)
	st, err := store.Open(cfg.Database.Path)
	if err != nil {
		return err
	}
	defer st.Close()
	logger.Info("database ready", "path", cfg.Database.Path)

	// Workers stop, and their queries finish, before the database is closed.
	runCtx, stopRun := context.WithCancel(ctx)
	var workers sync.WaitGroup
	defer func() {
		stopRun()
		workers.Wait()
	}()

	accounts := auth.New(st, logger)
	if err := accounts.Bootstrap(ctx,
		os.Getenv("DNSFILTER_BOOTSTRAP_ADMIN_USER"),
		os.Getenv("DNSFILTER_BOOTSTRAP_ADMIN_PASSWORD"),
		os.Getenv("DNSFILTER_BOOTSTRAP_ANALYST_USER"),
		os.Getenv("DNSFILTER_BOOTSTRAP_ANALYST_PASSWORD"),
	); err != nil {
		return err
	}

	engine := policy.NewEngine()
	if err := reload(ctx, st, engine); err != nil {
		return err
	}
	feedSvc := &feeds.Service{
		Store:   st,
		Sources: cfg.Feeds.Sources,
		Logger:  logger,
		OnChange: func(ctx context.Context) error {
			return reload(ctx, st, engine)
		},
	}
	if err := feedSvc.Reconcile(ctx); err != nil {
		return err
	}
	feedSvc.SyncAll(ctx)
	workers.Add(2)
	go func() {
		defer workers.Done()
		feeds.Schedule(runCtx, cfg.Feeds.SyncInterval, func(ctx context.Context) {
			feedSvc.SyncAll(ctx)
		})
	}()
	go func() {
		defer workers.Done()
		retainEvents(runCtx, st, cfg.Logging.Retention, logger)
	}()

	dnsSrv, err := dnsserver.Listen(dnsserver.Options{
		ListenUDP:    cfg.DNS.ListenUDP,
		ListenTCP:    cfg.DNS.ListenTCP,
		Engine:       engine,
		Upstream:     &upstream.Client{Addr: cfg.DNS.Upstream, Timeout: cfg.DNS.UpstreamTimeout},
		BlockedRCode: cfg.DNS.BlockedRCode,
		Record:       recordToStore(st),
		Logger:       logger,
	})
	if err != nil {
		return err
	}
	defer dnsSrv.Close()
	logger.Info("dns listening", "udp", dnsSrv.UDPAddr().String(), "tcp", dnsSrv.TCPAddr().String())

	api := &httpapi.API{
		Store:  st,
		Auth:   accounts,
		Feeds:  feedSvc,
		Engine: engine,
		Logger: logger,
		Reload: func(ctx context.Context) error { return reload(ctx, st, engine) },
	}
	httpLn, err := net.Listen("tcp", cfg.HTTP.Listen)
	if err != nil {
		return err
	}
	httpSrv := &http.Server{
		Handler:           api.Handler(),
		ReadHeaderTimeout: 5 * time.Second,
		IdleTimeout:       time.Minute,
	}
	go func() {
		if err := httpSrv.Serve(httpLn); err != nil && err != http.ErrServerClosed {
			logger.Error("http server stopped", "error", err.Error())
		}
	}()
	logger.Info("admin panel listening", "addr", httpLn.Addr().String())
	if !cfg.LoopbackHTTP() {
		logger.Warn("admin panel is not bound to loopback; keep it on an isolated lab network", "listen", cfg.HTTP.Listen)
	}
	workers.Add(1)
	go func() {
		defer workers.Done()
		ticker := time.NewTicker(10 * time.Minute)
		defer ticker.Stop()
		for {
			select {
			case <-runCtx.Done():
				return
			case <-ticker.C:
				if err := st.DeleteExpiredSessions(runCtx, time.Now()); err != nil && runCtx.Err() == nil {
					logger.Error("session cleanup failed", "error", err.Error())
				}
			}
		}
	}()

	<-ctx.Done()
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := httpSrv.Shutdown(shutdownCtx); err != nil {
		logger.Error("http shutdown failed", "error", err.Error())
	}
	logger.Info("shutting down")
	return nil
}

// LoadSnapshot reads manual rules and feed domains into one policy generation.
func LoadSnapshot(ctx context.Context, st *store.Store) (*policy.Snapshot, error) {
	rules, err := st.ListRules(ctx)
	if err != nil {
		return nil, err
	}
	domains, err := st.ListFeedDomains(ctx)
	if err != nil {
		return nil, err
	}
	policyRules := make([]policy.Rule, 0, len(rules))
	for _, rule := range rules {
		policyRules = append(policyRules, policy.Rule{
			ID: rule.ID, Domain: rule.Domain, Kind: rule.RuleType, Match: rule.MatchType,
		})
	}
	feeds := make([]policy.FeedRule, 0, len(domains))
	for _, domain := range domains {
		feeds = append(feeds, policy.FeedRule{Name: domain.FeedName, Domain: domain.Domain})
	}
	return policy.NewSnapshot(policyRules, feeds)
}

func reload(ctx context.Context, st *store.Store, engine *policy.Engine) error {
	snap, err := LoadSnapshot(ctx, st)
	if err != nil {
		return err
	}
	engine.Replace(snap)
	return nil
}

func retainEvents(ctx context.Context, st *store.Store, retention time.Duration, logger *slog.Logger) {
	run := func() {
		if retention <= 0 {
			return
		}
		n, err := st.DeleteEventsBefore(ctx, time.Now().Add(-retention))
		if err != nil {
			if ctx.Err() == nil {
				logger.Error("retention cleanup failed", "error", err.Error())
			}
			return
		}
		if n > 0 {
			logger.Info("removed old dns events", "count", n)
		}
	}
	run()
	ticker := time.NewTicker(time.Hour)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			run()
		}
	}
}

func recordToStore(st *store.Store) dnsserver.Recorder {
	return func(ctx context.Context, ev dnsserver.QueryEvent) error {
		_, err := st.InsertEvent(ctx, store.Event{
			Timestamp:         ev.Timestamp,
			ClientIP:          ev.ClientIP,
			QName:             ev.QName,
			QType:             ev.QType,
			Transport:         ev.Transport,
			Action:            ev.Action,
			RCode:             ev.RCode,
			UpstreamLatencyMS: ev.UpstreamLatencyMS,
			MatchedSource:     ev.MatchedSource,
			MatchedDomain:     ev.MatchedDomain,
		})
		return err
	}
}
