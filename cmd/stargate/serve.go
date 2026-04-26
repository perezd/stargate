package main

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/limbic-systems/stargate/internal/config"
	"github.com/limbic-systems/stargate/internal/server"
	"github.com/limbic-systems/stargate/internal/telemetry"
	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
)

// isLoopbackAddr returns true if addr binds to an explicit loopback IP only.
// Hostnames (including "localhost") are rejected — only literal 127.0.0.0/8
// and [::1] are accepted to avoid DNS resolution surprises.
func isLoopbackAddr(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return false
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

const serveUsage = `Usage: stargate serve [flags]

Start the HTTP classification server.

Flags:
  -l, --listen string   Override listen address (must be loopback; default from config)
`

func handleServe(args []string, configPath string, verbose bool) int {
	// Parse -l/--listen flag from args.
	var listenOverride string
	var unknown []string
	for i := 0; i < len(args); i++ {
		arg := args[i]
		switch {
		case arg == "--help" || arg == "-h":
			fmt.Print(serveUsage)
			return 0
		case arg == "-l" || arg == "--listen":
			i++
			if i >= len(args) {
				fmt.Fprintln(os.Stderr, "error: --listen requires a value")
				return 1
			}
			listenOverride = args[i]
		case strings.HasPrefix(arg, "--listen="):
			listenOverride = strings.TrimPrefix(arg, "--listen=")
		case strings.HasPrefix(arg, "-l="):
			listenOverride = strings.TrimPrefix(arg, "-l=")
		default:
			unknown = append(unknown, arg)
		}
	}
	if len(unknown) > 0 {
		fmt.Fprintf(os.Stderr, "serve: unknown argument(s): %s\n", strings.Join(unknown, " "))
		return 1
	}

	if configPath == "" {
		fmt.Fprintln(os.Stderr, "serve: no config file found; pass --config or set STARGATE_CONFIG")
		return 1
	}

	cfg, err := config.Load(configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "serve: failed to load config: %v\n", err)
		return 1
	}
	cfg.Version = Version

	listenAddr := cfg.Server.Listen
	if listenOverride != "" {
		// The --listen flag bypasses config validation, so validate here.
		if !isLoopbackAddr(listenOverride) {
			fmt.Fprintf(os.Stderr, "serve: listen address %q must be a loopback IP (127.0.0.1 or [::1])\n", listenOverride)
			return 1
		}
		listenAddr = listenOverride
	}

	// Initialize telemetry.
	tel, err := telemetry.Init(cfg.Telemetry)
	if err != nil {
		fmt.Fprintf(os.Stderr, "serve: telemetry init: %v\n", err)
		return 1
	}
	defer func() {
		shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer shutdownCancel()
		if err := tel.Shutdown(shutdownCtx); err != nil {
			fmt.Fprintf(os.Stderr, "serve: telemetry shutdown: %v\n", err)
		}
	}()

	srv, err := server.New(cfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "serve: %v\n", err)
		return 1
	}
	srv.SetTelemetry(tel)
	defer func() {
		if err := srv.Close(); err != nil {
			fmt.Fprintf(os.Stderr, "serve: close: %v\n", err)
		}
	}()
	// Derive WriteTimeout from server.timeout so the HTTP server never
	// severs the connection before the classify handler can write a JSON
	// response. The 5s grace covers JSON encoding + network flush.
	writeTimeout := 15 * time.Second
	if cfg.Server.Timeout != "" {
		if d, err := time.ParseDuration(cfg.Server.Timeout); err == nil && d > 0 {
			writeTimeout = d + 5*time.Second
		}
	}
	httpSrv := &http.Server{
		Addr:              listenAddr,
		Handler:           otelhttp.NewHandler(srv, "stargate"),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      writeTimeout,
		IdleTimeout:       60 * time.Second,
	}

	// Handle SIGINT/SIGTERM for graceful shutdown.
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	errCh := make(chan error, 1)
	go func() {
		fmt.Fprintf(os.Stderr, "stargate listening on %s\n", listenAddr)
		if err := httpSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			errCh <- err
		}
		close(errCh)
	}()

	select {
	case sig := <-sigCh:
		if verbose {
			fmt.Fprintf(os.Stderr, "debug: received signal %s, shutting down\n", sig)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := httpSrv.Shutdown(ctx); err != nil {
			fmt.Fprintf(os.Stderr, "serve: shutdown error: %v\n", err)
			return 1
		}
	case err := <-errCh:
		if err != nil {
			fmt.Fprintf(os.Stderr, "serve: %v\n", err)
			return 1
		}
	}

	return 0
}
