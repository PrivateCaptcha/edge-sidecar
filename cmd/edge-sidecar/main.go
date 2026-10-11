package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/PrivateCaptcha/PrivateCaptcha/pkg/common"
	"github.com/PrivateCaptcha/PrivateCaptcha/pkg/config"
	"github.com/PrivateCaptcha/edge-sidecar/pkg/api"
)

var (
	GitCommit string
)

func run(ctx context.Context, s api.Settings, stage string) error {
	keys := api.NewKeyCache(s)
	defer keys.CloseIdleConnections()
	if err := keys.RunOnce(ctx, keys.NewParams()); err != nil {
		return fmt.Errorf("initial JWKS fetch: %w", err)
	}
	listener, err := net.Listen("tcp", s.Address)
	if err != nil {
		return err
	}
	defer listener.Close()

	authorizer, err := api.NewAuthorizer(s, keys)
	if err != nil {
		return err
	}
	router := http.NewServeMux()
	authorizer.Setup(router)
	server := &http.Server{
		Handler:           router,
		ReadHeaderTimeout: 3 * time.Second,
		ReadTimeout:       5 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    16 * 1024,
		ErrorLog:          slog.NewLogLogger(slog.Default().Handler(), slog.LevelError),
	}
	jobsCtx, stopJobs := context.WithCancel(ctx)
	defer stopJobs()
	jobsDone := make(chan struct{})
	go func() {
		defer close(jobsDone)
		common.RunPeriodicJob(jobsCtx, keys)
	}()
	serveErr := make(chan error, 1)
	go func() {
		slog.InfoContext(ctx, "Listening", "address", listener.Addr().String(), "version", GitCommit, "stage", stage)
		serveErr <- server.Serve(listener)
	}()
	select {
	case <-ctx.Done():
	case err = <-serveErr:
		if errors.Is(err, http.ErrServerClosed) {
			err = nil
		}
	}
	stopJobs()
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if shutdownErr := server.Shutdown(shutdownCtx); shutdownErr != nil {
		server.Close()
		err = errors.Join(err, shutdownErr)
	}
	<-jobsDone
	return err
}

func main() {
	envFile := flag.String("env", "", "Path to .env file, 'stdin' or empty")
	versionFlag := flag.Bool("version", false, "Print version and exit")

	flag.Parse()

	if *versionFlag {
		fmt.Print(GitCommit)
		return
	}

	if err := start(*envFile); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func start(envFile string) error {
	env, err := common.NewEnvMap(envFile)
	if err != nil {
		return err
	}
	if err := api.RegisterConfig(); err != nil {
		return err
	}
	cfg := config.NewEnvConfig(func(name string) string {
		value, _ := env.GetEx(name)
		return value
	})
	stage := cfg.Get(common.StageKey).Value()
	common.SetupLogs(stage, config.AsBool(cfg.Get(common.VerboseKey)))
	s, err := api.LoadSettings(cfg)
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	return run(common.TraceContext(ctx, api.ServiceName), s, stage)
}
