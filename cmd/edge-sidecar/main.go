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
	"sync/atomic"
	"syscall"
	"time"

	"github.com/PrivateCaptcha/PrivateCaptcha/pkg/common"
	"github.com/PrivateCaptcha/PrivateCaptcha/pkg/config"
	"github.com/PrivateCaptcha/edge-sidecar/pkg/api"
)

var (
	GitCommit string
)

type authorizerState struct {
	keys       *api.KeyCache
	authorizer *api.Authorizer
	router     *http.ServeMux
	stopJobs   context.CancelFunc
	jobsDone   chan struct{}
}

func newAuthorizerState(ctx context.Context, s api.Settings, previous *authorizerState) (*authorizerState, error) {
	keys := api.NewKeyCache(s)
	if err := keys.RunOnce(ctx, keys.NewParams()); err != nil {
		keys.CloseIdleConnections()
		return nil, fmt.Errorf("initial JWKS fetch: %w", err)
	}
	var authorizer *api.Authorizer
	var err error
	if previous == nil {
		authorizer, err = api.NewAuthorizer(s, keys)
	} else {
		authorizer, err = previous.authorizer.Reconfigure(s, keys)
	}
	if err != nil {
		keys.CloseIdleConnections()
		return nil, err
	}
	router := http.NewServeMux()
	authorizer.Setup(router)
	jobsCtx, stopJobs := context.WithCancel(ctx)
	state := &authorizerState{
		keys:       keys,
		authorizer: authorizer,
		router:     router,
		stopJobs:   stopJobs,
		jobsDone:   make(chan struct{}),
	}
	go func() {
		defer close(state.jobsDone)
		common.RunPeriodicJob(jobsCtx, keys)
	}()
	return state, nil
}

func (s *authorizerState) close() {
	s.stopJobs()
	<-s.jobsDone
	s.keys.CloseIdleConnections()
}

func run(ctx context.Context, env *common.EnvMap, cfg common.ConfigStore, reloads <-chan os.Signal) error {
	stage := cfg.Get(common.StageKey).Value()
	common.SetupLogs(stage, config.AsBool(cfg.Get(common.VerboseKey)))
	s, err := api.LoadSettings(cfg)
	if err != nil {
		return err
	}
	slog.InfoContext(ctx, "Starting edge sidecar", "address", s.Address, "version", GitCommit, "stage", stage)
	state, err := newAuthorizerState(ctx, s, nil)
	if err != nil {
		return err
	}
	defer func() { state.close() }()
	listener, err := net.Listen("tcp", s.Address)
	if err != nil {
		return err
	}
	defer listener.Close()
	var active atomic.Pointer[authorizerState]
	active.Store(state)
	server := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			active.Load().router.ServeHTTP(w, r)
		}),
		ReadHeaderTimeout: 3 * time.Second,
		ReadTimeout:       5 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    16 * 1024,
		ErrorLog:          slog.NewLogLogger(slog.Default().Handler(), slog.LevelError),
	}
	serveErr := make(chan error, 1)
	go func(stage string) {
		slog.InfoContext(ctx, "Listening", "address", listener.Addr().String(), "version", GitCommit, "stage", stage)
		serveErr <- server.Serve(listener)
	}(stage)
serve:
	for {
		select {
		case <-ctx.Done():
			break serve
		case err = <-serveErr:
			if errors.Is(err, http.ErrServerClosed) {
				err = nil
			}
			break serve
		case <-reloads:
			if reloadErr := env.Update(); reloadErr != nil {
				// Dotenv parser errors can include secret values.
				slog.ErrorContext(ctx, "Environment reload failed; keeping active configuration", "error_type", fmt.Sprintf("%T", reloadErr))
				continue
			}
			cfg.Update(ctx)
			next, reloadErr := api.LoadSettings(cfg)
			if reloadErr == nil && next.Address != s.Address {
				reloadErr = errors.New("listen address changes require a restart")
			}
			if reloadErr != nil {
				slog.ErrorContext(ctx, "Configuration reload failed; keeping active configuration", common.ErrAttr(reloadErr))
				continue
			}
			replacement, reloadErr := newAuthorizerState(ctx, next, state)
			if reloadErr != nil {
				slog.ErrorContext(ctx, "Configuration reload failed; keeping active configuration", common.ErrAttr(reloadErr))
				continue
			}
			previous := state
			state = replacement
			active.Store(state)
			s = next
			stage = cfg.Get(common.StageKey).Value()
			common.SetupLogs(stage, config.AsBool(cfg.Get(common.VerboseKey)))
			previous.close()
			slog.InfoContext(ctx, "Reloaded edge sidecar configuration", "address", s.Address, "stage", stage)
		}
	}
	slog.InfoContext(ctx, "Shutting down edge sidecar", common.ErrAttr(err))
	state.stopJobs()
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if shutdownErr := server.Shutdown(shutdownCtx); shutdownErr != nil {
		server.Close()
		err = errors.Join(err, shutdownErr)
	}
	slog.InfoContext(ctx, "Edge sidecar stopped", common.ErrAttr(err))
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
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	reloads := make(chan os.Signal, 1)
	signal.Notify(reloads, syscall.SIGHUP)
	defer signal.Stop(reloads)
	return run(common.TraceContext(ctx, api.ServiceName), env, cfg, reloads)
}
