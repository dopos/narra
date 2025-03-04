package main

import (
	"context"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"regexp"
	"syscall"
	"time"

	"github.com/LeKovr/go-kit/config"
	"github.com/LeKovr/go-kit/slogger"
	"github.com/LeKovr/go-kit/ver"
	"golang.org/x/sync/errgroup"

	"github.com/dopos/narra"
)

const (
	// AppName holds app name
	AppName = "narra"
	// AppDescription holds app description
	AppDescription = "Nginx Auth Request via Remote Auth server"
)

var (
	// App version, actual value will be set at build time
	version = "0.0-dev"

	// Repository address, actual value will be set at build time
	repo = "repo.git"
)

// Config holds all config vars
type Config struct {
	Listen         string        `long:"listen" default:":8080" description:"Addr and port which server listens at"`
	GracePeriod    time.Duration `long:"grace" default:"1m" description:"Stop grace period"`
	Path           string        `long:"fs.path" default:"" description:"Path to static files (default: don't serve static)"`
	ProtectPattern string        `long:"fs.protect" default:"" description:"Regexp for pages which require auth"`

	Logger     slogger.Config `group:"Logging Options" namespace:"log" env-namespace:"LOG"`
	AuthServer narra.Config   `group:"Auth Service Options" namespace:"as" env-namespace:"AS"`

	MaxHeaderBytes int           `long:"maxheader" description:"MaxHeaderBytes"`
	ReadTimeout    time.Duration `long:"rto" default:"10s" description:"HTTP read timeout"`
	WriteTimeout   time.Duration `long:"wto" default:"60s" description:"HTTP write timeout"`

	config.EnableShowVersion
	config.EnableConfigDefGen
	config.EnableConfigDump
}

// Run app and exit via given exitFunc
func Run(version string, exitFunc func(code int)) {
	config.SetApplicationVersion(AppName, version)
	// Load config
	var cfg Config
	err := config.Open(&cfg)
	defer func() { config.Close(err, exitFunc) }()
	if err != nil {
		return
	}
	if err = slogger.Setup(cfg.Logger, nil); err != nil {
		return
	}
	slog.Info(AppName, "version", version)
	go ver.Check(repo, version)

	mux := http.NewServeMux()

	auth := narra.New(&cfg.AuthServer)
	auth.SetupRoutes(mux, "/")
	if cfg.Path != "" {
		serverRoot := os.DirFS(cfg.Path)
		hfs := http.FS(serverRoot)
		fileServer := http.FileServer(hfs)
		mux.Handle("/", fileServer)
	}
	var hh http.Handler
	if cfg.ProtectPattern != "" {
		re := regexp.MustCompile(cfg.ProtectPattern)
		hh = auth.ProtectMiddleware(mux, re)
	} else {
		hh = mux
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM, syscall.SIGINT)
	defer stop()
	ctx = slogger.NewContext(ctx, slog.Default())

	srv := &http.Server{
		Addr:           cfg.Listen,
		ReadTimeout:    cfg.ReadTimeout,
		WriteTimeout:   cfg.WriteTimeout,
		MaxHeaderBytes: cfg.MaxHeaderBytes,
		Handler:        hh,
		BaseContext: func(_ net.Listener) context.Context {
			return ctx
		},
	}

	g, gCtx := errgroup.WithContext(ctx)
	g.Go(func() error {
		slog.Info("Start", "addr", cfg.Listen)
		return srv.ListenAndServe()
	})
	g.Go(func() error {
		<-gCtx.Done()
		slog.Info("Shutdown")
		stop()
		timedCtx, cancel := context.WithTimeout(context.Background(), cfg.GracePeriod)
		defer cancel()
		return srv.Shutdown(timedCtx)
	})
	if er := g.Wait(); er != nil && er != http.ErrServerClosed {
		err = er
	}
	slog.Info("Exit")
}
