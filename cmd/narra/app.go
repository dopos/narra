package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/dopos/narra"
)

func run(exitFunc func(code int)) {
	var err error
	var cfg *Config
	defer func() { shutdown(exitFunc, err) }()
	cfg, err = setupConfig()
	if err != nil {
		return
	}
	l := setupLog(cfg.Debug)
	l.Debugf("Config: %+v", cfg)
	auth := narra.New(cfg.AuthServer, l)
	r := setupRouter(auth)
	if cfg.FileServer.Path != "" {
		r.Handle("/", FSHandler(cfg.FileServer, l, auth))
	}

	srv := &http.Server{
		Addr:    cfg.Listen,
		Handler: r,
	}

	// Graceful shutdown:
	// http://stackoverflow.com/questions/18106749/golang-catch-signals
	// https://medium.com/honestbee-tw-engineer/gracefully-shutdown-in-go-http-server-5f5e6b83da5a

	done := make(chan os.Signal, 2)
	signal.Notify(done, os.Interrupt, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			l.Fatalf("listen: %s\n", err)
		}
	}()
	l.Printf("Start listening at %s", cfg.Listen)

	sig := <-done
	l.Printf("Got signal %v", sig)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer func() {
		// extra handling here
		cancel()
	}()

	if err := srv.Shutdown(ctx); err != nil {
		l.Fatalf("Server Shutdown Failed: %+v", err)
	}
	l.Print("Server Exited Properly")

}

// exit after deferred cleanups have run or when work was cancelled on config load
func shutdown(exitFunc func(code int), e error) {
	if e != nil {
		var code int
		switch e {
		case ErrGotHelp:
			code = 3
		case ErrBadArgs:
			code = 2
		default:
			code = 1
			log.Printf("Run error: %s", e.Error())
		}
		exitFunc(code)
	}
}
