package main

import (
	"errors"
	"net/http"

	mapper "github.com/birkirb/loggers-mapper-logrus"
	"github.com/jessevdk/go-flags"
	"github.com/sirupsen/logrus"
	"gopkg.in/birkirb/loggers.v1"

	"github.com/dopos/narra"
)

// Config holds all config vars
type Config struct {
	Listen string `long:"listen" default:":8080" description:"Addr and port which server listens at"`
	Debug  bool   `long:"debug" description:"Show debug info"`

	AuthServer narra.Config `group:"Auth Service Options" namespace:"as" env-namespace:"AS"`
	FileServer FSConfig     `group:"File Service Options" namespace:"fs" env-namespace:"FS"`
}

var (
	// ErrGotHelp returned after showing requested help
	ErrGotHelp = errors.New("help printed")
	// ErrBadArgs returned after showing command args error message
	ErrBadArgs = errors.New("option error printed")
)

// setupConfig loads flags from args (if given) or command flags and ENV otherwise
func setupConfig(args ...string) (*Config, error) {
	cfg := &Config{}
	p := flags.NewParser(cfg, flags.Default)
	var err error
	if len(args) == 0 {
		_, err = p.Parse()
	} else {
		_, err = p.ParseArgs(args)
	}
	if err != nil {
		if e, ok := err.(*flags.Error); ok && e.Type == flags.ErrHelp {
			return nil, ErrGotHelp
		}
		return nil, ErrBadArgs
	}
	return cfg, nil
}

// setupLog creates logger
func setupLog(debug bool) loggers.Contextual {
	l := logrus.New()
	if debug {
		l.SetLevel(logrus.DebugLevel)
		l.SetReportCaller(true)
	}
	return &mapper.Logger{Logger: l} // Same as mapper.NewLogger(l) but without info log message
}

// setupRouter creates http mux
func setupRouter(srv *narra.Service) *http.ServeMux {
	mux := http.NewServeMux()
	mux.Handle("/auth", srv.AuthHandler())
	mux.Handle(srv.Config.CallBackURL, srv.Stage2Handler())
	mux.Handle("/401/", srv.Stage1Handler())
	return mux
}
