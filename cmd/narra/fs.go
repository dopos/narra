package main

import (
	"net/http"
	"regexp"

	"github.com/dopos/narra"
	"gopkg.in/birkirb/loggers.v1"
)

// FSConfig holds fileserver config
type FSConfig struct {
	Path           string `long:"path" default:"" description:"Path to static files (default: don't serve static)"`
	ProtectPattern string `long:"protect" default:"" description:"Regexp for pages which require auth"`
}

// FSHandler server static pages with auth checking for protected prefixes
func FSHandler(cfg FSConfig, log loggers.Contextual, srv *narra.Service) http.Handler {
	re := regexp.MustCompile(cfg.ProtectPattern)
	fs := http.FileServer(http.Dir(cfg.Path))
	fn := func(w http.ResponseWriter, r *http.Request) {
		log.Debugf("Request for %s", r.RequestURI)
		if cfg.ProtectPattern != "" && re.MatchString(r.RequestURI) {
			log.Debugf("Page is protected")
			scheme := "http"
			if r.TLS != nil {
				scheme += "s"
			}
			r.Header.Set("X-Forwarded-Proto", scheme)
			r.Header.Set("X-Forwarded-Host", r.Host)
			r.Header.Set("X-Forwarded-Uri", r.RequestURI)
			if !srv.AuthIsOK(w, r) {
				return
			}
			w.Header().Set("Last-Modified", "")
		}
		fs.ServeHTTP(w, r)
	}
	return http.HandlerFunc(fn)
}
