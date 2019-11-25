package main

import (
	"io"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	mapper "github.com/birkirb/loggers-mapper-logrus"
	"github.com/jessevdk/go-flags"
	"github.com/sirupsen/logrus"
	"github.com/sirupsen/logrus/hooks/test"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSetupConfig(t *testing.T) {
	cfg, err := setupConfig("--listen", "80")
	require.NoError(t, err)
	assert.NotNil(t, cfg)

	_, err = setupConfig("-h")
	assert.Equal(t, ErrGotHelp, err)

	_, err = setupConfig()
	assert.Equal(t, ErrBadArgs, err)
}

func TestSetupLog(t *testing.T) {
	mode := gin.Mode()
	gin.SetMode(gin.DebugMode)
	l := setupLog()
	if mode != gin.DebugMode {
		gin.SetMode(mode)
	}
	assert.NotNil(t, l)
}

func TestHandlers(t *testing.T) {
	// Fill config with default values
	cfg := &Config{}
	p := flags.NewParser(cfg, flags.Default)
	_, err := p.ParseArgs([]string{"--html"})
	require.NoError(t, err)

	l, hook := test.NewNullLogger()
	l.SetLevel(logrus.DebugLevel)
	log := mapper.NewLogger(l)
	hook.Reset()

	cfg.Img.Config.Dir, err = ioutil.TempDir("", "img")
	require.NoError(t, err)
	defer os.RemoveAll(cfg.Img.Config.Dir)
	srv := setupRouter(cfg, log)

	tests := []struct {
		name    string
		method  string
		url     string
		reader  io.Reader
		ctype   string
		code    int
		message string
	}{
		{"MultiPart", "POST", "/upload", strings.NewReader(`fake data`), "multipart/form-data",
			http.StatusBadRequest, "no multipart boundary param in Content-Type"},
		{"Base64", "POST", "/upload", strings.NewReader(`{"data":"data:image/png;base64,iVBORw0K","name":"file.ext"}`), "application/json",
			http.StatusUnsupportedMediaType, "Unsupported media type"},
		{"URL", "GET", "/upload?url=/img/xx.png", nil, "",
			http.StatusServiceUnavailable, "Get /img/xx.png: unsupported protocol scheme \"\""},
		{"BadCType", "POST", "/upload", nil, "application",
			http.StatusNotImplemented, "Content type (application) not supported"},
	}
	for _, tt := range tests {
		w := httptest.NewRecorder()
		req, _ := http.NewRequest(tt.method, tt.url, tt.reader)
		if tt.ctype != "" {
			req.Header.Set("Content-Type", tt.ctype)
		}
		srv.ServeHTTP(w, req)
		assert.Equal(t, tt.code, w.Code, tt.name)
		assert.Equal(t, tt.message, w.Body.String(), tt.name)
	}
}
