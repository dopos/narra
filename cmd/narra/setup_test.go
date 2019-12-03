package main

import (
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
	l := setupLog(true)
	assert.NotNil(t, l)
}

func TestHandlers(t *testing.T) {
	// Fill config with default values
	cfg := &Config{}
	p := flags.NewParser(cfg, flags.Default)
	_, err := p.ParseArgs([]string{"--listen"})
	require.NoError(t, err)

	l, hook := test.NewNullLogger()
	l.SetLevel(logrus.DebugLevel)
	log := mapper.NewLogger(l)
	require.NotNil(t, log)
	hook.Reset()
}
