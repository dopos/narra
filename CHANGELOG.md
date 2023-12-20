# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](http://keepachangelog.com/)
and this project adheres to [Semantic Versioning](http://semver.org/).

## [0.26.3] - 2023-12-20

### Update deps

* upd: build app for go 1.21
* add: build docker for arm64v8
* Bump github.com/google/uuid from 1.4.0 to 1.5.0
* Bump golang.org/x/oauth2 from 0.13.0 to 0.15.0

## [0.26.1] - 2023-11-13

### Update deps

* upd: move from github.com/patrickmn/go-cache to zgo.at/zcache/v2
* Bump golang.org/x/sync from 0.3.0 to 0.5.0
* bump golang.org/x/net to 0.17.0
* Bump github.com/google/uuid from 1.3.0 to 1.4.0
* Bump github.com/go-logr/logr from 1.2.4 to 1.3.0
* Bump golang.org/x/oauth2 from 0.10.0 to 0.13.0

## [0.26.0] - 2023-07-12

### Chores

* `make` and `docker` parts refactored like webtail
* fixed golangci-lint notes (most of)
* add app version check
* add golang actions (golangci-lint do not breaks on errors yet)
* Create dependabot.yml
* add golangci.yml

### Update deps

* github action versions
* Bump github.com/LeKovr/go-kit/logger from 0.2.1 to 0.2.2
* Bump golang.org/x/sync from 0.1.0 to 0.3.0
* Bump golang.org/x/oauth2 from 0.6.0 to 0.10.0
* Bump github.com/LeKovr/go-kit/config from 0.2.0 to 0.2.1

## [0.25.0] - 2022-12-05

### Chores

* CLI argument `--debug` changed to `--log.debug`
* build with go 1.18, update dependences
* move to github.com/LeKovr/go-kit
* use dcape-compose for `docker build` in `Makefile`
* support for pkg usage added (SetupRoutes, ProtectMiddleware)
* logging moved from gopkg.in/birkirb/loggers.v1 to github.com/go-logr/logr
