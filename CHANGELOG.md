# ChangeLog

## 0.26.0 (2023-07-12)

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

## 0.25.0 (2022-12-05)

### Chores

* CLI argument `--debug` changed to `--log.debug`
* build with go 1.18, update dependences
* move to github.com/LeKovr/go-kit
* use dcape-compose for `docker build` in `Makefile`
* support for pkg usage added (SetupRoutes, ProtectMiddleware)
* logging moved from gopkg.in/birkirb/loggers.v1 to github.com/go-logr/logr
