# ChangeLog

## 0.25.0 (2022-12-05)

### Chores

* CLI argument `--debug` changed to `--log.debug`
* build with go 1.18, update dependences
* move to github.com/LeKovr/go-kit
* use dcape-compose for `docker build` in `Makefile`
* support for pkg usage added (SetupRoutes, ProtectMiddleware)
* logging moved from gopkg.in/birkirb/loggers.v1 to github.com/go-logr/logr
