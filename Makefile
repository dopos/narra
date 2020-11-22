SHELL          = /bin/sh
GO            ?= go
CFG           ?= .env
PRG           ?= $(shell basename $$PWD)

VERSION       ?= $(shell git describe --tags --always)
SOURCES       ?= *.go cmd/*/*.go

APP_ROOT      ?= .
APP_SITE      ?= $(PRG).dev.lan
APP_PROTO     ?= http

AS_TYPE       ?= gitea
AS_HOST       ?= http://gitea:8080
AS_TEAM       ?= dcape
AS_CLIENT_ID  ?= you_should_get_id_from_as
AS_CLIENT_KEY ?= you_should_get_key_from_as

AS_COOKIE_SIGN_KEY   ?= $(shell < /dev/urandom tr -dc A-Za-z0-9 | head -c32; echo)
AS_COOKIE_CRYPT_KEY  ?= $(shell < /dev/urandom tr -dc A-Za-z0-9 | head -c32; echo)

# docker-compose version
DC_VER        ?= 1.27.4

# Docker-compose project name (container name prefix)
PROJECT_NAME  ?= $(PRG)

# dcape network connect to, must be set in .env
DCAPE_NET     ?= dcape_default

define CONFIG
# ------------------------------------------------------------------------------
# application config file, generated by make $(CFG)

# narra hostname
# hardcoded in nginx.conf as narra.dev.lan
APP_SITE=$(APP_SITE)
APP_PROTO=$(APP_PROTO)

AS_TYPE=$(AS_TYPE)
AS_HOST=$(AS_HOST)
AS_TEAM=$(AS_TEAM)
AS_CLIENT_ID=$(AS_CLIENT_ID)
AS_CLIENT_KEY=$(AS_CLIENT_KEY)
AS_COOKIE_SIGN_KEY=$(AS_COOKIE_SIGN_KEY)
AS_COOKIE_CRYPT_KEY=$(AS_COOKIE_CRYPT_KEY)

# Docker-compose project name (container name prefix)
PROJECT_NAME=$(PROJECT_NAME)
# dcape network attach to
DCAPE_NET=$(DCAPE_NET)

endef
export CONFIG

-include $(CFG)
export

.PHONY: all api dep build run lint test up up-db down clean help

all: help

$(PRG): $(SOURCES)
	$(GO) build -ldflags "-X main.version=$(VERSION)" ./cmd/$(PRG)

run: $(PRG)
	./$(PRG) --as.my_url http://$(APP_SITE):8080  --debug

## Format go sources
fmt:
	$(GO) fmt ./...

## Run vet
vet:
	$(GO) vet ./...

## Run linter
lint:
	golint ./...

## Run more linters
lint-more:
	golangci-lint run ./...

## Run tests and fill coverage.out
cov: coverage.out

# internal target
coverage.out: $(SOURCES)
	GIN_MODE=release $(GO) test -test.v -test.race -coverprofile=$@ -covermode=atomic ./...

#	GIN_MODE=release $(GO) test -race -coverprofile=$@ -covermode=atomic -v ./...

## Open coverage report in browser
cov-html: cov
	$(GO) tool cover -html=coverage.out

## Clean coverage report
cov-clean:
	rm -f coverage.*


docker: $(PRG)
	docker build -t $(PRG) .

# ------------------------------------------------------------------------------

## старт контейнеров
up:
up: CMD=up -d
up: dc

## рестарт контейнеров
reup:
reup: CMD=up --force-recreate -d
reup: dc

## остановка и удаление всех контейнеров
down:
down: CMD=rm -f -s
down: dc

# ------------------------------------------------------------------------------

# $$PWD используется для того, чтобы текущий каталог был доступен в контейнере по тому же пути
# и относительные тома новых контейнеров могли его использовать
## run docker-compose
dc: docker-compose.yml
	@docker run --rm  \
	  -v /var/run/docker.sock:/var/run/docker.sock \
	  -v $$PWD:$$PWD \
	  -w $$PWD \
	  -e APP_ROOT \
	  docker/compose:$(DC_VER) \
	  -p $$PROJECT_NAME \
	  $(CMD)

$(CFG).sample:
	@[ -f $@ ] || { echo "$$CONFIG" > $@ ; echo "Warning: Created default $@" ; }

conf: $(CFG).sample ## Create initial config
	@true

clean: ## Remove previous builds
	@rm -f $(PRG)

help: ## Display this help screen
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' Makefile | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-30s\033[0m %s\n", $$1, $$2}'
