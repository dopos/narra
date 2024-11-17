## narra Makefile:
## nginx auth_request via remote api
#:

SHELL          = /bin/sh
CFG           ?= .env
PRG           ?= $(shell basename $$PWD)
PRG_DEST      ?= $(PRG)
# -----------------------------------------------------------------------------
# Build config

GO            ?= go
GOLANG_VERSION = 1.21-alpine3.18

SOURCES        = $(shell find . -maxdepth 3 -mindepth 1 -path ./var -prune -o -name '*.go')
APP_VERSION   ?= $(shell git describe --tags --always)
# Last project tag (used in `make changelog`)
RELEASE       ?= $(shell git describe --tags --abbrev=0 --always)
# Repository address (compiled into main.repo)
REPO          ?= $(shell git config --get remote.origin.url)

TARGETOS      ?= linux
TARGETARCH    ?= amd64
LDFLAGS       := -s -w -extldflags '-static'

OS            ?= linux
ARCH          ?= amd64
ALLARCH       ?= "linux/amd64 linux/386 darwin/amd64 linux/arm linux/arm64"
DIRDIST       ?= dist

# Path to golang package docs
GODOC_REPO    ?= github.com/dopos/$(PRG)
# App docker image
DOCKER_IMAGE  ?= ghcr.io/dopos/$(PRG)

# -----------------------------------------------------------------------------
# Docker image config

# Hardcoded in docker-compose.yml service name
DC_SERVICE    ?= app

# Docker-compose project name (container name prefix)
PROJECT_NAME  ?= $(PRG)

# dcape network connect to, must be set in .env
#DCAPE_NET     ?= dcape_default

# docker app for change inside containers
DOCKER_BIN    ?= docker

# -----------------------------------------------------------------------------
# App config

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

# -----------------------------------------------------------------------------

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
#DCAPE_NET=$(DCAPE_NET)

endef
export CONFIG

-include $(CFG)
export

.PHONY: all api dep build run lint test up up-db down clean help

all: help

# ------------------------------------------------------------------------------
## Compile operations
#:

## Build app
build: $(PRG)

$(PRG): $(SOURCES)
	GOOS=$(OS) GOARCH=$(ARCH) $(GO) build -v -o $@ -ldflags \
	  "-X main.version=$(APP_VERSION) -X main.repo=$(REPO)" ./cmd/$@

## Build like docker image from scratch
build-standalone:
	CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} \
	  $(GO) build -a -o $(PRG_DEST) \
	  -ldflags "${LDFLAGS}-X main.version=$(APP_VERSION) -X main.repo=$(REPO)" \
	  ./cmd/$(PRG)

## Build & run app
run: $(PRG)
	@echo Open http://$(APP_SITE):8080
	./$(PRG) --as.my_url http://$(APP_SITE):8080 --fs.path ./test --fs.protect /private/ \
	 --as.do401  --log.debug --as.cookie_name=narra_local

## Format go sources
fmt:
	$(GO) fmt ./...

## Run lint
lint:
	@which golint > /dev/null || go install golang.org/x/lint/golint@latest
	@golint ./...

## Run golangci-lint
ci-lint:
	@golangci-lint run ./...

## Run vet
vet:
	@$(GO) vet ./...

## Run tests
test: lint vet coverage.out

# internal target
coverage.out: $(SOURCES)
	GIN_MODE=release $(GO) test -tags test -race -covermode=atomic -coverprofile=$@ ./...

## Open coverage report in browser
cov-html: cov
	$(GO) tool cover -html=coverage.out

## Show code coverage per func
cov-func: coverage.out
	$(GO) tool cover -func coverage.out

## Show total code coverage
cov-total: coverage.out
	@$(GO) tool cover -func coverage.out | grep total: | awk '{print $$3}'

## Clean coverage report
cov-clean:
	rm -f coverage.*

## count LoC without generated code
cloc:
	@cloc --md --fullpath --exclude-dir=zgen --not-match-f=./proto/README.md \
	  --not-match-f=static/js/api.js --not-match-f=static/js/service.swagger.json  .

## Changes from last tag
clog:
	@echo Changes since $(RELEASE)
	@echo
	@git log $(RELEASE)..@ --pretty=format:"* %s"


# ------------------------------------------------------------------------------
## Docker operations
#:

docker: $(PRG)
	docker build -t $(PRG) .

ALLARCH_DOCKER ?= "linux/arm/v7,linux/arm64"

docker-multi:
	time docker buildx build --platform $(ALLARCH_DOCKER) -t $(DOCKER_IMAGE):$(APP_VERSION) --push .

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

dc:
	docker compose -p $$PROJECT_NAME $(CMD)

## Build docker image
docker-build: CMD=build --no-cache $(DC_SERVICE)
docker-build: dc

## Remove docker image & temp files
docker-clean:
	[ "$$($(DOCKER_BIN) images -q $(DC_IMAGE) 2> /dev/null)" = "" ] || $(DOCKER_BIN) rmi $(DC_IMAGE)


# ------------------------------------------------------------------------------
## Other
#:

$(CFG).sample:
	@[ -f $@ ] || { echo "$$CONFIG" > $@ ; echo "Warning: Created default $@" ; }

## Generate config sample
conf: $(CFG).sample ## Create initial config
	@true

clean: ## Remove previous builds
	@rm -f $(PRG)

# This code handles group header and target comment with one or two lines only
## list Makefile targets
## (this is default target)
help:
	@grep -A 1 -h "^## " $(MAKEFILE_LIST) \
  | sed -E 's/^--$$// ; /./{H;$$!d} ; x ; s/^\n## ([^\n]+)\n(## (.+)\n)*(.+):(.*)$$/"    " "\4" "\1" "\3"/' \
  | sed -E 's/^"    " "#" "(.+)" "(.*)"$$/"" "" "" ""\n"\1 \2" "" "" ""/' \
  | xargs printf "%s\033[36m%-15s\033[0m %s %s\n"
