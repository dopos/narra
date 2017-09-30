SHELL         = /bin/bash
BIN = narra
CFG ?= .env
SOURCES   ?= *.go

SIGN_KEY   ?= $(shell < /dev/urandom tr -dc A-Za-z0-9 | head -c32; echo)
CRYPT_KEY  ?= $(shell < /dev/urandom tr -dc A-Za-z0-9 | head -c32; echo)

-include $(CFG)
export

$(BIN): $(SOURCES)
	go generate
	go build

run: $(BIN)
	echo ./$(BIN) --gitea_host http://git.dev.lan --cookie_sign $(SIGN_KEY) --cookie_crypt $(CRYPT_KEY)

docker: $(BIN)
	docker build -t $(BIN) .

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
	  docker/compose:1.14.0 \
	  -p $$PROJECT_NAME \
	  $(CMD)
