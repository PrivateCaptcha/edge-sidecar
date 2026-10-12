.PHONY: build-edge-sidecar setup-edge-docker validate-edge-docker run-edge-docker stop-edge-docker reload-edge-docker logs-edge-docker
.PHONY: setup-e2e test-e2e

STAGE ?= dev
GIT_COMMIT ?= $(shell git rev-list -1 HEAD)
GOARCH ?= amd64
BUILD_OUTPUT ?= bin/edge-sidecar
DOCKER ?= docker
EXTRA_BUILD_FLAGS ?=
EXTRA_TEST_FLAGS ?=
EXTRA_E2E_FLAGS ?=
PLAYWRIGHT_INSTALL_FLAGS ?=
CGO_TEST_ENABLED ?= 0
EDGE_PROXY ?= caddy
EDGE_DOCKER_ENV ?= docker/.env
EDGE_DOCKER_COMPOSE_FILES ?= -f docker/docker-compose.$(EDGE_PROXY).yml
EDGE_DOCKER_FLAGS ?=
EDGE_DOCKER_LOG_FLAGS ?= -f

ifeq ($(filter caddy nginx,$(EDGE_PROXY)),)
$(error EDGE_PROXY must be caddy or nginx)
endif

vendors:
	go mod tidy
	go mod vendor

build: build-edge-sidecar

lint:
	$(GOPATH)/bin/golangci-lint run

format:
	$(GOPATH)/bin/golangci-lint fmt

test-unit:
	@env GOFLAGS="-mod=vendor" CGO_ENABLED=$(CGO_TEST_ENABLED) go test $(EXTRA_TEST_FLAGS) ./...

setup-e2e:
	npm ci
	npm exec -- playwright install $(PLAYWRIGHT_INSTALL_FLAGS) chromium

test-e2e:
	env EDGE_PROXY="$(EDGE_PROXY)" EDGE_DOCKER_ENV="$(EDGE_DOCKER_ENV)" npm run test:e2e -- $(EXTRA_E2E_FLAGS)

build-edge-sidecar:
	env GOFLAGS="-mod=vendor" CGO_ENABLED=0 GOOS=linux GOARCH=$(GOARCH) go build -ldflags="-s -w -X main.GitCommit=$(GIT_COMMIT)" $(EXTRA_BUILD_FLAGS) -o "$(BUILD_OUTPUT)" ./cmd/edge-sidecar

build-edge-sidecar-prod:
	env GOFLAGS="-mod=vendor" CGO_ENABLED=0 GOOS=linux GOARCH=$(GOARCH) go build -ldflags="-s -w -X main.GitCommit=$(GIT_COMMIT)" $(EXTRA_BUILD_FLAGS) -o bin/edge-sidecar-prod ./cmd/edge-sidecar

docker/.env: docker/.env.example
	test -e "$@" || cp -v docker/.env.example "$@"

setup-edge-docker: $(EDGE_DOCKER_ENV)

validate-edge-docker:
	@env GIT_COMMIT="$(GIT_COMMIT)" $(DOCKER) compose --env-file "$(EDGE_DOCKER_ENV)" $(EDGE_DOCKER_COMPOSE_FILES) config --quiet

run-edge-docker:
	$(if $(filter -d --detach% --wait --wait=%,$(EDGE_DOCKER_FLAGS)),$(error run-edge-docker requires attached foreground mode; detach and wait flags are not supported))
	@env GIT_COMMIT="$(GIT_COMMIT)" $(DOCKER) compose --env-file "$(EDGE_DOCKER_ENV)" $(EDGE_DOCKER_COMPOSE_FILES) up --build $(EDGE_DOCKER_FLAGS)

stop-edge-docker:
	@env GIT_COMMIT="$(GIT_COMMIT)" $(DOCKER) compose --env-file "$(EDGE_DOCKER_ENV)" $(EDGE_DOCKER_COMPOSE_FILES) down

reload-edge-docker:
ifeq ($(EDGE_PROXY),caddy)
	@env GIT_COMMIT="$(GIT_COMMIT)" $(DOCKER) compose --env-file "$(EDGE_DOCKER_ENV)" $(EDGE_DOCKER_COMPOSE_FILES) exec caddy caddy reload --config /etc/caddy/Caddyfile --adapter caddyfile
else
	@env GIT_COMMIT="$(GIT_COMMIT)" $(DOCKER) compose --env-file "$(EDGE_DOCKER_ENV)" $(EDGE_DOCKER_COMPOSE_FILES) exec nginx sh -ec '/docker-entrypoint.d/20-envsubst-on-templates.sh && nginx -t && nginx -s reload'
endif

logs-edge-docker:
	@env GIT_COMMIT="$(GIT_COMMIT)" $(DOCKER) compose --env-file "$(EDGE_DOCKER_ENV)" $(EDGE_DOCKER_COMPOSE_FILES) logs $(EDGE_DOCKER_LOG_FLAGS) privatecaptcha-authorizer $(EDGE_PROXY) app
