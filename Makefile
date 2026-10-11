.PHONY: build-edge-sidecar setup-edge-docker run-edge-docker stop-edge-docker reload-edge-docker logs-edge-docker
.PHONY: setup-e2e test-e2e

STAGE ?= dev
GIT_COMMIT ?= $(shell git rev-list -1 HEAD)
DOCKER ?= docker
EXTRA_BUILD_FLAGS ?=
EXTRA_TEST_FLAGS ?=
EXTRA_E2E_FLAGS ?=
PLAYWRIGHT_INSTALL_FLAGS ?=
CGO_TEST_ENABLED ?= 0
EDGE_DOCKER_ENV ?= docker/.env
EDGE_DOCKER_COMPOSE_FILES ?= -f docker/docker-compose.yml
EDGE_DOCKER_FLAGS ?=
EDGE_DOCKER_LOG_FLAGS ?= -f

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
	env EDGE_DOCKER_ENV="$(EDGE_DOCKER_ENV)" npm run test:e2e -- $(EXTRA_E2E_FLAGS)

build-edge-sidecar:
	env GOFLAGS="-mod=vendor" CGO_ENABLED=0 go build -ldflags="-s -w -X main.GitCommit=$(GIT_COMMIT)" $(EXTRA_BUILD_FLAGS) -o bin/edge-sidecar ./cmd/edge-sidecar
docker/.env: docker/.env.example
	test -e "$@" || cp -v docker/.env.example "$@"

setup-edge-docker: $(EDGE_DOCKER_ENV)

run-edge-docker:
	@env GIT_COMMIT="$(GIT_COMMIT)" $(DOCKER) compose --env-file "$(EDGE_DOCKER_ENV)" $(EDGE_DOCKER_COMPOSE_FILES) up --build $(EDGE_DOCKER_FLAGS)

stop-edge-docker:
	$(DOCKER) compose --env-file "$(EDGE_DOCKER_ENV)" $(EDGE_DOCKER_COMPOSE_FILES) down

reload-edge-docker:
	$(DOCKER) compose --env-file "$(EDGE_DOCKER_ENV)" $(EDGE_DOCKER_COMPOSE_FILES) exec caddy caddy reload --config /etc/caddy/Caddyfile --adapter caddyfile

logs-edge-docker:
	$(DOCKER) compose --env-file "$(EDGE_DOCKER_ENV)" $(EDGE_DOCKER_COMPOSE_FILES) logs $(EDGE_DOCKER_LOG_FLAGS) privatecaptcha-authorizer caddy
