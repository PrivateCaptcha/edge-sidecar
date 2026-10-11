FROM golang:1.27.2 AS builder

WORKDIR /app
COPY go.mod go.sum ./
COPY vendor ./vendor
COPY pkg ./pkg
COPY cmd/edge-sidecar ./cmd/edge-sidecar

RUN --mount=type=cache,target=/root/.cache/go-build,sharing=locked \
    env GOFLAGS=-mod=vendor CGO_ENABLED=0 go build -ldflags="-s -w" -o bin/edge-sidecar ./cmd/edge-sidecar

FROM gcr.io/distroless/static-debian12:nonroot

COPY --from=builder /app/bin/edge-sidecar /app/edge-sidecar
ENV PC_HOST=0.0.0.0
ENV PC_PORT=8080
EXPOSE 8080
ENTRYPOINT ["/app/edge-sidecar"]
