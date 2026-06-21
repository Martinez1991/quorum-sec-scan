# syntax=docker/dockerfile:1

# ─────────────────────────────────────────────────────────────────────────────
# quorum:slim — only the orchestrator. Scanners are expected to already be on
# PATH (mounted in, or present in the CI runner). Tiny image, BYO-scanners.
# ─────────────────────────────────────────────────────────────────────────────

FROM golang:1.26-alpine AS build
WORKDIR /src
# Cache modules first.
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ARG VERSION=dev
RUN CGO_ENABLED=0 go build -trimpath \
    -ldflags "-s -w -X main.version=${VERSION}" \
    -o /out/quorum ./cmd/quorum

FROM alpine:3.20
RUN apk add --no-cache ca-certificates
COPY --from=build /out/quorum /usr/local/bin/quorum
# Bundle the default crosswalks so they ship with the image.
COPY crosswalk /opt/quorum/crosswalk
WORKDIR /work
ENTRYPOINT ["quorum"]
CMD ["--help"]
