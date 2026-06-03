FROM golang:1.26-alpine AS build
# git lets `go build` embed the VCS stamp (commit + time + dirty) so an
# image built with no build-args still self-identifies by commit.
RUN apk add --no-cache git
WORKDIR /src
COPY . .
# Optional release overrides; the publish workflow passes a real semver on
# tags. Left empty, the binary falls back to the embedded VCS stamp.
ARG VERSION=
ARG COMMIT=
ARG DATE=
RUN git config --global --add safe.directory /src && \
    go build -ldflags "-X main.version=${VERSION} -X main.commit=${COMMIT} -X main.date=${DATE}" -o /atreoagent ./cmd/atreoagent

FROM alpine:3.23
RUN apk add --no-cache ca-certificates iproute2 wireguard-tools iptables
COPY --from=build /atreoagent /usr/local/bin/
VOLUME /var/lib/atreoagent
ENTRYPOINT ["atreoagent"]
CMD ["run"]
