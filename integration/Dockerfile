FROM golang:1.27-bookworm AS build

WORKDIR /src
COPY go.mod go.sum ./
# A mis-sized Docker bridge can drop Go's larger hybrid-TLS ClientHello. Keep
# the Go default first, then fall back to classical TLS for this checksum-
# verified dependency fetch only. This does not affect the NestWG runtime.
RUN go mod download || GODEBUG=tlsmlkem=0 go mod download
COPY . .
RUN CGO_ENABLED=0 go build -tags nestwg_integration -trimpath -o /out/nestwg ./cmd/nestwg

FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        ca-certificates \
        iproute2 \
        iptables \
        iputils-ping \
        kmod \
        tcpdump \
        util-linux \
        wireguard-tools \
    && rm -rf /var/lib/apt/lists/*

COPY --from=build /out/nestwg /usr/local/bin/nestwg
COPY integration/lab.sh /usr/local/bin/nestwg-lab

ENTRYPOINT ["/usr/local/bin/nestwg-lab"]
