#!/bin/bash
set -e

goVersion="1.12"

dockerfile="
FROM golang:${goVersion}
RUN dpkg --add-architecture mips
RUN apt-get update
RUN apt-get install -y --no-install-recommends libpcap-dev:mips crossbuild-essential-mips && rm -rf /var/lib/apt/lists/*
"

tmpDockerfile="$(mktemp)"

echo "${dockerfile}" > "${tmpDockerfile}"

docker build --quiet --pull --file "${tmpDockerfile}" --tag golang-mips:latest .
docker volume create go-cache 
docker run \
    -it \
    -v "go-cache:/gocache" \
    -v "$(pwd):/pcap_exporter" \
    -w "/pcap_exporter" \
    -e GOCACHE="/gocache" \
    -e CC="mips-linux-gnu-gcc" \
    -e CGO_ENABLED="1" \
    -e GOOS="linux" \
    -e GOARCH="mips" \
    -e CGO_LDFLAGS="-L/usr/include/pcap" \
    golang-mips:latest \
    go build -o pcap_exporter
