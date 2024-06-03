# Builder image
FROM docker.io/golang:1.21-alpine AS build
ENV GOPATH /go
WORKDIR /go/src/ninja-panda

RUN mkdir -p /var/lib/ninjapanda
RUN mkdir /etc/ninjapanda

COPY go.mod go.sum /go/src/ninja-panda/
RUN apk add gcc musl-dev
COPY core . 

RUN GO111MODULE=on go mod download

COPY . .

ARG VERSION_LONG=""
ENV VERSION_LONG=$VERSION_LONG
ARG VERSION_SHORT=""
ENV VERSION_SHORT=$VERSION_SHORT
ARG VERSION_GIT_HASH=""
ENV VERSION_GIT_HASH=$VERSION_GIT_HASH
ARG TARGETARCH

RUN GO111MODULE=on go build \
	 -ldflags "-s -w -X optm.com/ninja-panda/src.Version=$VERSION_LONG" \
	 -v /go/src/ninja-panda/src/cmd/ninjapanda

RUN strip /go/src/ninja-panda/ninjapanda
RUN test -e /go/src/ninja-panda/ninjapanda

# Production image
FROM docker.io/alpine:latest

COPY --from=build /go/src/ninja-panda/ninjapanda /bin/ninjapanda
COPY --from=build /go/src/ninja-panda/config-docker.yaml /etc/ninjapanda/config.yaml

ADD scripts/check_ninjapanda.sh /bin/check_ninjapanda
RUN chmod 755 /bin/check_ninjapanda


ENV TZ UTC

EXPOSE 8080/tcp
CMD ["ninjapanda", "serve"]
