# ninja-panda ate your god
###
rwildcard=$(foreach d,$(wildcard $1*),$(call rwildcard,$d/,$2) $(filter $(subst *,%,$2),$d))

GO_SOURCES = $(call rwildcard,src,*.go)

INTEGRATION_SRCS = $(call rwildcard,integration,*.go)
PROTO_SOURCES = $(call rwildcard,proto,*.proto)

TAG_COMMIT := $(shell git rev-list --abbrev-commit --tags --max-count=1)

# `2>/dev/null` suppress errors and `|| true` suppress the error codes.
TAG := $(shell git describe --abbrev=0 --tags ${TAG_COMMIT} 2>/dev/null || true)

# here we strip the version prefix
VERSION := $(TAG:v%=%)

# get the latest commit hash in the short form
COMMIT := $(shell git rev-parse --short HEAD)

# get the latest commit date in the form of YYYYmmdd
DATE := $(shell git log -1 --format=%cd --date=format:"%Y%m%d")

# check if the version string is empty
ifeq ($(VERSION),)
	VERSION := $(COMMIT)-$(DATE)
endif

docker:
	@echo -n Creating docker image...
	@docker build -t ninja-panda .
	@echo done

build:
	@echo -n Building $(VERSION)...
	@CGO_ENABLED=0 GO111MODULE=auto go build -trimpath -ldflags "-s -w -X optm.com/ninja-panda/src.Version=$(VERSION)" src/cmd/ninjapanda/ninjapanda.go
	@echo done

dev: lint test build

test:
	@GO111MODULE=auto grc go test -v -gcflags="-e" -coverprofile=coverage.out ./...

test_integration: test_integration_cli test_integration_relay test_integration_general

test_integration_cli:
	docker network rm $$(docker network ls --filter name=ninjapanda-test --quiet) || true
	docker network create ninjapanda-test || true
	docker run -t --rm \
		--network ninjapanda-test \
		-v ~/.cache/np-integration-go:/go \
		-v $$PWD:$$PWD -w $$PWD \
		-v /var/run/docker.sock:/var/run/docker.sock golang:1 \
		go test -failfast -timeout 30m -count=1 -run IntegrationCLI ./...

test_integration_relay:
	docker network rm $$(docker network ls --filter name=ninjapanda-test --quiet) || true
	docker network create ninjapanda-test || true
	docker run -t --rm \
		--network ninjapanda-test \
		-v ~/.cache/np-integration-go:/go \
		-v $$PWD:$$PWD -w $$PWD \
		-v /var/run/docker.sock:/var/run/docker.sock golang:1 \
		go test -failfast -timeout 30m -count=1 -run IntegrationRELAY ./...

test_integration_general:
	docker network rm $$(docker network ls --filter name=ninjapanda-test --quiet) || true
	docker network create ninjapanda-test || true
	docker run -t --rm \
		--network ninjapanda-test \
		-v ~/.cache/np-integration-go:/go \
		-v $$PWD:$$PWD -w $$PWD \
		-v /var/run/docker.sock:/var/run/docker.sock golang:1 \
		go test -failfast -timeout 30m -count=1 -run IntegrationGeneral ./...

test_integration_v2_general:
	docker run \
		-t --rm \
		-v ~/.cache/np-integration-go:/go \
		--name ninjapanda-test-suite \
		-v $$PWD:$$PWD -w $$PWD/integration \
		-v /var/run/docker.sock:/var/run/docker.sock \
		golang:1 \
		go test  -failfast ./... -timeout 120m -parallel 8

coverprofile_func:
	@GO111MODULE=on go tool cover -func=coverage.out

coverprofile_html:
	@GO111MODULE=on go tool cover -html=coverage.out

lint:
	@echo -n Linting...
	@golangci-lint run --fix --timeout 10m src/
	@echo done

pretty:
	@echo -n Making things pretty...
	@prettier --write '**/**.{ts,js,md,yaml,yml,sass,css,scss,html}'
	@gofmt $(GO_SOURCES) > /dev/null
	@gofmt $(INTEGRATION_SRCS) > /dev/null
	@golines --max-len=88 --base-formatter=gofumpt -w $(GO_SOURCES)
	@golines --max-len=88 --base-formatter=gofumpt -w $(INTEGRATION_SRCS)
	@clang-format -style="{BasedOnStyle: Google, IndentWidth: 4, AlignConsecutiveDeclarations: true, AlignConsecutiveAssignments: true, ColumnLimit: 0}" -i $(PROTO_SOURCES)
	@echo done

proto-lint:
	@echo -n Linting...
	@GO111MODULE=on go run github.com/bufbuild/buf/cmd/buf lint proto # --debug
	@echo done

compress: build
	upx --brute ninjapanda

clean:
	@rm ninjapanda

generate:
	@echo -n Generating protos...
	@rm -rf gen
	@GO111MODULE=on go run github.com/bufbuild/buf/cmd/buf@v1.15 generate proto
	@cp -r gen/openapiv2/ninjapanda/v1/ninjapanda.swagger.json ./src/assets
	@echo ...done

install-plugins:
	GO111MODULE=on go install \
		github.com/grpc-ecosystem/grpc-gateway/v2/protoc-gen-grpc-gateway@v2.10 \
		github.com/grpc-ecosystem/grpc-gateway/v2/protoc-gen-openapiv2 \
		google.golang.org/protobuf/cmd/protoc-gen-go \
		google.golang.org/grpc/cmd/protoc-gen-go-grpc

