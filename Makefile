## Make file for CTD project
## Make sure your Makefile uses proper tabs and view if it is run cat -e -t -v Makefile
## TODO: Add gosec https://github.com/securego/gosec

PROJECT_NAME := "privki"
PKG := "$(PROJECT_NAME)"
PKG_LIST := $(shell go list ${PKG}/... | grep -v /vendor/)
GO_FILES := $(shell find . -name '*.go')

VERSION := $(shell cat version.txt)
TIME := $(shell date)

PLATFORM=local
GO111MODULE=on


DOCKER_BUILDKIT=1

LINTERS := \
        github.com/golangci/golangci-lint/cmd/golangci-lint@v1.27.0 \
        github.com/kisielk/errcheck \
        honnef.co/go/tools/cmd/staticcheck

OTHERS := \
        github.com/git-chglog/git-chglog/cmd/git-chglog

.PHONY: all check dep build clean lint echo help install

all: build

check: ## Check if basic requirements are installed
	@command -v go >/dev/null 2>&1 || { echo >&2 "I require golang version 1.14 but it's not installed.  Aborting."; exit 1; }

lint: check ## Lint the files (Lints both protobuf and golang files)
	@golangci-lint run --timeout 10m0s ${PKG_LIST}

test: check ## Run unittests
	@go test -short -v ${PKG_LIST}

race: check dep ## Run data race detector
	@go test -race -short ${PKG_LIST}

msan: check dep ## Run memory sanitizer
	@go test -msan -short ${PKG_LIST}


dep: ## Get the dependencies
	@go get -v -d  ./...
	@go get -v $(LINTERS)
	@go get -v $(OTHERS)

build: check dep ## Build the binary file
	@echo "  >  Building sfcert for $(PLATFORM)"
	@go build -ldflags="-X 'version/version.BuildTime=${TIME}' -X 'version/version.BuildVersion=${VERSION}'" -o bin/${PROJECT_NAME}

docker:
	@docker build . --target bin --output bin/${PROJECT_NAME} --platform ${PLATFORM}

format: dep
	@gofmt -e -s -d .

clean: ## Remove previous build
	@rm -f $(PROJECT_NAME)
	@rm -f bin/$(PROJECT_NAME)

install: check dep
	@go install 

help: ## Display this help screen
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-30s\033[0m %s\n", $$1, $$2}'

changelog:
	git-chglog -o CHANGELOG.md --next-tag 'semtag final -s minor -o'
