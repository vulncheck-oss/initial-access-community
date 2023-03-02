export GO111MODULE := on
export GOPRIVATE := github.com/vulncheck

all: check compile

check:
	go fmt
	golangci-lint run

compile:
	go build

install:
	go install

uninstall:
	go clean -i

clean:
	go clean
