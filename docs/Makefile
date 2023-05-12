# Don't touch these variables
export GO111MODULE := on
export GOPRIVATE := github.com/vulncheck

# HACK: "Detect" exploit and payload filenames
exploit_files := $(wildcard cve-*.go)
payload_files := $(wildcard *_shell.go)

# Don't touch these variables
exploit_os := $(shell go env GOOS)
exploit_arch := $(shell go env GOARCH)

# NOTE: Don't forget to update these variables
payload_os := windows
payload_arch := amd64

# Output directory for binaries
output_dir := build

all: format lint compile

format:
	gofmt -d -w $(exploit_files) $(payload_files)

lint:
	$(foreach exploit_file,$(exploit_files),golangci-lint run --fix $(exploit_file);)
ifneq ($(payload_files),)
	$(foreach payload_file,$(payload_files),golangci-lint run --fix $(payload_file);)
endif

compile: exploit payload

exploit: suffix = $(if $(findstring windows,$(exploit_os)),.exe)
exploit:
	$(foreach exploit_file,$(exploit_files),GOOS=$(exploit_os) GOARCH=$(exploit_arch) \
		go build -o $(output_dir)/$(exploit_file:.go=)_$(exploit_os)-$(exploit_arch)$(suffix) $(exploit_file);)

payload: suffix = $(if $(findstring windows,$(payload_os)),.exe)
payload:
ifneq ($(payload_files),)
	$(foreach payload_file,$(payload_files),GOOS=$(payload_os) GOARCH=$(payload_arch) \
		go build -o $(output_dir)/$(payload_file:.go=)_$(payload_os)-$(payload_arch)$(suffix) $(payload_file);)
endif

clean:
	rm -rf $(output_dir)

# GOOS=darwin GOARCH=amd64
darwin-amd64: exploit_os := darwin
darwin-amd64: exploit_arch := amd64
darwin-amd64: all

# GOOS=darwin GOARCH=arm64
darwin-arm64: exploit_os := darwin
darwin-arm64: exploit_arch := arm64
darwin-arm64: all

# GOOS=linux GOARCH=amd64
linux-amd64: exploit_os := linux
linux-amd64: exploit_arch := amd64
linux-amd64: all

# GOOS=linux GOARCH=arm64
linux-arm64: exploit_os := linux
linux-arm64: exploit_arch := arm64
linux-arm64: all

# GOOS=windows GOARCH=amd64
windows-amd64: exploit_os := windows
windows-amd64: exploit_arch := amd64
windows-amd64: all

# GOOS=windows GOARCH=arm64
windows-arm64: exploit_os := windows
windows-arm64: exploit_arch := arm64
windows-arm64: all
