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
payload_oses := linux windows
payload_archs := amd64 arm arm64

# Output directory for binaries
output_dir := build

all: format lint compile

format:
	gofmt -d -w $(exploit_files) $(payload_files)

lint:
	$(foreach file,$(exploit_files),golangci-lint run --fix $(file);)
ifneq ($(payload_files),)
	$(foreach file,$(payload_files),golangci-lint run --fix $(file);)
endif

compile: exploit payload extra
	@find $(output_dir)/*

exploit: ext = $(if $(findstring windows,$(exploit_os)),.exe)
exploit:
	$(foreach file,$(exploit_files),GOOS=$(exploit_os) GOARCH=$(exploit_arch) \
		go build -o $(output_dir)/$(file:.go=)_$(exploit_os)-$(exploit_arch)$(ext) $(file);)

payload:
ifneq ($(payload_files),)
	$(foreach file,$(payload_files),$(foreach os,$(payload_oses),$(foreach arch,$(payload_archs),GOOS=$(os) GOARCH=$(arch) \
		go build -ldflags "-s -w" -o $(output_dir)/$(file:.go=)_$(os)-$(arch)$(if $(findstring windows,$(os)),.exe) $(file);)))
endif

# Add extra stuff to this recipe
extra:

clean:
	@rm -rfv $(output_dir)

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
