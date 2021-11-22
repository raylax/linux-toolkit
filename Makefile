GO=go
GOBUILD=$(GO) build -ldflags="-s -w" -a -v -o

all: clean build

build:
	GOOS=linux GOARCH=amd64 $(GOBUILD) bin/ltk_amd64
	GOOS=linux GOARCH=arm64 $(GOBUILD) bin/ltk_arm64
	GOOS=linux GOARCH=arm $(GOBUILD) bin/ltk_arm
	@chmod +x bin/ltk*
	@cp bin/ltk_amd64 bin/ltk

clean:
	@rm -rf bin/ltk*