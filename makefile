all:
	go test -v ./...
	GOBIN=${PWD} go install -v ./...
	@echo "built demo program './seconfig-tester'"
