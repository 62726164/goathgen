PROGRAM = goathgen
SOURCE = *.go

build:
	go build -o $(PROGRAM) $(SOURCE)

test:
	go test -v ../goathgen_test.go

clean:
	rm -f $(PROGRAM)

fmt:
	gofmt -w $(SOURCE)

vet:
	go vet $(SOURCE)
