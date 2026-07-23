.PHONY: all build test examples clean harness

all: build examples

build:
	go build -o picc ./cmd/picc

test:
	go test ./...

examples: build
	./picc examples/hello.pic -o examples/hello.bin -S
	./picc examples/agent_skeleton.pic -o examples/agent_skeleton.bin -S
	./picc examples/peb_walk.pic -o examples/peb_walk.bin -map examples/peb_walk.map -S

harness:
	cc -O2 -o harness/run_shellcode harness/run_shellcode.c

run-hello: build harness
	./picc examples/hello.pic -o /tmp/piclang_hello.bin
	./harness/run_shellcode /tmp/piclang_hello.bin

clean:
	rm -f picc examples/*.bin examples/*.map harness/run_shellcode
