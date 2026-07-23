# Build piclin PIC shellcode with the Piclang compiler

PICC    ?= ../../picc
SRC     := piclin.pic
OUT     := piclin.bin
MAP     := piclin.map

.PHONY: all clean test

all: $(OUT)

$(PICC):
	$(MAKE) -C ../.. build

$(OUT): $(SRC) $(PICC)
	$(PICC) $(SRC) -o $(OUT) -map $(MAP) -S

clean:
	rm -f $(OUT) $(MAP) test.txt

# Requires a loader that mmaps RWX and calls offset 0.
# Prefers ../../harness/run_shellcode or ../../../piclin/bin/loader
test: $(OUT)
	@if [ -x ../../../piclin/bin/loader ]; then \
		rm -f test.txt; \
		../../../piclin/bin/loader $(OUT); \
	elif [ -x ../../harness/run_shellcode ]; then \
		rm -f test.txt; \
		../../harness/run_shellcode $(OUT); \
	else \
		echo "build a loader first (piclin bin/loader or piclang harness)"; exit 1; \
	fi
	@grep -qx success test.txt && echo "[+] piclin PoC OK" || (echo "FAIL"; exit 1)
