CLANG ?= clang
MULTIARCH ?= $(shell cc -print-multiarch)

all: ingress.bpf.o pass.bpf.o

ingress.bpf.o: ingress.bpf.c
	$(CLANG) -O2 -g -target bpf -I/usr/include/$(MULTIARCH) -c $< -o $@

pass.bpf.o: ingress.bpf.c
	$(CLANG) -O2 -g -target bpf -I/usr/include/$(MULTIARCH) -DPASS_ONLY -c $< -o $@

clean:
	rm -f ingress.bpf.o pass.bpf.o

.PHONY: all clean
