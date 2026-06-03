CLANG ?= clang
TARGET ?= kernel_tracer

all:
	$(CLANG) -O2 -target bpf -c $(TARGET).c -o $(TARGET).o

clean:
	rm -f $(TARGET).o

