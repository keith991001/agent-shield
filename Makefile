.PHONY: all build generate run clean test

# Default target: build the daemon
all: build

# Compile eBPF C code -> BPF bytecode + Go bindings
generate:
	go generate ./...

# Build the userspace daemon
build: generate
	go build -o agent-shield .

# Build + run with sudo (eBPF needs root / CAP_BPF)
run: build
	sudo ./agent-shield

# Run with verbose logging
debug: build
	sudo ./agent-shield -v

# Cleanup build artifacts
clean:
	rm -f agent-shield
	rm -f bpf_bpfel.o bpf_bpfel.go bpf_bpfeb.o bpf_bpfeb.go

# Run tests (placeholder for now)
test:
	go test ./...

# Verify environment is ready (kernel + tools)
check-env:
	@echo "=== Kernel version (need >= 5.8) ==="
	@uname -r
	@echo ""
	@echo "=== BTF available? ==="
	@ls /sys/kernel/btf/vmlinux 2>/dev/null && echo "yes" || echo "MISSING - CO-RE won't work"
	@echo ""
	@echo "=== Tools ==="
	@command -v clang && clang --version | head -1 || echo "clang MISSING"
	@command -v go && go version || echo "go MISSING"
