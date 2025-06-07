# ZeiCoin Makefile - Simplified build process

.PHONY: all clean build randomx test server cli help

# Default target - check if RandomX is built, build if needed
all: check-randomx build

# Build everything
build:
	@echo "🔨 Building ZeiCoin executables..."
	zig build

# Build RandomX helper (required for mining)
randomx:
	@echo "🔬 Building RandomX helper..."
	gcc -o randomx/randomx_helper randomx/randomx_helper.c randomx/wrapper.c \
		-Irandomx -Irandomx/randomx_install/include \
		-Lrandomx/randomx_install/lib -lrandomx -lstdc++ -lm
	@echo "✅ RandomX helper built successfully"

# Run tests
test:
	@echo "🧪 Running tests..."
	zig test randomx.zig
	zig test types.zig
	zig test main.zig

# Start server
server: all
	@echo "🚀 Starting ZeiCoin server..."
	./zig-out/bin/zen_server

# CLI shortcuts
cli: all
	@echo "💻 ZeiCoin CLI ready:"
	@echo "  ./zig-out/bin/zeicoin help"

# Clean build artifacts
clean:
	@echo "🧹 Cleaning build artifacts..."
	rm -rf zig-out .zig-cache
	rm -f randomx/randomx_helper

# Setup RandomX from scratch
setup-randomx:
	@echo "🔧 Setting up RandomX..."
	cd randomx && chmod +x build.sh && ./build.sh
	$(MAKE) randomx

# Check if RandomX is built, build if needed
check-randomx:
	@if [ ! -f randomx/randomx_helper ]; then \
		echo "🔧 RandomX not found, trying to build..."; \
		if $(MAKE) setup-randomx 2>/dev/null; then \
			echo "✅ RandomX built successfully"; \
		else \
			echo "❌ RandomX build failed. Please run: ./setup.sh"; \
			echo "   Or install manually with: make setup-randomx"; \
			exit 1; \
		fi; \
	else \
		echo "✅ RandomX already built"; \
	fi

# Help
help:
	@echo "ZeiCoin Build System"
	@echo "==================="
	@echo ""
	@echo "Targets:"
	@echo "  all          - Build everything (default)"
	@echo "  build        - Build Zig executables only"
	@echo "  randomx      - Build RandomX helper"
	@echo "  test         - Run all tests"
	@echo "  server       - Start blockchain server"
	@echo "  cli          - Show CLI usage"
	@echo "  clean        - Clean build artifacts"
	@echo "  setup-randomx - Build RandomX from source"
	@echo "  help         - Show this help"
	@echo ""
	@echo "Quick Start:"
	@echo "  make all           # Auto-builds RandomX if needed, then builds ZeiCoin"
	@echo "  make server        # Start mining"
	@echo ""
	@echo "Manual Setup (if needed):"
	@echo "  make setup-randomx  # Build RandomX from source"