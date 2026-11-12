#
# Makefile - pipesix IPv6 over UDP Tunnel
#
# Targets:
#   all          - Build the pipesix binary
#   install      - Install pipesix to PREFIX (default: /usr/local)
#   clean        - Remove build artifacts
#   distclean    - Remove build artifacts and dependency files
#
# Variables:
#   CC           - C compiler (default: gcc)
#   CFLAGS       - Compiler flags
#   LDFLAGS      - Linker flags
#   PREFIX       - Installation prefix (default: /usr/local)
#   CONFIG_DIR   - Configuration directory (default: /etc/pipesix)
#
# Example:
#   make              # Build with defaults
#   make PREFIX=/opt  # Build with custom prefix
#   make install      # Build and install
#   make clean        # Clean build artifacts
#

# Platform detection
UNAME_S  := $(shell uname -s)

# Compiler and linker configuration
ifeq ($(UNAME_S),Darwin)
CC       ?= clang
else
CC       ?= gcc
endif
CFLAGS   ?= -O2 -g
LDFLAGS  ?=

# Installation paths
PREFIX      ?= /usr/local
BINDIR       = $(PREFIX)/sbin
CONFIG_DIR   = /etc/pipesix

# Source files
SRCDIR       = src
SOURCES      = $(SRCDIR)/main.c \
               $(SRCDIR)/logger.c \
               $(SRCDIR)/config.c \
               $(SRCDIR)/crypto.c \
               $(SRCDIR)/proto.c \
               $(SRCDIR)/runtime.c \
               $(SRCDIR)/stats.c \
               $(SRCDIR)/tun.c \
               $(SRCDIR)/ipv6.c \
               $(SRCDIR)/control.c \
               $(SRCDIR)/metrics.c \
               $(SRCDIR)/client.c \
               $(SRCDIR)/server.c

OBJECTS      = $(SOURCES:.c=.o)
DEPENDS      = $(SOURCES:.c=.d)

# Unit tests only need the platform-independent modules
TEST_BIN     = tests/test_core
TEST_SOURCES = tests/test_core.c
TEST_OBJECTS = $(SRCDIR)/crypto.o $(SRCDIR)/proto.o \
               $(SRCDIR)/config.o $(SRCDIR)/logger.o \
               $(SRCDIR)/ipv6.o $(SRCDIR)/stats.o

# The control channel test needs no root: it exercises the socket, not
# the tunnel.
TEST_CONTROL_BIN     = tests/test_control
TEST_CONTROL_SOURCES = tests/test_control.c
TEST_CONTROL_OBJECTS = $(SRCDIR)/control.o $(SRCDIR)/logger.o

# Binary name
TARGET       = pipesix

# Compiler flags
 override CFLAGS += -std=gnu11 \
                    -Wall \
                    -Wextra \
                    -Wpedantic \
                    -Wshadow \
                    -Wstrict-prototypes \
                    -Wmissing-prototypes \
                    -Wconversion \
                    -Wsign-conversion \
                    -Wfloat-equal \
                    -Wcast-align \
                    -Wformat=2 \
                    -Wno-unused-parameter \
                    -I$(SRCDIR)

# Platform-specific feature macros
ifeq ($(UNAME_S),Darwin)
 override CFLAGS += -D_DARWIN_C_SOURCE
else
 override CFLAGS += -D_POSIX_C_SOURCE=200809L \
                    -D_DEFAULT_SOURCE
endif

# Linker flags
 override LDFLAGS += -pthread

# Default target: build the binary
.PHONY: all
all: $(TARGET)

#
# Link the final binary from all object files.
#
$(TARGET): $(OBJECTS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)
	@echo "Build complete: $(TARGET)"

#
# Compile source files to object files with dependency generation.
#
$(SRCDIR)/%.o: $(SRCDIR)/%.c
	$(CC) $(CFLAGS) -MMD -MP -c -o $@ $<

#
# Include auto-generated dependency files.
#
-include $(DEPENDS)

#
# Build and run the unit tests (no root privileges required).
#
$(TEST_BIN): $(TEST_SOURCES) $(TEST_OBJECTS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

$(TEST_CONTROL_BIN): $(TEST_CONTROL_SOURCES) $(TEST_CONTROL_OBJECTS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

.PHONY: check
check: $(TEST_BIN) $(TEST_CONTROL_BIN)
	@./$(TEST_BIN)
	@./$(TEST_CONTROL_BIN)

#
# Build and package every platform the local toolchains support.
#
dist:
	@./build.sh --all

#
# Install the binary and example configuration.
#
.PHONY: install
install: $(TARGET)
	@echo "Installing $(TARGET) to $(BINDIR)..."
	install -d $(DESTDIR)$(BINDIR)
	install -m 755 $(TARGET) $(DESTDIR)$(BINDIR)/$(TARGET)

	@echo "Installing example configuration to $(CONFIG_DIR)..."
	install -d $(DESTDIR)$(CONFIG_DIR)
	install -m 644 pipesix.conf.example $(DESTDIR)$(CONFIG_DIR)/pipesix.conf.example

	@echo "Installation complete"

#
# Uninstall the binary and configuration.
#
.PHONY: uninstall
uninstall:
	@echo "Removing $(TARGET) from $(BINDIR)..."
	rm -f $(DESTDIR)$(BINDIR)/$(TARGET)
	@echo "Uninstall complete"

#
# Windows client build.
#
# Only the TUN backend and the portability layer are platform specific,
# so tun.c and server.c are replaced (server mode stays on the VPS) and
# platform_win.c joins the build. Cross-compile from Linux with mingw-w64,
# or run 'make windows' inside MSYS2:
#
#   make windows
#
# wintun.dll is loaded at run time and never linked, so nothing beyond the
# compiler is needed to build a self-contained pipesix.exe.
#
WINDOWS_CC      ?= x86_64-w64-mingw32-gcc
WINDOWS_TARGET   = pipesix.exe
# -Wconversion and -Wsign-conversion are deliberately absent: the Win32 API
# mixes int, DWORD, SIZE_T and pointer-sized SOCKET values by design, so the
# POSIX warning set would fire on every call rather than on every bug.
WINDOWS_CFLAGS  ?= -O2 -g -Wall -Wextra -Wpedantic -Wshadow -Wformat=2 \
                   -Werror -D_WIN32_WINNT=0x0601 \
                   -D__USE_MINGW_ANSI_STDIO=1
# winpthread is linked statically so the zip needs no extra runtime DLL;
# the C99 stdio shim makes %zu/%llu correct on the legacy msvcrt.
WINDOWS_LDLIBS   = -lws2_32 -lbcrypt \
                   -Wl,-Bstatic -lwinpthread -Wl,-Bdynamic
WINDOWS_SOURCES  = $(filter-out $(SRCDIR)/tun.c $(SRCDIR)/server.c,$(SOURCES)) \
                   $(SRCDIR)/tun_windows.c $(SRCDIR)/platform_win.c

.PHONY: windows clean-windows
windows: $(WINDOWS_TARGET)

$(WINDOWS_TARGET): $(WINDOWS_SOURCES) $(SRCDIR)/platform.h $(SRCDIR)/control.h
	$(WINDOWS_CC) $(WINDOWS_CFLAGS) -o $@ $(WINDOWS_SOURCES) $(WINDOWS_LDLIBS)
	@echo "Build complete: $(WINDOWS_TARGET)"

clean-windows:
	rm -f $(WINDOWS_TARGET)

#
# Clean build artifacts without removing dependency files.
#
.PHONY: clean
clean:
	rm -f $(OBJECTS) $(TARGET) $(TEST_BIN) $(TEST_CONTROL_BIN) $(WINDOWS_TARGET)

#
# Clean build artifacts and dependency files.
#
.PHONY: dist distclean
distclean: clean
	rm -f $(DEPENDS)
	rm -rf dist

#
# Display build configuration.
#
.PHONY: info
info:
	@echo "pipesix build configuration:"
	@echo "  CC:        $(CC)"
	@echo "  CFLAGS:    $(CFLAGS)"
	@echo "  LDFLAGS:   $(LDFLAGS)"
	@echo "  PREFIX:    $(PREFIX)"
	@echo "  BINDIR:    $(BINDIR)"
	@echo "  CONFIG:    $(CONFIG_DIR)/pipesix.conf"
	@echo ""
	@echo "Source files:"
	@for src in $(SOURCES); do \
	    echo "    $$src"; \
	done
