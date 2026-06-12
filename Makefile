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

# Compiler and linker configuration
CC       ?= gcc
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
               $(SRCDIR)/tun.c \
               $(SRCDIR)/ipv6.c \
               $(SRCDIR)/client.c \
               $(SRCDIR)/server.c

OBJECTS      = $(SOURCES:.c=.o)
DEPENDS      = $(SOURCES:.c=.d)

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
                    -D_POSIX_C_SOURCE=200809L \
                    -D_DEFAULT_SOURCE \
                    -I$(SRCDIR)

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
# Clean build artifacts without removing dependency files.
#
.PHONY: clean
clean:
	rm -f $(OBJECTS) $(TARGET)

#
# Clean build artifacts and dependency files.
#
.PHONY: distclean
distclean: clean
	rm -f $(DEPENDS)

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
