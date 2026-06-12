/*
 * tun.h - TUN Device Management
 *
 * Provides an abstraction over Linux TUN (TUNnel) virtual network
 * devices. The TUN device operates at Layer 3 (IP) and delivers raw
 * IPv6 packets to the application. This module handles device
 * creation, destruction, address configuration, and MTU settings.
 *
 * TUN Device Lifecycle:
 *   1. tun_open()   - Create and open the TUN device
 *   2. tun_set_addr()- Assign IPv6 address and bring interface up
 *   3. tun_read()   - Read raw IPv6 packets from the device
 *   4. tun_write()  - Write raw IPv6 packets to the device
 *   5. tun_close()  - Close the device (cleanup)
 *
 * Implementation notes:
 *   - Uses /dev/net/tun (Linux universal TUN/TAP driver)
 *   - Operates in IFF_TUN | IFF_NO_PI mode (no packet info header)
 *   - Address configuration via ioctl() or fallback to ip command
 */

#ifndef PIPESIX_TUN_H
#define PIPESIX_TUN_H

#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>
#include <unistd.h>

/*
 * TUN device descriptor.
 *
 * Contains the file descriptor for the TUN device and the interface
 * name assigned by the kernel or requested by the user.
 */
typedef struct {
    int   fd;                  /* TUN device file descriptor (-1 if closed) */
    char  name[64];            /* Interface name (e.g., "tun0") */
    int   mtu;                 /* Configured MTU */
} tun_device_t;

/*
 * Initialize a TUN device structure to an invalid state.
 *
 * Must be called before any other tun_* functions. Sets fd to -1
 * and name to empty string.
 *
 * Parameters:
 *   tun - TUN device structure to initialize
 */
void tun_init(tun_device_t *tun);

/*
 * Open and configure a TUN device.
 *
 * Creates a new TUN device via the Linux universal TUN/TAP driver.
 * After creation, assigns the IPv6 address and brings the interface
 * up. Also sets the MTU if specified.
 *
 * Address format examples:
 *   "2001:db8::1/64"   - Address with prefix length
 *   "fd00::1"          - Address only (uses tun_prefixlen from config)
 *
 * Parameters:
 *   tun         - TUN device structure (must be initialized)
 *   name        - Requested interface name (or NULL for kernel default)
 *   address     - IPv6 address with optional /prefix (or NULL)
 *   prefixlen   - Prefix length used if address has no /prefix
 *   mtu         - MTU value (0 to leave at default)
 *
 * Returns:
 *   0 on success, -1 on failure with errno set
 */
int tun_open(tun_device_t *tun, const char *name,
             const char *address, int prefixlen, int mtu);

/*
 * Read a raw IPv6 packet from the TUN device.
 *
 * Blocks until a packet is available. Returns the raw IPv6 packet
 * (including the IPv6 header) in the provided buffer.
 *
 * Parameters:
 *   tun  - TUN device structure
 *   buf  - Buffer to receive the packet
 *   size - Size of the buffer
 *
 * Returns:
 *   Number of bytes read on success, -1 on error
 */
ssize_t tun_read(tun_device_t *tun, void *buf, size_t size);

/*
 * Write a raw IPv6 packet to the TUN device.
 *
 * Injects a raw IPv6 packet into the kernel's network stack via the
 * TUN device. The kernel will then route the packet according to
 * the system routing table.
 *
 * Parameters:
 *   tun    - TUN device structure
 *   buf    - Buffer containing the raw IPv6 packet
 *   length - Length of the packet in bytes
 *
 * Returns:
 *   Number of bytes written on success, -1 on error
 */
ssize_t tun_write(tun_device_t *tun, const void *buf, size_t length);

/*
 * Close the TUN device.
 *
 * Closes the file descriptor and resets the device structure.
 * Safe to call even if the device was never successfully opened.
 *
 * Parameters:
 *   tun - TUN device structure to close
 */
void tun_close(tun_device_t *tun);

#endif /* PIPESIX_TUN_H */
