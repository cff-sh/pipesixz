/*
 * tun.c - TUN Device Management Implementation
 *
 * Implements the Linux TUN device interface using the universal
 * TUN/TAP driver (/dev/net/tun). This module handles:
 *
 *   1. Opening /dev/net/tun and creating a virtual interface via ioctl
 *   2. Configuring the IPv6 address using the ip command
 *   3. Setting MTU via ioctl
 *   4. Raw packet read/write operations
 *   5. Cleanup on close
 *
 * The TUN device operates in Layer 3 (IFF_TUN) mode without packet
 * information headers (IFF_NO_PI), meaning each read/write delivers
 * or expects a raw IP packet without any additional framing.
 */

#include "tun.h"
#include "logger.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <linux/if.h>
#include <linux/if_tun.h>

/*
 * Path to the Linux universal TUN/TAP character device.
 * This device is provided by the tun kernel module.
 */
#define TUN_DEVICE_PATH    "/dev/net/tun"

/*
 * Buffer size for system() command strings.
 * Must be large enough to hold full ip commands.
 */
#define CMD_BUF_SIZE       512

void tun_init(tun_device_t *tun)
{
    if (tun == NULL) return;
    tun->fd   = -1;
    tun->name[0] = '\0';
    tun->mtu  = 0;
}

int tun_open(tun_device_t *tun, const char *name,
             const char *address, int prefixlen, int mtu)
{
    struct ifreq ifr;
    int fd, rc;

    if (tun == NULL) {
        errno = EINVAL;
        return -1;
    }

    /*
     * Step 1: Open the TUN/TAP control device.
     * This device is the entry point for all TUN/TAP operations.
     */
    fd = open(TUN_DEVICE_PATH, O_RDWR);
    if (fd < 0) {
        log_error("Cannot open %s: %s", TUN_DEVICE_PATH, strerror(errno));
        return -1;
    }

    /*
     * Step 2: Create the TUN interface via ioctl.
     * IFF_TUN    - Creates a Layer 3 (IP) tunnel device
     * IFF_NO_PI  - Do not prepend packet info header to packets
     * The interface name can be specified or left to the kernel.
     */
    memset(&ifr, 0, sizeof(ifr));
    ifr.ifr_flags = IFF_TUN | IFF_NO_PI;

    if (name != NULL && strlen(name) > 0) {
        strncpy(ifr.ifr_name, name, IFNAMSIZ - 1);
    }

    rc = ioctl(fd, TUNSETIFF, &ifr);
    if (rc < 0) {
        log_error("ioctl(TUNSETIFF) failed: %s", strerror(errno));
        close(fd);
        return -1;
    }

    /* Store the actual interface name (kernel may have modified it) */
    strncpy(tun->name, ifr.ifr_name, sizeof(tun->name) - 1);
    tun->fd = fd;

    log_info("TUN device '%s' created (fd=%d)", tun->name, tun->fd);

    /*
     * Step 3: Set MTU if specified.
     * Uses the SIOCSIFMTU ioctl to configure the interface MTU.
     */
    if (mtu > 0) {
        memset(&ifr, 0, sizeof(ifr));
        memcpy(ifr.ifr_name, tun->name, IFNAMSIZ - 1);
        ifr.ifr_name[IFNAMSIZ - 1] = '\0';
        ifr.ifr_mtu = mtu;

        rc = ioctl(fd, SIOCSIFMTU, &ifr);
        if (rc < 0) {
            log_warn("Failed to set MTU to %d: %s", mtu, strerror(errno));
        } else {
            tun->mtu = mtu;
            log_info("TUN device MTU set to %d", mtu);
        }
    }

    /*
     * Step 4: Configure IPv6 address and bring interface up.
     * Uses the ip command via system() since netlink address management
     * is complex and the ip tool is universally available on Linux.
     */
    if (address != NULL && strlen(address) > 0) {
        char cmd[CMD_BUF_SIZE];
        int cmd_rc;

        /*
         * Add IPv6 address to the TUN interface.
         * Format: ip -6 addr add <address>/<prefixlen> dev <name>
         */
        rc = snprintf(cmd, sizeof(cmd),
                      "ip -6 addr add %s/%d dev %s 2>/dev/null",
                      address, prefixlen, tun->name);
        if (rc < 0 || (size_t)rc >= sizeof(cmd)) {
            log_error("Address configuration command too long");
            tun_close(tun);
            return -1;
        }

        cmd_rc = system(cmd);
        if (cmd_rc != 0) {
            log_warn("'ip -6 addr add' returned %d (address may already exist)", cmd_rc);
        }

        /*
         * Bring the interface up.
         * Format: ip link set <name> up
         */
        rc = snprintf(cmd, sizeof(cmd),
                      "ip link set %s up 2>/dev/null", tun->name);
        if (rc < 0 || (size_t)rc >= sizeof(cmd)) {
            log_error("Link up command too long");
            tun_close(tun);
            return -1;
        }

        cmd_rc = system(cmd);
        if (cmd_rc != 0) {
            log_error("Failed to bring TUN interface up (ip link returned %d)", cmd_rc);
            tun_close(tun);
            return -1;
        }

        log_info("TUN device '%s' configured with %s/%d and brought up",
                 tun->name, address, prefixlen);
    }

    return 0;
}

ssize_t tun_read(tun_device_t *tun, void *buf, size_t size)
{
    ssize_t n;

    if (tun == NULL || tun->fd < 0 || buf == NULL) {
        errno = EBADF;
        return -1;
    }

    n = read(tun->fd, buf, size);
    if (n < 0 && errno != EINTR) {
        log_error("TUN read error (fd=%d): %s", tun->fd, strerror(errno));
    }

    return n;
}

ssize_t tun_write(tun_device_t *tun, const void *buf, size_t length)
{
    ssize_t n;

    if (tun == NULL || tun->fd < 0 || buf == NULL) {
        errno = EBADF;
        return -1;
    }

    n = write(tun->fd, buf, length);
    if (n < 0 && errno != EINTR) {
        log_error("TUN write error (fd=%d): %s", tun->fd, strerror(errno));
    }

    return n;
}

void tun_close(tun_device_t *tun)
{
    if (tun == NULL) return;

    if (tun->fd >= 0) {
        log_info("Closing TUN device '%s' (fd=%d)", tun->name, tun->fd);
        close(tun->fd);
        tun->fd = -1;
    }

    tun->name[0] = '\0';
    tun->mtu = 0;
}
