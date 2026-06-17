/*
 * tun.c - TUN Device Management Implementation
 *
 * Implements the TUN device interface for multiple platforms:
 *
 *   Linux: Uses /dev/net/tun with the universal TUN/TAP driver.
 *          Address configuration via the ip command.
 *
 *   macOS: Uses the utun (user tunnel) kernel control interface.
 *          Address configuration via the ifconfig command.
 *
 * The TUN device operates in Layer 3 (IFF_TUN) mode without packet
 * information headers (IFF_NO_PI on Linux, equivalent on macOS),
 * meaning each read/write delivers or expects a raw IP packet.
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

#ifdef __linux__
#include <linux/if.h>
#include <linux/if_tun.h>
#define TUN_DEVICE_PATH    "/dev/net/tun"
#endif

#ifdef __APPLE__
#include <sys/sys_domain.h>
#include <sys/kern_control.h>
#include <net/if.h>
#include <netinet/in.h>
#ifndef UTUN_CONTROL_NAME
#define UTUN_CONTROL_NAME "com.apple.net.utun_control"
#endif
#ifndef UTUN_OPT_IFNAME
#define UTUN_OPT_IFNAME 2
#endif
#endif

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
    if (tun == NULL) {
        errno = EINVAL;
        return -1;
    }

#if defined(__linux__)
    struct ifreq ifr;
    int fd, rc;

    fd = open(TUN_DEVICE_PATH, O_RDWR);
    if (fd < 0) {
        log_error("Cannot open %s: %s", TUN_DEVICE_PATH, strerror(errno));
        return -1;
    }

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

    strncpy(tun->name, ifr.ifr_name, sizeof(tun->name) - 1);
    tun->fd = fd;

    log_info("TUN device '%s' created (fd=%d)", tun->name, tun->fd);

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

    if (address != NULL && strlen(address) > 0) {
        char cmd[CMD_BUF_SIZE];
        int cmd_rc;

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

#elif defined(__APPLE__)
    int fd, rc;
    struct ctl_info ci;
    struct sockaddr_ctl sc;
    char ifname[IFNAMSIZ];

    fd = socket(PF_SYSTEM, SOCK_DGRAM, SYSPROTO_CONTROL);
    if (fd < 0) {
        log_error("Cannot create utun control socket: %s", strerror(errno));
        return -1;
    }

    memset(&ci, 0, sizeof(ci));
    strncpy(ci.ctl_name, UTUN_CONTROL_NAME, sizeof(ci.ctl_name) - 1);

    rc = ioctl(fd, CTLIOCGINFO, &ci);
    if (rc < 0) {
        log_error("ioctl(CTLIOCGINFO) for utun failed: %s", strerror(errno));
        close(fd);
        return -1;
    }

    memset(&sc, 0, sizeof(sc));
    sc.sc_id = ci.ctl_id;
    sc.sc_len = sizeof(sc);
    sc.sc_family = AF_SYSTEM;
    sc.ss_sysaddr = AF_SYS_CONTROL;
    sc.sc_unit = 0;

    rc = connect(fd, (struct sockaddr *)&sc, sizeof(sc));
    if (rc < 0) {
        log_error("connect(utun) failed: %s", strerror(errno));
        close(fd);
        return -1;
    }

    memset(ifname, 0, sizeof(ifname));
    {
        socklen_t ifnamelen = sizeof(ifname);
        if (getsockopt(fd, SYSPROTO_CONTROL, UTUN_OPT_IFNAME,
                       ifname, &ifnamelen) < 0) {
            log_error("getsockopt(UTUN_OPT_IFNAME) failed: %s", strerror(errno));
            close(fd);
            return -1;
        }
    }

    strncpy(tun->name, ifname, sizeof(tun->name) - 1);
    tun->fd = fd;

    log_info("TUN device '%s' created (fd=%d)", tun->name, tun->fd);

    if (mtu > 0) {
        char cmd[CMD_BUF_SIZE];

        rc = snprintf(cmd, sizeof(cmd),
                      "ifconfig %s mtu %d 2>/dev/null", tun->name, mtu);
        if (rc < 0 || (size_t)rc >= sizeof(cmd)) {
            log_error("MTU command too long");
        } else if (system(cmd) != 0) {
            log_warn("Failed to set MTU to %d on %s", mtu, tun->name);
        } else {
            tun->mtu = mtu;
            log_info("TUN device MTU set to %d", mtu);
        }
    }

    if (address != NULL && strlen(address) > 0) {
        char cmd[CMD_BUF_SIZE];
        int cmd_rc;

        rc = snprintf(cmd, sizeof(cmd),
                      "ifconfig %s inet6 %s/%d up 2>/dev/null",
                      tun->name, address, prefixlen);
        if (rc < 0 || (size_t)rc >= sizeof(cmd)) {
            log_error("Address configuration command too long");
            tun_close(tun);
            return -1;
        }

        cmd_rc = system(cmd);
        if (cmd_rc != 0) {
            log_error("Failed to configure address on %s "
                      "(ifconfig returned %d)", tun->name, cmd_rc);
            tun_close(tun);
            return -1;
        }

        log_info("TUN device '%s' configured with %s/%d and brought up",
                 tun->name, address, prefixlen);
    }

#else
#error "Unsupported platform: pipesix requires Linux or macOS"
#endif

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
