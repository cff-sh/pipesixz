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
 * External commands are executed with fork/execvp() and argument
 * arrays, so interface names and addresses cannot be interpreted by a
 * shell.
 *
 * The TUN device operates in Layer 3 (IFF_TUN) mode without packet
 * information headers (IFF_NO_PI on Linux, equivalent on macOS),
 * meaning each read/write delivers or expects a raw IP packet.
 */

#include "tun.h"
#include "logger.h"

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>
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

/*
 * Copy an interface name, always NUL-terminating and never writing more
 * than size - 1 bytes.
 */
static void copy_name(char *dst, size_t size, const char *src)
{
    size_t len;

    if (dst == NULL || size == 0) {
        return;
    }
    if (src == NULL) {
        dst[0] = '\0';
        return;
    }

    len = strlen(src);
    if (len >= size) {
        len = size - 1;
    }

    memcpy(dst, src, len);
    dst[len] = '\0';
}

/*
 * Run an external command without a shell.
 *
 * Parameters:
 *   argv  - NULL-terminated argument vector
 *   quiet - Non-zero to discard the child's stdout/stderr
 *
 * Returns:
 *   The command's exit status, or -1 if it could not be run.
 */
static int run_command(char *const argv[], int quiet)
{
    pid_t pid;
    int status;

    pid = fork();
    if (pid < 0) {
        return -1;
    }

    if (pid == 0) {
        if (quiet) {
            int null_fd = open("/dev/null", O_WRONLY);

            if (null_fd >= 0) {
                (void)dup2(null_fd, STDOUT_FILENO);
                (void)dup2(null_fd, STDERR_FILENO);
                if (null_fd > STDERR_FILENO) {
                    close(null_fd);
                }
            }
        }

        execvp(argv[0], argv);
        _exit(127);
    }

    while (waitpid(pid, &status, 0) < 0) {
        if (errno != EINTR) {
            return -1;
        }
    }

    if (WIFEXITED(status)) {
        return WEXITSTATUS(status);
    }

    return -1;
}

void tun_init(tun_device_t *tun)
{
    if (tun == NULL) return;
    tun->fd = -1;
    tun->name[0] = '\0';
    tun->mtu = 0;
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
        copy_name(ifr.ifr_name, sizeof(ifr.ifr_name), name);
    }

    rc = ioctl(fd, TUNSETIFF, &ifr);
    if (rc < 0) {
        log_error("ioctl(TUNSETIFF) failed: %s", strerror(errno));
        close(fd);
        return -1;
    }

    copy_name(tun->name, sizeof(tun->name), ifr.ifr_name);
    tun->fd = fd;

    log_info("TUN device '%s' created (fd=%d)", tun->name, tun->fd);

    if (mtu > 0) {
        memset(&ifr, 0, sizeof(ifr));
        copy_name(ifr.ifr_name, sizeof(ifr.ifr_name), tun->name);
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
        char addr_opt[INET6_ADDRSTRLEN + 8];
        char *addr_argv[8];
        char *up_argv[8];
        int n;

        n = snprintf(addr_opt, sizeof(addr_opt), "%s/%d", address, prefixlen);
        if (n < 0 || (size_t)n >= sizeof(addr_opt)) {
            log_error("IPv6 address option too long");
            tun_close(tun);
            return -1;
        }

        /*
         * "replace" is idempotent: restarting pipesix does not fail
         * because the address already exists.
         */
        addr_argv[0] = "ip";
        addr_argv[1] = "-6";
        addr_argv[2] = "addr";
        addr_argv[3] = "replace";
        addr_argv[4] = addr_opt;
        addr_argv[5] = "dev";
        addr_argv[6] = tun->name;
        addr_argv[7] = NULL;

        rc = run_command(addr_argv, 1);
        if (rc != 0) {
            log_warn("'ip -6 addr replace' returned %d (address may already exist)",
                     rc);
        }

        up_argv[0] = "ip";
        up_argv[1] = "link";
        up_argv[2] = "set";
        up_argv[3] = "dev";
        up_argv[4] = tun->name;
        up_argv[5] = "up";
        up_argv[6] = NULL;

        rc = run_command(up_argv, 1);
        if (rc != 0) {
            log_error("Failed to bring TUN interface up (ip link returned %d)",
                      rc);
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
    copy_name(ci.ctl_name, sizeof(ci.ctl_name), UTUN_CONTROL_NAME);

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
            log_error("getsockopt(UTUN_OPT_IFNAME) failed: %s",
                      strerror(errno));
            close(fd);
            return -1;
        }
    }

    copy_name(tun->name, sizeof(tun->name), ifname);
    tun->fd = fd;

    log_info("TUN device '%s' created (fd=%d)", tun->name, tun->fd);

    if (mtu > 0) {
        char mtu_opt[16];
        char *mtu_argv[5];
        int n = snprintf(mtu_opt, sizeof(mtu_opt), "%d", mtu);

        mtu_argv[0] = "ifconfig";
        mtu_argv[1] = tun->name;
        mtu_argv[2] = "mtu";
        mtu_argv[3] = mtu_opt;
        mtu_argv[4] = NULL;

        if (n < 0 || (size_t)n >= sizeof(mtu_opt)) {
            log_error("MTU option too long");
        } else if (run_command(mtu_argv, 1) != 0) {
            log_warn("Failed to set MTU to %d on %s", mtu, tun->name);
        } else {
            tun->mtu = mtu;
            log_info("TUN device MTU set to %d", mtu);
        }
    }

    if (address != NULL && strlen(address) > 0) {
        char addr_opt[INET6_ADDRSTRLEN + 8];
        char *addr_argv[6];
        int n;

        n = snprintf(addr_opt, sizeof(addr_opt), "%s/%d", address, prefixlen);
        if (n < 0 || (size_t)n >= sizeof(addr_opt)) {
            log_error("IPv6 address option too long");
            tun_close(tun);
            return -1;
        }

        addr_argv[0] = "ifconfig";
        addr_argv[1] = tun->name;
        addr_argv[2] = "inet6";
        addr_argv[3] = addr_opt;
        addr_argv[4] = "up";
        addr_argv[5] = NULL;

        if (run_command(addr_argv, 1) != 0) {
            log_error("Failed to configure address %s on %s",
                      addr_opt, tun->name);
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

int tun_wait(tun_device_t *tun, int timeout_ms)
{
    struct pollfd pfd;

    if (tun == NULL || tun->fd < 0) {
        errno = EBADF;
        return -1;
    }

    pfd.fd = tun->fd;
    pfd.events = POLLIN;
    pfd.revents = 0;

    return poll(&pfd, 1, timeout_ms);
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
