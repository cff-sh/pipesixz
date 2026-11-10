/*
 * main.c - pipesix IPv6 over UDP Tunnel - Entry Point
 *
 * pipesix forwards IPv6 packets between a local TUN device and a
 * remote peer over UDP. A VPS relay (server mode) connects the tunnel
 * to a Route64 or NetAssist IPv6 uplink; a local machine (client mode)
 * gains IPv6 connectivity through it.
 *
 * Usage:
 *   pipesix [-c <config>]         Start with the given (or default) config
 *   pipesix -t [-c <config>]      Validate the configuration and exit
 *   pipesix --genkey              Print a random 256-bit per-client key
 *   pipesix --rotate-all          Replace every client key and reload the server
 *   pipesix -V                    Show version information
 *
 * Command-Line Options:
 *   -c, --config <path>     Configuration file (default /etc/pipesix/pipesix.conf)
 *   -t, --check             Validate configuration without touching the network
 *   -l, --log-level <name>  Override the configured log level
 *   -g, --genkey            Generate a per-client pre-shared key
 *   -R, --rotate-all        Generate and apply a new key for every client,
 *                           then make the running server adopt it
 *   -V, --version           Show version information
 *   -h, --help              Show help
 *
 * Signals:
 *   SIGINT/SIGTERM  Graceful shutdown
 *   SIGUSR1         Dump traffic statistics immediately
 *   SIGHUP          Reload runtime-tunable configuration
 */

#include "client.h"
#include "config.h"
#include "crypto.h"
#include "logger.h"
#include "proto.h"
#include "runtime.h"
#include "server.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <limits.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#define PIPESIX_APP_VERSION "2.1.0"
#define DEFAULT_CONFIG_PATH "/etc/pipesix/pipesix.conf"

static void handle_shutdown(int sig)
{
    (void)sig;
    runtime_request_stop();
}

static void handle_stats(int sig)
{
    (void)sig;
    runtime_request_stats();
}

static void handle_reload(int sig)
{
    (void)sig;
    runtime_request_reload();
}

static int setup_signal_handlers(void)
{
    struct sigaction sa;

    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = handle_shutdown;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0; /* Do not restart blocking calls, so poll() wakes up. */

    if (sigaction(SIGINT, &sa, NULL) < 0) {
        return -1;
    }
    if (sigaction(SIGTERM, &sa, NULL) < 0) {
        return -1;
    }

    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = handle_stats;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    if (sigaction(SIGUSR1, &sa, NULL) < 0) {
        return -1;
    }

    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = handle_reload;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    if (sigaction(SIGHUP, &sa, NULL) < 0) {
        return -1;
    }

    /* Broken pipes must surface as EPIPE instead of killing the process. */
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = SIG_IGN;
    sigemptyset(&sa.sa_mask);
    if (sigaction(SIGPIPE, &sa, NULL) < 0) {
        return -1;
    }

    return 0;
}

static void print_usage(const char *progname)
{
    fprintf(stderr,
            "Usage: %s [-c <config>] [-l <level>]\n"
            "       %s -t [-c <config>]\n"
            "       %s --genkey\n"
            "       %s --rotate-all [-c <config>]\n"
            "\n"
            "pipesix %s - IPv6 over UDP Tunnel\n"
            "\n"
            "Options:\n"
            "  -c, --config <path>     Configuration file\n"
            "                          (default: %s)\n"
            "  -t, --check             Validate configuration and exit\n"
            "  -l, --log-level <name>  Override log level\n"
            "  -g, --genkey            Generate a per-client key and exit\n"
            "  -R, --rotate-all        Generate and apply a new key for every\n"
            "                          'client' entry, print them and reload\n"
            "                          the running server (server only)\n"
            "  -V, --version           Show version information\n"
            "  -h, --help              Show this help message\n"
            "\n"
            "Configuration file format (key = value):\n"
            "  mode            client | server\n"
            "  tun_name        TUN device name (default: tun0)\n"
            "  tun_address     IPv6 address, optionally with /prefix\n"
            "  tun_prefixlen   Prefix length (default: 64)\n"
            "  tun_mtu         TUN MTU (default: 1500, 0 = leave unchanged)\n"
            "  remote_address  Server address (client mode)\n"
            "  remote_port     Server port (client mode, default: 8899)\n"
            "  bind_address    Bind address (server mode, default: 0.0.0.0)\n"
            "  bind_port       Bind port (server mode, default: 8899)\n"
            "  secret          This client's pre-shared key (client mode)\n"
            "  client_id       This client's identity (client mode)\n"
            "  client          <id>: <secret> entry (server mode, repeatable)\n"
            "  keepalive       Client keepalive seconds (default: 20, 0 = off)\n"
            "  session_timeout Server idle timeout seconds (default: 120)\n"
            "  peer_timeout    Client reconnect timeout seconds (default: 120, 0 = off)\n"
            "  allow_client    Server allow-list of client IPs (comma separated)\n"
            "  stats_interval  Stats log interval seconds (default: 60, 0 = off)\n"
            "  log_level       debug | info | warn | error | fatal\n"
            "\n"
            "Examples:\n"
            "  sudo pipesix\n"
            "  pipesix --genkey\n"
            "  pipesix -t -c ./pipesix.conf\n"
            "\n"
            "Signal SIGUSR1 dumps traffic statistics immediately.\n"
            "Signal SIGHUP reloads log_level, keepalive, peer_timeout,\n"
            "session_timeout, stats_interval and keys (server: client\n"
            "table, client: own secret) for live key rotation.\n",
            progname, progname, progname, progname, PIPESIX_APP_VERSION,
            DEFAULT_CONFIG_PATH);
}

static int generate_key(void)
{
    uint8_t key[PIPESIX_KEY_LEN];
    char hex[PIPESIX_KEY_LEN * 2 + 1];

    if (pipesix_random_bytes(key, sizeof(key)) != 0) {
        fprintf(stderr, "Error: cannot read random bytes: %s\n",
                strerror(errno));
        return EXIT_FAILURE;
    }

    pipesix_hex_encode(key, sizeof(key), hex);
    printf("%s\n", hex);
    return EXIT_SUCCESS;
}

/*
 * Read a small file into buf, NUL-terminating it.
 *
 * Returns the number of bytes read, or -1 when the file cannot be read.
 */
static ssize_t read_small_file(const char *path, char *buf, size_t size)
{
    size_t total = 0;
    int fd;

    if (size == 0) {
        return -1;
    }

    fd = open(path, O_RDONLY);
    if (fd < 0) {
        return -1;
    }

    while (total + 1 < size) {
        ssize_t n = read(fd, buf + total, size - 1 - total);

        if (n < 0) {
            if (errno == EINTR) {
                continue;
            }
            close(fd);
            return -1;
        }
        if (n == 0) {
            break;
        }
        total += (size_t)n;
    }

    close(fd);
    buf[total] = '\0';
    return (ssize_t)total;
}

/*
 * Does this NUL-separated command line use config_path?
 *
 * A process that was started without -c/--config uses the default path,
 * which only matches when that is the file being rotated. A relative path
 * is resolved on both sides before giving up, since the two processes need
 * not share a working directory.
 */
static int cmdline_uses_config(const char *cmdline, size_t len,
                               const char *config_path)
{
    const char *arg = cmdline;
    const char *end = cmdline + len;
    const char *found = NULL;

    while (arg < end) {
        size_t arg_len = strnlen(arg, (size_t)(end - arg));

        if (strcmp(arg, "-c") == 0 || strcmp(arg, "--config") == 0) {
            const char *next = arg + arg_len + 1;

            if (next < end) {
                found = next;
            }
            break;
        }

        if (strncmp(arg, "--config=", 9) == 0) {
            found = arg + 9;
            break;
        }

        arg += arg_len + 1;
    }

    if (found == NULL) {
        return strcmp(config_path, DEFAULT_CONFIG_PATH) == 0;
    }

    if (strcmp(found, config_path) == 0) {
        return 1;
    }

    {
        char theirs[PATH_MAX];
        char ours[PATH_MAX];

        if (realpath(found, theirs) != NULL &&
            realpath(config_path, ours) != NULL) {
            return strcmp(theirs, ours) == 0;
        }
    }

    return 0;
}

/*
 * Ask running pipesix instances to reload the configuration we just wrote.
 *
 * A rotation that stopped at the file would look successful while the
 * relay kept using the old keys, so --rotate-all finishes the job by
 * sending SIGHUP. There is no pid file to consult, so the instance is
 * found by walking /proc: a process counts when its program is named
 * 'pipesix' (never ourselves) and its command line names this very
 * configuration file. Restricting the match that way keeps a client or a
 * second server on another configuration untouched.
 *
 * Returns:
 *   the number of processes signalled, or -1 where /proc is unavailable
 *   (no /proc on this platform, so the reload has to be done by hand)
 */
static int reload_running_instances(const char *config_path)
{
    DIR *dir;
    struct dirent *entry;
    pid_t self = getpid();
    int signalled = 0;

    dir = opendir("/proc");
    if (dir == NULL) {
        return -1;
    }

    while ((entry = readdir(dir)) != NULL) {
        char path[64];
        char comm[32];
        char cmdline[4096];
        char *endptr = NULL;
        long parsed;
        ssize_t len;
        pid_t pid;

        /* Only the numeric entries are processes. */
        errno = 0;
        parsed = strtol(entry->d_name, &endptr, 10);
        if (errno != 0 || endptr == entry->d_name || *endptr != '\0' ||
            parsed <= 0) {
            continue;
        }

        pid = (pid_t)parsed;
        if (pid == self) {
            continue;
        }

        snprintf(path, sizeof(path), "/proc/%ld/comm", parsed);
        if (read_small_file(path, comm, sizeof(comm)) < 0) {
            continue;
        }
        comm[strcspn(comm, "\n")] = '\0';
        if (strcmp(comm, "pipesix") != 0) {
            continue;
        }

        snprintf(path, sizeof(path), "/proc/%ld/cmdline", parsed);
        len = read_small_file(path, cmdline, sizeof(cmdline));
        if (len < 0) {
            continue;
        }
        if (!cmdline_uses_config(cmdline, (size_t)len, config_path)) {
            continue;
        }

        if (kill(pid, SIGHUP) == 0) {
            signalled++;
        } else if (errno != ESRCH) {
            log_warn("Cannot signal pid %ld: %s", parsed, strerror(errno));
        }
    }

    closedir(dir);
    return signalled;
}

/*
 * Report the keys generated by --rotate-all.
 *
 * The keys are printed because they still have to reach each client's
 * 'secret' line; there is no channel that could push them there.
 */
static void report_rotated_keys(const pipesix_config_t *config)
{
    int i;

    printf("Rotated %d client key(s) in %s\n\n", config->client_count,
           config->config_path);

    for (i = 0; i < config->client_count; i++) {
        printf("  %-16s %s\n", config->clients[i].id,
               config->clients[i].secret);
    }

    printf("\n"
           "Put each key in the matching client's 'secret' line and reload\n"
           "each client:\n"
           "  sudo systemctl reload pipesix\n");
}

int main(int argc, char *argv[])
{
    static const struct option long_options[] = {
        { "config",    required_argument, NULL, 'c' },
        { "check",     no_argument,       NULL, 't' },
        { "log-level", required_argument, NULL, 'l' },
        { "genkey",    no_argument,       NULL, 'g' },
        { "rotate-all", no_argument,      NULL, 'R' },
        { "version",   no_argument,       NULL, 'V' },
        { "help",      no_argument,       NULL, 'h' },
        { NULL,        0,                 NULL, 0   }
    };

    pipesix_config_t config;
    const char *config_path = NULL;
    log_level_t cli_level = LOG_INFO;
    int have_cli_level = 0;
    int check_only = 0;
    int rotate_all = 0;
    int opt;

    while ((opt = getopt_long(argc, argv, "c:tl:gRVh", long_options, NULL)) != -1) {
        switch (opt) {
            case 'c':
                config_path = optarg;
                break;
            case 't':
                check_only = 1;
                break;
            case 'l':
                if (config_parse_log_level(optarg, &cli_level) != 0) {
                    fprintf(stderr, "Error: unknown log level '%s'\n", optarg);
                    return EXIT_FAILURE;
                }
                have_cli_level = 1;
                break;
            case 'g':
                return generate_key();
            case 'R':
                rotate_all = 1;
                break;
            case 'V':
                printf("pipesix %s (protocol %d)\n",
                       PIPESIX_APP_VERSION, PIPESIX_VERSION);
                return EXIT_SUCCESS;
            case 'h':
                print_usage(argv[0]);
                return EXIT_SUCCESS;
            default:
                print_usage(argv[0]);
                return EXIT_FAILURE;
        }
    }

    if (optind < argc) {
        fprintf(stderr, "Error: unexpected argument '%s'\n", argv[optind]);
        print_usage(argv[0]);
        return EXIT_FAILURE;
    }

    if (config_path == NULL) {
        config_path = DEFAULT_CONFIG_PATH;
    }

    logger_init(NULL);
    log_info("Loading configuration from '%s'", config_path);

    if (config_load(config_path, &config) != 0) {
        log_error("Failed to load configuration from '%s'", config_path);
        return EXIT_FAILURE;
    }

    if (have_cli_level) {
        config.log_level = cli_level;
    }
    logger_set_level(config.log_level);

    if (config_validate(&config) != 0) {
        log_error("Configuration validation failed");
        return EXIT_FAILURE;
    }

    config_dump(&config);

    if (rotate_all) {
        int signalled;

        if (config_rotate_all_keys(&config) != 0) {
            return EXIT_FAILURE;
        }
        report_rotated_keys(&config);

        signalled = reload_running_instances(config.config_path);
        if (signalled > 0) {
            printf("Signalled %d running pipesix process(es) with SIGHUP; "
                   "the server\nhas adopted the new keys.\n", signalled);
        } else if (signalled == 0) {
            printf("No running pipesix uses this configuration. Live "
                   "sessions keep\ntheir current keys until it is reloaded:\n"
                   "  sudo systemctl reload pipesix\n");
        } else {
            printf("Cannot look for a running pipesix here; reload the "
                   "server to\nadopt the new keys:\n"
                   "  sudo systemctl reload pipesix\n");
        }

        return EXIT_SUCCESS;
    }

    if (check_only) {
        printf("Configuration OK: %s\n", config_path);
        return EXIT_SUCCESS;
    }

    log_info("Frame protection: %s",
             "ChaCha20-Poly1305 with per-client session keys");

    runtime_init();

    if (setup_signal_handlers() != 0) {
        log_error("Failed to setup signal handlers: %s", strerror(errno));
        return EXIT_FAILURE;
    }

    int ret;

    if (strcmp(config.mode, "client") == 0) {
        log_info("Starting pipesix in CLIENT mode");
        ret = client_start(&config);
    } else {
        log_info("Starting pipesix in SERVER mode");
        ret = server_start(&config);
    }

    if (ret != 0) {
        log_error("pipesix terminated with error");
        return EXIT_FAILURE;
    }

    log_info("pipesix terminated successfully");
    return EXIT_SUCCESS;
}
