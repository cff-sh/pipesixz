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
 *   pipesix --add-client <id> [--route <prefix> | --delegate]
 *                                 Add a client to the server configuration
 *   pipesix --remove-client <id>  Remove a client from the configuration
 *   pipesix -V                    Show version information
 *
 * Command-Line Options:
 *   -c, --config <path>     Configuration file (default /etc/pipesix/pipesix.conf)
 *   -t, --check             Validate configuration without touching the network
 *   -l, --log-level <name>  Override the configured log level
 *   -g, --genkey            Generate a per-client pre-shared key
 *   -R, --rotate-all        Generate and apply a new key for every client,
 *                           then make the running server adopt it
 *       --status            Report the running instance's state
 *       --json              Print that status as one JSON object
 *       --kick <client-id>  Drop that client's session
 *   -V, --version           Show version information
 *   -h, --help              Show help
 *
 * Signals:
 *   SIGINT/SIGTERM  Graceful shutdown
 *   SIGUSR1         Dump traffic statistics immediately
 *   SIGHUP          Reload runtime-tunable configuration
 */

#include "client.h"
#include "audit.h"
#include "config.h"
#include "control.h"
#include "crypto.h"
#include "logger.h"
#include "platform.h"
#include "policy.h"
#include "proto.h"
#include "runtime.h"
#include "server.h"

#if !defined(_WIN32)
#include <dirent.h>
#endif
#include <errno.h>
#if !defined(_WIN32)
#include <fcntl.h>
#endif
#include <getopt.h>
#include <limits.h>
#if !defined(_WIN32)
#include <signal.h>
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

/*
 * The Makefile owns the version and passes it as -DPIPESIX_APP_VERSION,
 * so 'pipesix -V' matches the release archive and .deb it came from. A
 * build that bypasses the Makefile says 'dev' instead of an old number
 * that was true at some point.
 */
#ifndef PIPESIX_APP_VERSION
#define PIPESIX_APP_VERSION "dev"
#endif

/*
 * Windows has no /etc, so the default is the current directory: a Windows
 * user runs pipesix.exe where the configuration lives, or passes -c.
 */
#if defined(_WIN32)
#define DEFAULT_CONFIG_PATH "pipesix.conf"
#else
#define DEFAULT_CONFIG_PATH "/etc/pipesix/pipesix.conf"
#endif

#if defined(_WIN32)

/*
 * Windows has no signals. A console handler covers Ctrl+C, Ctrl+Break and
 * the stop/shutdown notifications a service wrapper sends; reload and
 * statistics requests arrive through the named events in control.c, which
 * is why --reload and --stats exist.
 */
static BOOL WINAPI console_handler(DWORD event)
{
    switch (event) {
        case CTRL_C_EVENT:
        case CTRL_BREAK_EVENT:
        case CTRL_CLOSE_EVENT:
        case CTRL_SHUTDOWN_EVENT:
            runtime_request_stop();
            return TRUE;
        default:
            return FALSE;
    }
}

static int setup_signal_handlers(void)
{
    if (!SetConsoleCtrlHandler(console_handler, TRUE)) {
        errno = EIO;
        return -1;
    }

    return 0;
}

#else

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

#endif /* _WIN32 */

#if defined(_WIN32)
/*
 * Server mode is not built for Windows: the relay needs a TUN device
 * routed to an IPv6 uplink, which belongs on the VPS. This stub keeps the
 * client binary self-contained and says so instead of failing to link.
 */
int server_start(pipesix_config_t *config)
{
    (void)config;
    log_error("Server mode is not supported on Windows; run the server on "
              "the VPS and use this binary as a client");
    return -1;
}
#endif

static void print_usage(const char *progname)
{
    fprintf(stderr,
            "Usage: %s [-c <config>] [-l <level>]\n"
            "       %s -t [-c <config>]\n"
            "       %s --genkey\n"
            "       %s --rotate-all [-c <config>]\n"
            "       %s --add-client <id> [--route <prefix> | --delegate]\n"
            "                          [-c <config>]\n"
            "       %s --remove-client <id> [-c <config>]\n"
            "       %s --set-limit <id> [--rate <kbps>] [--quota <MiB>]\n"
            "                          [--quota-warn <percent>] [-c <config>]\n"
            "       %s --clear-limit <id> [-c <config>]\n"
            "       %s --usage [--history] [--json|--csv] [-c <config>]\n"
            "       %s --doctor [-c <config>]\n"
            "       %s --stage-key <id> | --promote-key <id> | --abort-key <id>\n"
            "\n"
            "pipesix %s - IPv6 over UDP Tunnel\n"
            "\n"
            "Options:\n"
            "  -c, --config <path>     Configuration file\n"
            "                          (default: %s)\n",
            progname, progname, progname, progname, progname, progname,
            progname, progname, progname, progname, progname,
            PIPESIX_APP_VERSION, DEFAULT_CONFIG_PATH);

    fprintf(stderr,
            "  -t, --check             Validate configuration and exit\n"
            "  -l, --log-level <name>  Override log level\n"
            "  -g, --genkey            Generate a per-client key and exit\n"
            "  -R, --rotate-all        Generate and apply a new key for every\n"
            "                          'client' entry, print them and reload\n"
            "                          the running server (server only)\n"
            "      --reload            Ask the running instance for this\n"
            "                          configuration to reload it\n"
            "      --stats             Ask it to dump statistics now\n"
            "      --status            Report the running instance's state\n"
            "      --json              Print --status or --usage as one\n"
            "                          JSON object\n"
            "      --usage             Report per-client usage and limits\n"
            "      --reset-usage <id>  Reset that client's current-period\n"
            "                          usage to zero\n"
            "      --credit-usage <id> Subtract MiB from current usage\n"
            "                          (needs --mib)\n"
            "      --add-usage <id>    Add MiB to current usage (needs --mib)\n"
            "      --mib <MiB>         Amount for --credit-usage/--add-usage\n"
            "      --history           With --usage, print completed periods\n"
            "                          from the usage_history file\n"
            "      --csv               Print --usage as one CSV table\n"
            "      --metrics           Print the running instance's Prometheus\n"
            "                          metrics\n"
            "      --kick <client-id>  Drop that client's session; it\n"
            "                          handshakes again immediately\n"
            "      --add-client <id>   Generate a key, write a 'client' entry\n"
            "                          and its route into the configuration\n"
            "                          and reload the running server\n"
            "      --remove-client <id>\n"
            "                          Remove that client's entry and route\n"
            "      --set-limit <id>    Replace that client's limits in the\n"
            "                          configuration and reload the server\n"
            "      --clear-limit <id>  Remove every limit for that client\n"
            "      --rate <kbps>       Bandwidth cap for --add-client or\n"
            "                          --set-limit (0 = unlimited)\n"
            "      --quota <MiB>       Quota per period for --add-client or\n"
            "                          --set-limit (0 = unlimited)\n"
            "      --quota-warn <pct>  Tell the client when this percentage\n"
            "                          of its quota is used (1-99)\n"
            "      --route <prefix>    Return route for --add-client\n"
            "      --delegate          Give --add-client a free /64 from\n"
            "                          'client_prefix_pool' as its route\n"
            "      --server-address <host>\n"
            "                          Address written into exported client\n"
            "                          configurations (or the bind address)\n"
            "      --write-client-config <path>\n"
            "                          Write a complete client config after\n"
            "                          --add-client or --export-client\n"
            "      --export-client <id>\n"
            "                          Export an existing client's config\n"
            "      --export-dir <dir>  With --export-client or --rotate-all,\n"
            "                          write <dir>/<id>.conf for each client\n"
            "      --doctor            Probe every relay endpoint without\n"
            "                          opening the TUN device or changing a session\n"
            "      --stage-key <id>    Generate a replacement key and keep the\n"
            "                          current one valid\n"
            "      --promote-key <id>  Make the staged key current\n"
            "      --abort-key <id>    Discard the staged key\n"
            "      --disable-client <id> Refuse this client on the next reload\n"
            "      --enable-client <id>  Re-admit a disabled client\n"
            "      --expire-client <id> <when>\n"
            "                          Set a YYYY-MM-DD or Unix expiry; use\n"
            "                          'never' to clear it\n"
            "      --rate-in <kbps>    Client-to-server cap for --add-client or\n"
            "                          --set-limit\n"
            "      --rate-out <kbps>   Server-to-client cap for --add-client or\n"
            "                          --set-limit\n"
            "  -V, --version           Show version information\n"
            "  -h, --help              Show this help message\n");

    fprintf(stderr,
            "\n"
            "Configuration file format (key = value):\n"
            "  mode            client | server\n"
            "  tun_name        TUN device name (default: tun0)\n"
            "  tun_address     IPv6 address, optionally with /prefix\n"
            "  tun_prefixlen   Prefix length (default: 64)\n"
            "  tun_mtu         TUN MTU (default: 1500, 0 = leave unchanged)\n"
            "  remote_address  Relay address(es), comma separated (client)\n"
            "  remote_port     Server port (client mode, default: 8899)\n"
            "  bind_address    Bind address (server mode, default: 0.0.0.0)\n"
            "  bind_port       Bind port (server mode, default: 8899)\n"
            "  secret          This client's pre-shared key (client mode)\n"
            "  client_id       This client's identity (client mode)\n"
            "  client          <id>: <secret> entry (server mode, repeatable)\n"
            "  client_route    <id> <prefix> (server, repeatable)\n"
            "  client_prefix_pool <ipv6>/<len> /64 delegation pool (server)\n"
            "  client_rate_limit <id> <kbit/s> (server, repeatable, both directions)\n"
            "  client_rate_limit_in/out <id> <kbit/s> per direction\n"
            "  client_next     <id>: <secret> staged rotation key\n"
            "  client_disabled <id> (server, repeatable)\n"
            "  client_expires  <id> YYYY-MM-DD|unix\n"
            "  client_quota    <id> <MiB> per period (server, repeatable)\n"
            "  client_quota_warn <id> <percent> (server, repeatable)\n"
            "  strict_source   Drop data outside the client route (server)\n"
            "  quota_period    daily | weekly | monthly | custom\n"
            "                  (default: daily)\n"
            "  quota_period_days Custom period length in days (1-365)\n"
            "  quota_action    drop | throttle (default: drop)\n"
            "  quota_grace     MiB over quota before the action (default: 0)\n"
            "  quota_throttle_kbps Over-quota rate (default: 64)\n"
            "  quota_state     File for quota usage (server, empty = off)\n"
            "  usage_history   Completed periods as CSV (server, empty = off)\n"
            "  audit_log       Append-only JSONL audit file (empty = off)\n"
            "  endpoint_failback on | off (client, default off)\n"
            "  endpoint_failback_interval Seconds between preferred probes\n");

    fprintf(stderr,
            "  keepalive       Client keepalive seconds (default: 20, 0 = off)\n"
            "  session_timeout Server idle timeout seconds (default: 120)\n"
            "  peer_timeout    Client reconnect timeout seconds (default: 120, 0 = off)\n"
            "  allow_client    Server allow-list of client IPs (comma separated)\n"
            "  stats_interval  Stats log interval seconds (default: 60, 0 = off)\n"
            "  metrics_address Metrics endpoint address (empty = disabled)\n"
            "  metrics_port    Metrics endpoint port (default: 9100)\n"
            "  metrics_token   Bearer token for /metrics (empty = open)\n");

    fprintf(stderr,
            "  log_level       debug | info | warn | error | fatal\n"
            "  log_format      text | json (default: text)\n"
            "\n"
            "Examples:\n"
            "  sudo pipesix\n"
            "  pipesix --genkey\n"
            "  pipesix -t -c ./pipesix.conf\n"
            "\n"
            "Signal SIGUSR1 dumps traffic statistics immediately.\n"
            "Signal SIGHUP reloads log settings, timing settings, ACLs,\n"
            "allow_client, quota windows/action/grace/rate, quota_state,\n"
            "usage_history, metrics settings, keys and limits. A client\n"
            "also adopts new remote_address/remote_port and reconnects.\n"
            "On Windows there are no signals: use --reload and --stats.\n"
            "The control channel (--status, --kick) is a 0600 UNIX socket\n"
            "and is available on POSIX only.\n");
}

static int parse_u64(const char *text, uint64_t *out)
{
    char *end = NULL;
    unsigned long long value;

    if (text == NULL || text[0] == '\0' || out == NULL) {
        return -1;
    }

    errno = 0;
    value = strtoull(text, &end, 10);
    if (errno != 0 || end == text || *end != '\0') {
        return -1;
    }

    *out = (uint64_t)value;
    return 0;
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

#if !defined(_WIN32)

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
 * Ask running pipesix instances to act on a configuration.
 *
 * A rotation that stopped at the file would look successful while the
 * relay kept using the old keys, so --rotate-all finishes the job by
 * signalling the instance. --reload and --stats reach the same code with a
 * different signal. There is no pid file to consult, so the instance is
 * found by walking /proc: a process counts when its program is named
 * 'pipesix' (never ourselves) and its command line names this very
 * configuration file. Restricting the match that way keeps a client or a
 * second server on another configuration untouched.
 *
 * Parameters:
 *   config_path - configuration the instance was started with
 *   sig         - SIGHUP to reload it, SIGUSR1 to dump its statistics
 *
 * Returns:
 *   the number of processes signalled, or -1 where /proc is unavailable
 *   (no /proc on this platform, so the signal has to be sent by hand)
 */
static int signal_running_instances(const char *config_path, int sig)
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

        if (kill(pid, sig) == 0) {
            signalled++;
        } else if (errno != ESRCH) {
            log_warn("Cannot signal pid %ld: %s", parsed, strerror(errno));
        }
    }

    closedir(dir);
    return signalled;
}

#endif /* !_WIN32 */

/*
 * Report the keys generated by --rotate-all.
 *
 * The keys are printed because they still have to reach each client's
 * 'secret' line; there is no channel that could push them there.
 */
/*
 * Turn a client's return prefix into the address it should put on its TUN
 * device. A /128 is the address itself; a shorter prefix gets host bit 1,
 * which is valid for the common /64 delegation and avoids the all-zero
 * subnet-router address.
 */
static int client_tun_address(const pipesix_client_cred_t *cred, char *out,
                              size_t out_size, int *prefix_len)
{
    uint8_t addr[16];

    if (cred == NULL || cred->prefix_len <= 0 || out == NULL ||
        out_size == 0) {
        return -1;
    }

    memcpy(addr, cred->prefix, sizeof(addr));
    if (cred->prefix_len < 128) {
        if (cred->prefix_len <= 120) {
            addr[15] = 1;
        } else {
            addr[15] |= 1;
        }
    }

    *prefix_len = cred->prefix_len;
    return config_format_prefix(addr, *prefix_len, out, out_size);
}

/*
 * Write a complete client configuration for one provisioned client.
 *
 * The server's own bind address is a poor default when it is a wildcard,
 * so the caller should pass --server-address there. The file is opened
 * with mode 0600 before the secret is written on POSIX.
 */
static int write_client_config(const pipesix_config_t *config, const char *id,
                               const char *server_address, const char *path)
{
    const pipesix_client_cred_t *cred = config_find_client(config, id);
    char tun_address[CONFIG_MAX_ADDRESS];
    char route_text[CONFIG_MAX_ADDRESS];
    char dir_path[CONFIG_PATH_MAX];
    char address[CONFIG_MAX_ADDRESS];
    const char *remote = server_address;
    FILE *fp;
    int prefix_len = 0;
    int port;

    if (cred == NULL || path == NULL || path[0] == '\0') {
        log_error("cannot export client '%s': no such credential or path",
                  id != NULL ? id : "?");
        return -1;
    }

    if (client_tun_address(cred, tun_address, sizeof(tun_address),
                           &prefix_len) != 0) {
        log_error("cannot export client '%s': it has no client_route", id);
        return -1;
    }

    if (config_format_prefix(cred->prefix, cred->prefix_len, route_text,
                             sizeof(route_text)) != 0) {
        return -1;
    }

    if (remote == NULL || remote[0] == '\0') {
        remote = config->bind_address;
    }
    if (remote == NULL || remote[0] == '\0' ||
        strcmp(remote, "0.0.0.0") == 0 || strcmp(remote, "::") == 0) {
        log_error("exporting '%s' needs a reachable --server-address", id);
        return -1;
    }

    snprintf(dir_path, sizeof(dir_path), "%s", path);
    fp = fopen(dir_path, "w");
    if (fp == NULL) {
        log_error("cannot write client config '%s': %s", path,
                  strerror(errno));
        return -1;
    }

#if !defined(_WIN32)
    (void)fchmod(fileno(fp), 0600);
#endif

    port = (strcmp(config->mode, "server") == 0) ? config->bind_port
                                                  : config->remote_port;
    snprintf(address, sizeof(address), "%s", tun_address);

    if (fprintf(fp,
                "# pipesix client configuration for %s\n"
                "# generated from %s:%s\n"
                "mode = client\n"
                "client_id = %s\n"
                "secret = %s\n"
                "remote_address = %s\n"
                "remote_port = %d\n"
                "tun_name = tun0\n"
                "tun_address = %s\n"
                "tun_prefixlen = %d\n"
                "tun_mtu = %d\n"
                "log_level = info\n"
                "# route the generated %s on the client if it is a /64\n",
                id, config->config_path, route_text, id, cred->secret,
                remote, port, address, prefix_len, config->tun_mtu,
                route_text) < 0) {
        fclose(fp);
        unlink(path);
        return -1;
    }

    if (fclose(fp) != 0) {
        unlink(path);
        return -1;
    }

    return 0;
}

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
        { "reload",    no_argument,       NULL, 1000 },
        { "stats",     no_argument,       NULL, 1001 },
        { "status",    no_argument,       NULL, 1002 },
        { "json",      no_argument,       NULL, 1007 },
        { "metrics",   no_argument,       NULL, 1008 },
        { "usage",     no_argument,       NULL, 1010 },
        { "csv",       no_argument,       NULL, 1011 },
        { "history",   no_argument,       NULL, 1018 },
        { "set-limit", required_argument, NULL, 1012 },
        { "clear-limit", required_argument, NULL, 1013 },
        { "rate",      required_argument, NULL, 1014 },
        { "quota",     required_argument, NULL, 1015 },
        { "quota-warn", required_argument, NULL, 1016 },
        { "kick",      required_argument, NULL, 1003 },
        { "add-client", required_argument, NULL, 1004 },
        { "remove-client", required_argument, NULL, 1005 },
        { "route",     required_argument, NULL, 1006 },
        { "delegate",  no_argument,       NULL, 1017 },
        { "reset-usage", required_argument, NULL, 1019 },
        { "credit-usage", required_argument, NULL, 1020 },
        { "add-usage", required_argument, NULL, 1021 },
        { "mib",       required_argument, NULL, 1022 },
        { "server-address", required_argument, NULL, 1023 },
        { "write-client-config", required_argument, NULL, 1024 },
        { "export-client", required_argument, NULL, 1025 },
        { "export-dir", required_argument, NULL, 1026 },
        { "doctor",    no_argument,       NULL, 1027 },
        { "stage-key", required_argument, NULL, 1028 },
        { "promote-key", required_argument, NULL, 1029 },
        { "abort-key", required_argument, NULL, 1030 },
        { "disable-client", required_argument, NULL, 1031 },
        { "enable-client", required_argument, NULL, 1032 },
        { "expire-client", required_argument, NULL, 1033 },
        { "rate-in",  required_argument, NULL, 1034 },
        { "rate-out", required_argument, NULL, 1035 },
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
    int reload_only = 0;
    int stats_only = 0;
    int status_only = 0;
    int json_output = 0;
    int metrics_only = 0;
    int usage_only = 0;
    int csv_output = 0;
    int history_only = 0;
    const char *set_limit = NULL;
    const char *clear_limit = NULL;
    const char *rate_arg = NULL;
    const char *rate_in_arg = NULL;
    const char *rate_out_arg = NULL;
    const char *quota_arg = NULL;
    const char *warn_arg = NULL;
    uint64_t rate_kbps = 0;
    uint64_t rate_in_kbps = 0;
    uint64_t rate_out_kbps = 0;
    uint64_t quota_mib = 0;
    uint64_t warn_percent = 0;
    int have_rate = 0;
    int have_rate_in = 0;
    int have_rate_out = 0;
    int have_quota = 0;
    int have_warn = 0;
    int doctor_only = 0;
    const char *stage_key = NULL;
    const char *promote_key = NULL;
    const char *abort_key = NULL;
    const char *disable_client = NULL;
    const char *enable_client = NULL;
    const char *expire_client = NULL;
    const char *expire_when = NULL;
    const char *kick_id = NULL;
    const char *add_client = NULL;
    const char *remove_client = NULL;
    const char *add_route = NULL;
    const char *reset_usage = NULL;
    const char *credit_usage = NULL;
    const char *add_usage = NULL;
    const char *mib_arg = NULL;
    const char *server_address = NULL;
    const char *write_client_path = NULL;
    const char *export_client = NULL;
    const char *export_dir = NULL;
    uint64_t mib_value = 0;
    int delegate = 0;
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
            case 1000:
                reload_only = 1;
                break;
            case 1001:
                stats_only = 1;
                break;
            case 1002:
                status_only = 1;
                break;
            case 1003:
                kick_id = optarg;
                break;
            case 1007:
                json_output = 1;
                break;
            case 1008:
                metrics_only = 1;
                break;
            case 1010:
                usage_only = 1;
                break;
            case 1011:
                csv_output = 1;
                break;
            case 1018:
                history_only = 1;
                break;
            case 1012:
                set_limit = optarg;
                break;
            case 1013:
                clear_limit = optarg;
                break;
            case 1014:
                rate_arg = optarg;
                break;
            case 1015:
                quota_arg = optarg;
                break;
            case 1016:
                warn_arg = optarg;
                break;
            case 1004:
                add_client = optarg;
                break;
            case 1005:
                remove_client = optarg;
                break;
            case 1006:
                add_route = optarg;
                break;
            case 1017:
                delegate = 1;
                break;
            case 1019:
                reset_usage = optarg;
                break;
            case 1020:
                credit_usage = optarg;
                break;
            case 1021:
                add_usage = optarg;
                break;
            case 1022:
                mib_arg = optarg;
                break;
            case 1023:
                server_address = optarg;
                break;
            case 1024:
                write_client_path = optarg;
                break;
            case 1025:
                export_client = optarg;
                break;
            case 1026:
                export_dir = optarg;
                break;
            case 1027:
                doctor_only = 1;
                break;
            case 1028:
                stage_key = optarg;
                break;
            case 1029:
                promote_key = optarg;
                break;
            case 1030:
                abort_key = optarg;
                break;
            case 1031:
                disable_client = optarg;
                break;
            case 1032:
                enable_client = optarg;
                break;
            case 1033:
                expire_client = optarg;
                expire_when = argv[optind] != NULL ? argv[optind++] : NULL;
                break;
            case 1034:
                rate_in_arg = optarg;
                break;
            case 1035:
                rate_out_arg = optarg;
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

    if (add_client != NULL && remove_client != NULL) {
        fprintf(stderr, "Error: --add-client and --remove-client are "
                        "mutually exclusive\n");
        return EXIT_FAILURE;
    }

    if (add_route != NULL && add_client == NULL) {
        fprintf(stderr, "Error: --route is only valid with --add-client\n");
        return EXIT_FAILURE;
    }

    if (delegate && add_client == NULL) {
        fprintf(stderr, "Error: --delegate is only valid with "
                        "--add-client\n");
        return EXIT_FAILURE;
    }

    if (delegate && add_route != NULL) {
        fprintf(stderr, "Error: --delegate and --route are mutually "
                        "exclusive\n");
        return EXIT_FAILURE;
    }

    if (set_limit != NULL && clear_limit != NULL) {
        fprintf(stderr, "Error: --set-limit and --clear-limit are "
                        "mutually exclusive\n");
        return EXIT_FAILURE;
    }

    if ((set_limit != NULL || clear_limit != NULL) &&
        (add_client != NULL || remove_client != NULL)) {
        fprintf(stderr, "Error: --set-limit/--clear-limit cannot be "
                        "combined with --add-client or --remove-client\n");
        return EXIT_FAILURE;
    }

    if (rate_arg != NULL) {
        if (parse_u64(rate_arg, &rate_kbps) != 0 ||
            rate_kbps > 100000000u) {
            fprintf(stderr, "Error: --rate must be 0-100000000 kbit/s\n");
            return EXIT_FAILURE;
        }
        have_rate = 1;
    }
    if (rate_in_arg != NULL) {
        if (parse_u64(rate_in_arg, &rate_in_kbps) != 0 ||
            rate_in_kbps > 100000000u) {
            fprintf(stderr, "Error: --rate-in must be 0-100000000 kbit/s\n");
            return EXIT_FAILURE;
        }
        have_rate_in = 1;
    }
    if (rate_out_arg != NULL) {
        if (parse_u64(rate_out_arg, &rate_out_kbps) != 0 ||
            rate_out_kbps > 100000000u) {
            fprintf(stderr, "Error: --rate-out must be 0-100000000 kbit/s\n");
            return EXIT_FAILURE;
        }
        have_rate_out = 1;
    }

    if (quota_arg != NULL) {
        if (parse_u64(quota_arg, &quota_mib) != 0 ||
            quota_mib > 1048576u) {
            fprintf(stderr, "Error: --quota must be 0-1048576 MiB\n");
            return EXIT_FAILURE;
        }
        have_quota = 1;
    }

    if (warn_arg != NULL) {
        if (parse_u64(warn_arg, &warn_percent) != 0 ||
            warn_percent > 99u) {
            fprintf(stderr, "Error: --quota-warn must be 0-99 percent\n");
            return EXIT_FAILURE;
        }
        have_warn = 1;
    }

    if ((have_rate || have_rate_in || have_rate_out || have_quota ||
         have_warn) && add_client == NULL && set_limit == NULL) {
        fprintf(stderr, "Error: --rate, --rate-in, --rate-out, --quota and "
                        "--quota-warn require --add-client or --set-limit\n");
        return EXIT_FAILURE;
    }

    if (set_limit != NULL &&
        !(have_rate || have_rate_in || have_rate_out || have_quota ||
          have_warn)) {
        fprintf(stderr, "Error: --set-limit needs --rate, --rate-in, "
                        "--rate-out, --quota or --quota-warn\n");
        return EXIT_FAILURE;
    }

    if (json_output && !status_only && !usage_only) {
        fprintf(stderr, "Error: --json requires --status or --usage\n");
        return EXIT_FAILURE;
    }

    if (csv_output && !usage_only) {
        fprintf(stderr, "Error: --csv requires --usage\n");
        return EXIT_FAILURE;
    }

    if (history_only && !usage_only) {
        fprintf(stderr, "Error: --history requires --usage\n");
        return EXIT_FAILURE;
    }

    if (json_output && csv_output) {
        fprintf(stderr, "Error: --json and --csv are mutually exclusive\n");
        return EXIT_FAILURE;
    }

    if ((reset_usage != NULL) + (credit_usage != NULL) +
            (add_usage != NULL) > 1) {
        fprintf(stderr, "Error: --reset-usage, --credit-usage and "
                        "--add-usage are mutually exclusive\n");
        return EXIT_FAILURE;
    }

    if (mib_arg != NULL) {
        if (parse_u64(mib_arg, &mib_value) != 0 ||
            mib_value > 1048576u) {
            fprintf(stderr, "Error: --mib must be 0-1048576\n");
            return EXIT_FAILURE;
        }
    }

    if ((credit_usage != NULL || add_usage != NULL) && mib_arg == NULL) {
        fprintf(stderr, "Error: --credit-usage and --add-usage need "
                        "--mib <MiB>\n");
        return EXIT_FAILURE;
    }

    if (reset_usage != NULL && mib_arg != NULL) {
        fprintf(stderr, "Error: --mib is not valid with --reset-usage\n");
        return EXIT_FAILURE;
    }

    if (mib_arg != NULL && reset_usage == NULL && credit_usage == NULL &&
        add_usage == NULL) {
        fprintf(stderr, "Error: --mib requires --credit-usage or "
                        "--add-usage\n");
        return EXIT_FAILURE;
    }

    if (write_client_path != NULL && add_client == NULL &&
        export_client == NULL) {
        fprintf(stderr, "Error: --write-client-config requires "
                        "--add-client or --export-client\n");
        return EXIT_FAILURE;
    }

    if (export_dir != NULL && export_client == NULL && !rotate_all) {
        fprintf(stderr, "Error: --export-dir requires --export-client or "
                        "--rotate-all\n");
        return EXIT_FAILURE;
    }

    if (export_client != NULL &&
        (add_client != NULL || remove_client != NULL || rotate_all ||
         set_limit != NULL || clear_limit != NULL)) {
        fprintf(stderr, "Error: --export-client cannot be combined with "
                        "provisioning or rotation commands\n");
        return EXIT_FAILURE;
    }

    if (export_client != NULL && write_client_path == NULL &&
        export_dir == NULL) {
        fprintf(stderr, "Error: --export-client needs --write-client-config "
                        "or --export-dir\n");
        return EXIT_FAILURE;
    }

    if ((stage_key != NULL) + (promote_key != NULL) + (abort_key != NULL) +
            (disable_client != NULL) + (enable_client != NULL) +
            (expire_client != NULL) > 1) {
        fprintf(stderr, "Error: choose one of --stage-key, --promote-key, "
                        "--abort-key, --disable-client, --enable-client or "
                        "--expire-client\n");
        return EXIT_FAILURE;
    }

    if (expire_client != NULL &&
        (expire_when == NULL || expire_when[0] == '-')) {
        fprintf(stderr, "Error: --expire-client needs <id> <when>\n");
        return EXIT_FAILURE;
    }

    if (doctor_only &&
        (stage_key != NULL || promote_key != NULL || abort_key != NULL ||
         disable_client != NULL || enable_client != NULL ||
         expire_client != NULL || add_client != NULL ||
         remove_client != NULL || rotate_all)) {
        fprintf(stderr, "Error: --doctor cannot be combined with a "
                        "configuration-changing command\n");
        return EXIT_FAILURE;
    }

    /*
     * The history is an append-only file, so this query reads it directly
     * and works without a running server (and on a copy of the machine).
     */
    if (history_only) {
        policy_history_t *rows;
        int count = 0;
        int total = 0;
        int i;

        logger_init(NULL);
        logger_set_level(LOG_ERROR);

        if (config_load(config_path, &config) != 0 ||
            config_validate(&config) != 0) {
            return EXIT_FAILURE;
        }

        if (config.usage_history[0] == '\0') {
            fprintf(stderr,
                    "Error: no 'usage_history' configured in '%s'\n",
                    config_path);
            return EXIT_FAILURE;
        }

        rows = calloc(POLICY_HISTORY_MAX, sizeof(*rows));
        if (rows == NULL) {
            fprintf(stderr, "Error: out of memory\n");
            return EXIT_FAILURE;
        }

        if (policy_history_load(config.usage_history, rows,
                                POLICY_HISTORY_MAX, &count, &total) != 0) {
            fprintf(stderr,
                    "Error: cannot read the usage history '%s': %s\n",
                    config.usage_history, strerror(errno));
            free(rows);
            return EXIT_FAILURE;
        }

        if (csv_output) {
            printf("client_id,period_start,period_end,period,used_bytes\n");
            for (i = 0; i < count; i++) {
                char start[16] = "?";
                char end[16] = "?";
                char kind[24];

                (void)policy_format_date((time_t)rows[i].start_unix, start,
                                         sizeof(start));
                (void)policy_format_date((time_t)rows[i].end_unix, end,
                                         sizeof(end));
                policy_period_name(rows[i].kind, kind, sizeof(kind));
                printf("%s,%s,%s,%s,%llu\n", rows[i].id, start, end,
                       kind, (unsigned long long)rows[i].used);
            }
            free(rows);
            return EXIT_SUCCESS;
        }

        if (json_output) {
            char config_esc[1024];

            if (control_json_escape(config.config_path, config_esc,
                                    sizeof(config_esc)) != 0) {
                fprintf(stderr,
                        "Error: cannot encode the history as JSON\n");
                free(rows);
                return EXIT_FAILURE;
            }

            printf("{\"mode\":\"server\",\"config\":\"%s\","
                   "\"history\":[", config_esc);
            for (i = 0; i < count; i++) {
                char id_esc[128];
                char kind[24];

                if (control_json_escape(rows[i].id, id_esc,
                                        sizeof(id_esc)) != 0) {
                    fprintf(stderr,
                            "Error: cannot encode the history as JSON\n");
                    free(rows);
                    return EXIT_FAILURE;
                }

                policy_period_name(rows[i].kind, kind, sizeof(kind));
                printf("%s{\"client_id\":\"%s\","
                       "\"period_start_unix\":%lld,"
                       "\"period_end_unix\":%lld,\"period\":\"%s\","
                       "\"used_bytes\":%llu}",
                       i > 0 ? "," : "", id_esc,
                       (long long)rows[i].start_unix,
                       (long long)rows[i].end_unix, kind,
                       (unsigned long long)rows[i].used);
            }
            printf("]}\n");
            free(rows);
            return EXIT_SUCCESS;
        }

        printf("mode: server\n");
        printf("config: %s\n", config.config_path);
        printf("history: %s (%d record(s))\n", config.usage_history, total);
        for (i = 0; i < count; i++) {
            char start[16] = "?";
            char end[16] = "?";
            char kind[24];

            (void)policy_format_date((time_t)rows[i].start_unix, start,
                                     sizeof(start));
            (void)policy_format_date((time_t)rows[i].end_unix, end,
                                     sizeof(end));
            policy_period_name(rows[i].kind, kind, sizeof(kind));
            printf("  %s %s..%s (%s) used=%llu B\n", rows[i].id, start,
                   end, kind, (unsigned long long)rows[i].used);
        }
        if (total > count) {
            printf("  ... %d older record(s) not shown\n", total - count);
        }

        free(rows);
        return EXIT_SUCCESS;
    }

    /*
     * --status, --metrics and --kick ask the running instance instead of
     * starting a second one, so they are answered before the
     * configuration is loaded (and before anything is logged to stderr).
     */
    if (status_only || kick_id != NULL || metrics_only || usage_only ||
        reset_usage != NULL || credit_usage != NULL || add_usage != NULL) {
        char reply[CONTROL_MAX_REPLY];
        char request[CONFIG_MAX_CLIENT_ID + 64];

        if (kick_id != NULL) {
            if (strlen(kick_id) >= CONFIG_MAX_CLIENT_ID) {
                fprintf(stderr, "Error: client id is too long\n");
                return EXIT_FAILURE;
            }
            snprintf(request, sizeof(request), "kick %s", kick_id);
        } else if (reset_usage != NULL) {
            snprintf(request, sizeof(request), "usage-reset %s", reset_usage);
        } else if (credit_usage != NULL) {
            snprintf(request, sizeof(request), "usage-credit %s %llu",
                     credit_usage, (unsigned long long)mib_value);
        } else if (add_usage != NULL) {
            snprintf(request, sizeof(request), "usage-add %s %llu",
                     add_usage, (unsigned long long)mib_value);
        } else if (usage_only) {
            snprintf(request, sizeof(request), "usage%s",
                     csv_output ? " csv" : (json_output ? " json" : ""));
        } else if (metrics_only) {
            snprintf(request, sizeof(request), "metrics");
        } else if (json_output) {
            snprintf(request, sizeof(request), "status json");
        } else {
            snprintf(request, sizeof(request), "status");
        }

        if (control_request(config_path, request, reply, sizeof(reply)) != 0) {
            fprintf(stderr,
                    "Cannot reach a running pipesix for '%s': %s\n"
                    "(the control socket exists only while pipesix runs)\n",
                    config_path, strerror(errno));
            return EXIT_FAILURE;
        }

        if (json_output || metrics_only || csv_output) {
            /*
             * Strip the channel's OK line so stdout is the JSON object or
             * the metrics body itself, ready to pipe into jq or a scraper.
             */
            if (strncmp(reply, "OK\n", 3) != 0) {
                fputs(reply, stderr);
                return EXIT_FAILURE;
            }
            fputs(reply + 3, stdout);
            return EXIT_SUCCESS;
        }

        fputs(reply, stdout);
        return (strncmp(reply, "OK", 2) == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
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
    logger_set_json(config.log_json);

    if (config_validate(&config) != 0) {
        log_error("Configuration validation failed");
        return EXIT_FAILURE;
    }

    if (doctor_only) {
        return client_doctor(&config) == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
    }

    if (stage_key != NULL || promote_key != NULL || abort_key != NULL ||
        disable_client != NULL || enable_client != NULL ||
        expire_client != NULL) {
        const char *id = stage_key != NULL ? stage_key
                        : promote_key != NULL ? promote_key
                        : abort_key != NULL ? abort_key
                        : disable_client != NULL ? disable_client
                        : enable_client != NULL ? enable_client
                                                : expire_client;
        char reply[1024];
        char key[PIPESIX_KEY_LEN * 2 + 1];
        int rc;

        if (audit_open(config.audit_log) != 0) {
            fprintf(stderr, "Warning: cannot open the audit log '%s': %s\n",
                    config.audit_log, strerror(errno));
        }

        if (stage_key != NULL) {
            rc = config_stage_key(&config, id, key, sizeof(key));
            if (rc == 0) {
                printf("Staged a replacement key for client '%s':\n\n", id);
                printf("  client_next = %s: %s\n\n", id, key);
                printf("The current key stays valid. Update the client to "
                       "the new key,\nverify it connects, then run "
                       "'pipesix --promote-key %s'.\n", id);
                audit_event("key_staged", id, "",
                            "replacement key staged");
            }
            memset(key, 0, sizeof(key));
        } else if (promote_key != NULL) {
            rc = config_promote_key(&config, id);
            if (rc == 0) {
                printf("Promoted the staged key for client '%s'.\n", id);
                audit_event("key_promoted", id, "",
                            "staged key promoted to current");
            }
        } else if (abort_key != NULL) {
            rc = config_abort_key(&config, id);
            if (rc == 0) {
                printf("Discarded the staged key for client '%s'.\n", id);
                audit_event("key_aborted", id, "",
                            "staged key discarded");
            }
        } else if (disable_client != NULL) {
            rc = config_set_client_disabled(&config, id, 1);
            if (rc == 0) {
                printf("Client '%s' is now disabled.\n", id);
                audit_event("client_disabled", id, "",
                            "client disabled");
            }
        } else if (enable_client != NULL) {
            rc = config_set_client_disabled(&config, id, 0);
            if (rc == 0) {
                printf("Client '%s' is now enabled.\n", id);
                audit_event("client_enabled", id, "",
                            "client enabled");
            }
        } else {
            rc = config_set_client_expiry(&config, id, expire_when);
            if (rc == 0) {
                if (strcasecmp(expire_when, "never") == 0) {
                    printf("Cleared the expiry for client '%s'.\n", id);
                    audit_event("client_expiry_cleared", id, "",
                                "expiry cleared");
                } else {
                    printf("Client '%s' now expires at %s UTC.\n", id,
                           expire_when);
                    audit_event("client_expiry_set", id, "",
                                "expires at %s UTC", expire_when);
                }
            }
        }

        if (rc != 0) {
            fprintf(stderr, "Error: cannot update client '%s' in '%s'\n",
                    id, config_path);
            audit_close();
            return EXIT_FAILURE;
        }

        if (control_request(config_path, "reload", reply, sizeof(reply)) == 0) {
            printf("Running instance asked to reload.\n");
        } else {
            printf("No running instance for this configuration; the change "
                   "applies when it starts.\n");
        }
        audit_close();
        return EXIT_SUCCESS;
    }

    if (export_client != NULL) {
        char path[CONFIG_PATH_MAX];

        if (export_dir != NULL) {
            if (snprintf(path, sizeof(path), "%s/%s.conf", export_dir,
                         export_client) >= (int)sizeof(path)) {
                fprintf(stderr, "Error: export path is too long\n");
                return EXIT_FAILURE;
            }
        } else {
            snprintf(path, sizeof(path), "%s", write_client_path);
        }

        if (write_client_config(&config, export_client, server_address,
                                path) != 0) {
            return EXIT_FAILURE;
        }

        printf("Wrote client configuration for '%s' to %s\n",
               export_client, path);
        return EXIT_SUCCESS;
    }

    if (add_client != NULL || remove_client != NULL) {
        char reply[1024];
        char secret[PIPESIX_KEY_LEN * 2 + 1];

        if (add_client != NULL) {
            pipesix_client_policy_t limits;
            int have_limits = have_rate || have_quota || have_warn;
            const char *route = add_route;
            char delegated_route[CONFIG_MAX_ADDRESS];
            char client_address[CONFIG_MAX_ADDRESS];
            uint8_t delegated[16];

            if (delegate) {
                uint8_t address[16];

                if (config.prefix_pool_len <= 0) {
                    fprintf(stderr,
                            "Error: --delegate needs a "
                            "'client_prefix_pool' in '%s'\n",
                            config_path);
                    return EXIT_FAILURE;
                }

                if (config_delegate_prefix(&config, delegated) != 0) {
                    fprintf(stderr,
                            "Error: no free /64 left in "
                            "'client_prefix_pool' for client '%s'\n",
                            add_client);
                    return EXIT_FAILURE;
                }

                if (config_format_prefix(delegated, 64, delegated_route,
                                         sizeof(delegated_route)) != 0) {
                    fprintf(stderr,
                            "Error: cannot format the delegated prefix\n");
                    return EXIT_FAILURE;
                }

                memcpy(address, delegated, sizeof(address));
                address[15] = 1;
                if (config_format_prefix(address, 64, client_address,
                                         sizeof(client_address)) != 0) {
                    fprintf(stderr,
                            "Error: cannot format the client address\n");
                    return EXIT_FAILURE;
                }

                route = delegated_route;
            }

            memset(&limits, 0, sizeof(limits));
            snprintf(limits.id, sizeof(limits.id), "%s", add_client);
            limits.rate_kbps = have_rate ? rate_kbps : 0;
            limits.rate_in_set = have_rate_in;
            limits.rate_in_kbps = have_rate_in ? rate_in_kbps : 0;
            limits.rate_out_set = have_rate_out;
            limits.rate_out_kbps = have_rate_out ? rate_out_kbps : 0;
            limits.quota_mib = have_quota ? quota_mib : 0;
            limits.warn_percent = have_warn ? warn_percent : 0;

            if (config_add_client(&config, add_client, route,
                                  have_limits ? &limits : NULL, secret,
                                  sizeof(secret)) != 0) {
                fprintf(stderr, "Error: cannot add client '%s' to '%s'\n",
                        add_client, config_path);
                return EXIT_FAILURE;
            }

            /* Provisioning writes the file; adopt it before exporting. */
            if (config_reload_runtime(&config) != 0) {
                fprintf(stderr, "Error: cannot reload '%s' after adding "
                                "client '%s'\n", config_path, add_client);
                return EXIT_FAILURE;
            }

            printf("Added client '%s' to %s\n\n", add_client, config_path);
            printf("  client_id = %s\n", add_client);
            printf("  secret    = %s\n", secret);
            if (route != NULL) {
                printf("  client_route = %s %s\n", add_client, route);
            }
            if (delegate) {
                printf("\nDelegated %s from 'client_prefix_pool'.\n",
                       delegated_route);
                printf("  on the client: tun_address = %s "
                       "(and route the /64 on its LAN)\n", client_address);
            }
            if (limits.rate_kbps > 0) {
                printf("  client_rate_limit = %s %llu\n", add_client,
                       (unsigned long long)limits.rate_kbps);
            }
            if (limits.rate_in_set) {
                printf("  client_rate_limit_in = %s %llu\n", add_client,
                       (unsigned long long)limits.rate_in_kbps);
            }
            if (limits.rate_out_set) {
                printf("  client_rate_limit_out = %s %llu\n", add_client,
                       (unsigned long long)limits.rate_out_kbps);
            }
            if (limits.quota_mib > 0) {
                printf("  client_quota = %s %llu\n", add_client,
                       (unsigned long long)limits.quota_mib);
            }
            if (limits.warn_percent > 0) {
                printf("  client_quota_warn = %s %llu\n", add_client,
                       (unsigned long long)limits.warn_percent);
            }
            if (write_client_path != NULL) {
                if (write_client_config(&config, add_client, server_address,
                                        write_client_path) != 0) {
                    return EXIT_FAILURE;
                }
                printf("\nWrote a complete client configuration to %s\n",
                       write_client_path);
            }

            printf("\nSet these on the client host and start it; the key is "
                   "printed once\nand is not stored anywhere else.\n");
        } else {
            if (config_remove_client(&config, remove_client) != 0) {
                fprintf(stderr,
                        "Error: cannot remove client '%s' from '%s'\n",
                        remove_client, config_path);
                return EXIT_FAILURE;
            }
            printf("Removed client '%s' from %s\n", remove_client,
                   config_path);
        }

        /*
         * The file is authoritative, but a running server holds the
         * credential table in memory: ask it to reload so the change takes
         * effect without a restart (and a removal drops the session).
         */
        if (control_request(config_path, "reload", reply, sizeof(reply)) == 0) {
            printf("Running server asked to reload.\n");
        } else {
            printf("No running server for this configuration; the change "
                   "applies when it starts.\n");
        }

        return EXIT_SUCCESS;
    }

    if (set_limit != NULL || clear_limit != NULL) {
        const char *id = (set_limit != NULL) ? set_limit : clear_limit;
        const pipesix_client_policy_t *limits;
        char reply[1024];

        if (set_limit != NULL) {
            if (config_set_limits(&config, id,
                                  have_rate ? &rate_kbps : NULL,
                                  have_rate_in ? &rate_in_kbps : NULL,
                                  have_rate_out ? &rate_out_kbps : NULL,
                                  have_quota ? &quota_mib : NULL,
                                  have_warn ? &warn_percent : NULL) != 0) {
                fprintf(stderr,
                        "Error: cannot set limits for client '%s' in '%s'\n",
                        id, config_path);
                return EXIT_FAILURE;
            }
            printf("Limits for client '%s' in %s:\n", id, config_path);
        } else {
            if (config_clear_limits(&config, id) != 0) {
                fprintf(stderr,
                        "Error: cannot clear limits for client '%s' in "
                        "'%s'\n", id, config_path);
                return EXIT_FAILURE;
            }
            printf("Removed every limit for client '%s' in %s\n", id,
                   config_path);
        }

        limits = config_find_policy(&config, id);
        if (limits != NULL) {
            if (pipesix_policy_rate_in(limits) > 0 ||
                pipesix_policy_rate_out(limits) > 0) {
                printf("  rate:  in %llu / out %llu kbit/s\n",
                       (unsigned long long)pipesix_policy_rate_in(limits),
                       (unsigned long long)pipesix_policy_rate_out(limits));
            } else {
                printf("  rate:  unlimited\n");
            }

            if (limits->quota_mib > 0) {
                char period_name[24];

                policy_period_name(config.quota_period, period_name,
                                   sizeof(period_name));
                printf("  quota: %llu MiB per %s\n",
                       (unsigned long long)limits->quota_mib, period_name);
            } else {
                printf("  quota: unlimited\n");
            }

            if (limits->warn_percent > 0) {
                printf("  warn:  at %llu%% of the quota\n",
                       (unsigned long long)limits->warn_percent);
            }
        }

        if (control_request(config_path, "reload", reply, sizeof(reply)) == 0) {
            printf("Running server asked to reload.\n");
        } else {
            printf("No running server for this configuration; the change "
                   "applies when it starts.\n");
        }

        return EXIT_SUCCESS;
    }

    config_dump(&config);

    if (rotate_all) {
        int signalled;

        if (config_rotate_all_keys(&config) != 0) {
            return EXIT_FAILURE;
        }
        report_rotated_keys(&config);

        if (export_dir != NULL) {
            int i;

            for (i = 0; i < config.client_count; i++) {
                char path[CONFIG_PATH_MAX];

                if (snprintf(path, sizeof(path), "%s/%s.conf", export_dir,
                             config.clients[i].id) >= (int)sizeof(path) ||
                    write_client_config(&config, config.clients[i].id,
                                        server_address, path) != 0) {
                    fprintf(stderr, "Error: cannot export client '%s'\n",
                            config.clients[i].id);
                    return EXIT_FAILURE;
                }
                printf("Wrote client configuration for '%s' to %s\n",
                       config.clients[i].id, path);
            }
        }

#if defined(_WIN32)
        /* No signals: the running instance is reached through its events. */
        signalled = control_request_reload(config.config_path);
#else
        signalled = signal_running_instances(config.config_path, SIGHUP);
#endif
        if (signalled > 0) {
#if defined(_WIN32)
            printf("Asked the running pipesix to reload; the server has "
                   "adopted\nthe new keys.\n");
#else
            printf("Signalled %d running pipesix process(es) with SIGHUP; "
                   "the server\nhas adopted the new keys.\n", signalled);
#endif
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

    /*
     * --reload and --stats are the Windows equivalents of SIGHUP and
     * SIGUSR1; on POSIX they signal the instance through /proc, so the
     * behaviour is the same everywhere.
     */
    if (reload_only || stats_only) {
        int signalled;

#if defined(_WIN32)
        signalled = reload_only ? control_request_reload(config.config_path)
                                : control_request_stats(config.config_path);
#else
        signalled = signal_running_instances(config.config_path,
                                             reload_only ? SIGHUP : SIGUSR1);
#endif

        if (signalled > 0) {
            printf("Signalled %d running pipesix process(es): %s\n",
                   signalled, reload_only ? "reload the configuration"
                                          : "dump statistics");
            return EXIT_SUCCESS;
        }
        if (signalled == 0) {
            printf("No running pipesix uses this configuration; nothing to "
                   "signal.\n");
            return EXIT_FAILURE;
        }

        printf("Cannot find a running pipesix on this platform; reload it "
               "with 'systemctl reload pipesix'.\n");
        return EXIT_FAILURE;
    }

    log_info("Frame protection: %s",
             "ChaCha20-Poly1305 with per-client session keys");

    runtime_init();
    control_start(config.config_path);

    if (setup_signal_handlers() != 0) {
        log_error("Failed to setup signal handlers: %s", strerror(errno));
        return EXIT_FAILURE;
    }

    if (psix_net_init() != 0) {
        log_error("Failed to initialise the network stack");
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

    psix_net_shutdown();
    control_stop();

    if (ret != 0) {
        log_error("pipesix terminated with error");
        return EXIT_FAILURE;
    }

    log_info("pipesix terminated successfully");
    return EXIT_SUCCESS;
}
