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
 *   pipesix --rotate-all          Replace every client key in a server config
 *   pipesix -V                    Show version information
 *
 * Command-Line Options:
 *   -c, --config <path>     Configuration file (default /etc/pipesix/pipesix.conf)
 *   -t, --check             Validate configuration without touching the network
 *   -l, --log-level <name>  Override the configured log level
 *   -g, --genkey            Generate a per-client pre-shared key
 *   -R, --rotate-all        Generate and apply a new key for every client
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

#include <errno.h>
#include <getopt.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

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
            "                          'client' entry, then print them (server)\n"
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
           "Put each key in the matching client's 'secret' line. Live\n"
           "sessions keep running until the server reloads, and a client\n"
           "whose key is not updated cannot handshake again, so reload the\n"
           "server first and then each client:\n"
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
        if (config_rotate_all_keys(&config) != 0) {
            return EXIT_FAILURE;
        }
        report_rotated_keys(&config);
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
