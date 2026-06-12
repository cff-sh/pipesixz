/*
 * main.c - pipesix IPv6 over UDP Tunnel - Entry Point
 *
 * pipesix is an IPv6 tunneling application that forwards IPv6 packets
 * between a local TUN device and a remote peer over UDP. It is designed
 * to connect applications on a client machine to a Route64 IPv6 subnet
 * through a VPS-based relay server.
 *
 * Architecture:
 *
 *   [Client Machine]
 *   Applications -> TUN (tun0) -> pipesix client -> UDP -> Internet
 *                                                          |
 *   [VPS Server]                                           |
 *   Internet -> UDP -> pipesix server -> TUN (tun0) -> Route64 Gateway
 *
 * Usage:
 *   pipesix -c /path/to/pipesix.conf
 *
 * The configuration file specifies the operating mode (client or server),
 * TUN device parameters, and endpoint addresses.
 *
 * Command-Line Options:
 *   -c <path>   Path to configuration file (required)
 *   -h          Display help information
 */

#include "config.h"
#include "logger.h"
#include "client.h"
#include "server.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>

/*
 * Global running flag.
 * Set to 0 by the signal handler to request graceful shutdown.
 * Accessed by signal handler (async-signal-safe) and main loop.
 */
static volatile sig_atomic_t g_running = 1;

/*
 * Path to the configuration file, stored globally so the signal
 * handler (which has limited context) could theoretically access it.
 * Currently unused in the handler but available for future cleanup.
 */
static char g_config_path[4096] = {0};

/*
 * Signal Handler
 *
 * Handles SIGINT (Ctrl+C) and SIGTERM (system shutdown) by setting
 * the global running flag to 0. This triggers a graceful shutdown
 * of the worker threads and clean resource deallocation.
 *
 * This function must be async-signal-safe (no complex operations).
 */
static void signal_handler(int sig)
{
    (void)sig;

    /* Signal all components to stop */
    g_running = 0;
}

/*
 * Setup signal handlers for graceful shutdown.
 *
 * Registers handlers for SIGINT and SIGTERM. SIGPIPE is ignored
 * to prevent the process from dying on broken socket connections.
 *
 * Returns:
 *   0 on success, -1 if sigaction() fails
 */
static int setup_signal_handlers(void)
{
    struct sigaction sa;

    /*
     * Configure SIGINT (Ctrl+C) and SIGTERM (termination request)
     * to trigger graceful shutdown.
     */
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = signal_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;

    if (sigaction(SIGINT, &sa, NULL) < 0) {
        return -1;
    }

    if (sigaction(SIGTERM, &sa, NULL) < 0) {
        return -1;
    }

    /*
     * Ignore SIGPIPE to prevent the process from being terminated
     * when writing to a closed socket/pipe. write() will return
     * EPIPE instead, which is handled by the worker threads.
     */
    sa.sa_handler = SIG_IGN;
    if (sigaction(SIGPIPE, &sa, NULL) < 0) {
        return -1;
    }

    return 0;
}

/*
 * Print usage information to stderr.
 */
static void print_usage(const char *progname)
{
    fprintf(stderr,
            "Usage: %s -c <config_file>\n"
            "\n"
            "pipesix - IPv6 over UDP Tunnel\n"
            "\n"
            "Options:\n"
            "  -c <path>   Path to configuration file\n"
            "  -h          Show this help message\n"
            "\n"
            "Configuration file format (key = value):\n"
            "  mode            Operating mode: client | server\n"
            "  tun_name        TUN device name (default: tun0)\n"
            "  tun_address     IPv6 address for TUN device\n"
            "  tun_prefixlen   IPv6 prefix length (default: 64)\n"
            "  tun_mtu         TUN device MTU (default: 1500)\n"
            "  remote_address  Server address (client mode)\n"
            "  remote_port     Server port (client mode, default: 8899)\n"
            "  bind_address    Bind address (server mode, default: 0.0.0.0)\n"
            "  bind_port       Bind port (server mode, default: 8899)\n"
            "  log_level       Log level: debug | info | warn | error | fatal\n"
            "\n"
            "Example:\n"
            "  pipesix -c /etc/pipesix/pipesix.conf\n",
            progname);
}

int main(int argc, char *argv[])
{
    pipesix_config_t config;
    int opt;

    /*
     * Parse command-line options.
     * Currently supports -c for configuration file path.
     */
    while ((opt = getopt(argc, argv, "c:h")) != -1) {
        switch (opt) {
            case 'c':
                strncpy(g_config_path, optarg, sizeof(g_config_path) - 1);
                break;
            case 'h':
            default:
                print_usage(argv[0]);
                return (opt == 'h') ? EXIT_SUCCESS : EXIT_FAILURE;
        }
    }

    /* Configuration file is required */
    if (g_config_path[0] == '\0') {
        fprintf(stderr, "Error: No configuration file specified\n");
        print_usage(argv[0]);
        return EXIT_FAILURE;
    }

    /*
     * Initialize the logging system.
     * Default level is INFO; config_load may override this.
     */
    logger_init(NULL);

    /*
     * Load and validate configuration.
     * If loading or validation fails, report and exit.
     */
    log_info("Loading configuration from '%s'", g_config_path);

    if (config_load(g_config_path, &config) != 0) {
        log_error("Failed to load configuration from '%s'", g_config_path);
        return EXIT_FAILURE;
    }

    /* Override log level from configuration */
    logger_set_level(config.log_level);

    if (config_validate(&config) != 0) {
        log_error("Configuration validation failed");
        return EXIT_FAILURE;
    }

    /* Display the loaded configuration for operational visibility */
    config_dump(&config);

    /*
     * Setup signal handlers before starting any threads.
     * This ensures signals are properly caught during operation.
     */
    if (setup_signal_handlers() != 0) {
        log_error("Failed to setup signal handlers: %s", strerror(errno));
        return EXIT_FAILURE;
    }

    /*
     * Dispatch to the appropriate operating mode.
     * The mode is determined by the configuration file.
     */
    int ret;

    if (strcmp(config.mode, "client") == 0) {
        log_info("Starting pipesix in CLIENT mode");
        ret = client_start(&config);
    } else if (strcmp(config.mode, "server") == 0) {
        log_info("Starting pipesix in SERVER mode");
        ret = server_start(&config);
    } else {
        log_error("Unknown mode '%s' (must be 'client' or 'server')", config.mode);
        return EXIT_FAILURE;
    }

    if (ret != 0) {
        log_error("pipesix terminated with error");
        return EXIT_FAILURE;
    }

    log_info("pipesix terminated successfully");
    return EXIT_SUCCESS;
}
