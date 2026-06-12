/*
 * config.c - pipesix Configuration Implementation
 *
 * Implements a flat key-value configuration file parser. The format
 * is simple and human-readable:
 *
 *   # This is a comment
 *   key = value
 *
 * Leading and trailing whitespace is stripped from keys and values.
 * Unknown keys are silently ignored to allow forward compatibility.
 * Required fields are validated after loading.
 */

#include "config.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <ctype.h>
#include <errno.h>

/*
 * Trim leading and trailing whitespace from a string in place.
 *
 * Parameters:
 *   str - NUL-terminated string to trim
 *
 * Returns:
 *   Pointer to the trimmed string (same buffer)
 */
static char *str_trim(char *str)
{
    char *end;

    /* Trim leading space */
    while (isspace((unsigned char)*str)) {
        str++;
    }

    /* Trim trailing space */
    end = str + strlen(str) - 1;
    while (end > str && isspace((unsigned char)*end)) {
        end--;
    }

    /* Write new null terminator */
    *(end + 1) = '\0';

    return str;
}

/*
 * Set default values for all configuration fields.
 *
 * Parameters:
 *   config - Configuration structure to initialize
 */
static void config_set_defaults(pipesix_config_t *config)
{
    memset(config, 0, sizeof(*config));

    strncpy(config->tun_name, CONFIG_DEFAULT_TUN_NAME, CONFIG_MAX_TUN_NAME - 1);
    config->tun_prefixlen = CONFIG_DEFAULT_TUN_PREFIX;
    config->tun_mtu       = CONFIG_DEFAULT_TUN_MTU;
    config->remote_port   = CONFIG_DEFAULT_PORT;
    strncpy(config->bind_address, CONFIG_DEFAULT_BIND_ADDRESS, CONFIG_MAX_ADDRESS - 1);
    config->bind_port     = CONFIG_DEFAULT_PORT;
    config->log_level     = CONFIG_DEFAULT_LOG_LEVEL;
}

/*
 * Parse a log level string into the corresponding enum value.
 *
 * Parameters:
 *   str   - Log level string (case-insensitive)
 *   level - Output parameter for parsed level
 *
 * Returns:
 *   0 on success, -1 if the string is not a valid log level
 */
static int parse_log_level(const char *str, log_level_t *level)
{
    if (strcasecmp(str, "debug") == 0)  { *level = LOG_DEBUG; return 0; }
    if (strcasecmp(str, "info") == 0)   { *level = LOG_INFO;  return 0; }
    if (strcasecmp(str, "warn") == 0)   { *level = LOG_WARN;  return 0; }
    if (strcasecmp(str, "error") == 0)  { *level = LOG_ERROR; return 0; }
    if (strcasecmp(str, "fatal") == 0)  { *level = LOG_FATAL; return 0; }
    return -1;
}

/*
 * Process a single key=value line and update the configuration.
 *
 * Parameters:
 *   config - Configuration structure to update
 *   key    - Trimmed key string
 *   value  - Trimmed value string
 */
static void config_set_value(pipesix_config_t *config, const char *key, const char *value)
{
    if (strcmp(key, "mode") == 0) {
        strncpy(config->mode, value, CONFIG_MAX_MODE - 1);
    } else if (strcmp(key, "tun_name") == 0) {
        strncpy(config->tun_name, value, CONFIG_MAX_TUN_NAME - 1);
    } else if (strcmp(key, "tun_address") == 0) {
        strncpy(config->tun_address, value, CONFIG_MAX_ADDRESS - 1);
    } else if (strcmp(key, "tun_prefixlen") == 0) {
        config->tun_prefixlen = atoi(value);
    } else if (strcmp(key, "tun_mtu") == 0) {
        config->tun_mtu = atoi(value);
    } else if (strcmp(key, "remote_address") == 0) {
        strncpy(config->remote_address, value, CONFIG_MAX_ADDRESS - 1);
    } else if (strcmp(key, "remote_port") == 0) {
        config->remote_port = atoi(value);
    } else if (strcmp(key, "bind_address") == 0) {
        strncpy(config->bind_address, value, CONFIG_MAX_ADDRESS - 1);
    } else if (strcmp(key, "bind_port") == 0) {
        config->bind_port = atoi(value);
    } else if (strcmp(key, "log_level") == 0) {
        log_level_t level;
        if (parse_log_level(value, &level) == 0) {
            config->log_level = level;
        }
    }
    /* Unknown keys are silently ignored */
}

int config_load(const char *path, pipesix_config_t *config)
{
    FILE *fp;
    char line[4096];
    unsigned int line_num = 0;

    if (config == NULL || path == NULL) {
        fprintf(stderr, "config_load: invalid parameters\n");
        return -1;
    }

    /* Initialize with defaults */
    config_set_defaults(config);

    /* Open configuration file */
    fp = fopen(path, "r");
    if (fp == NULL) {
        fprintf(stderr, "config_load: cannot open '%s': %s\n",
                path, strerror(errno));
        return -1;
    }

    /* Parse each line */
    while (fgets(line, sizeof(line), fp) != NULL) {
        char *ptr, *key, *value;

        line_num++;

        /* Remove trailing newline/carriage return */
        ptr = line + strlen(line);
        while (ptr > line && (*(ptr - 1) == '\n' || *(ptr - 1) == '\r')) {
            *(--ptr) = '\0';
        }

        /* Skip empty lines and comments */
        ptr = line;
        while (isspace((unsigned char)*ptr)) ptr++;
        if (*ptr == '\0' || *ptr == '#') {
            continue;
        }

        /* Find the '=' separator */
        value = strchr(line, '=');
        if (value == NULL) {
            fprintf(stderr, "config_load: %s:%u: malformed line (no '=')\n",
                    path, line_num);
            fclose(fp);
            return -1;
        }

        /* Split into key and value */
        *value = '\0';
        key = str_trim(line);
        value = str_trim(value + 1);

        if (*key == '\0') {
            fprintf(stderr, "config_load: %s:%u: empty key\n",
                    path, line_num);
            fclose(fp);
            return -1;
        }

        config_set_value(config, key, value);
    }

    fclose(fp);
    return 0;
}

int config_validate(const pipesix_config_t *config)
{
    if (config == NULL) {
        return -1;
    }

    /* Validate mode */
    if (strlen(config->mode) == 0) {
        log_error("Configuration validation failed: 'mode' is required (client or server)");
        return -1;
    }

    if (strcmp(config->mode, "client") != 0 &&
        strcmp(config->mode, "server") != 0) {
        log_error("Configuration validation failed: 'mode' must be 'client' or 'server' (got '%s')",
                  config->mode);
        return -1;
    }

    /* Validate TUN configuration */
    if (strlen(config->tun_address) == 0) {
        log_error("Configuration validation failed: 'tun_address' is required");
        return -1;
    }

    if (config->tun_prefixlen < 0 || config->tun_prefixlen > 128) {
        log_error("Configuration validation failed: 'tun_prefixlen' must be 0-128 (got %d)",
                  config->tun_prefixlen);
        return -1;
    }

    if (config->tun_mtu < 576 || config->tun_mtu > 65535) {
        log_warn("TUN MTU %d is unusual (expected 576-65535)", config->tun_mtu);
    }

    /* Validate mode-specific fields */
    if (strcmp(config->mode, "client") == 0) {
        if (strlen(config->remote_address) == 0) {
            log_error("Configuration validation failed: 'remote_address' is required in client mode");
            return -1;
        }
        if (config->remote_port <= 0 || config->remote_port > 65535) {
            log_error("Configuration validation failed: 'remote_port' must be 1-65535 (got %d)",
                      config->remote_port);
            return -1;
        }
    }

    if (strcmp(config->mode, "server") == 0) {
        if (strlen(config->bind_address) == 0) {
            log_error("Configuration validation failed: 'bind_address' is required in server mode");
            return -1;
        }
        if (config->bind_port <= 0 || config->bind_port > 65535) {
            log_error("Configuration validation failed: 'bind_port' must be 1-65535 (got %d)",
                      config->bind_port);
            return -1;
        }
    }

    return 0;
}

void config_dump(const pipesix_config_t *config)
{
    if (config == NULL) return;

    log_info("Configuration:");
    log_info("  mode            = %s", config->mode);
    log_info("  tun_name        = %s", config->tun_name);
    log_info("  tun_address     = %s/%d", config->tun_address, config->tun_prefixlen);
    log_info("  tun_mtu         = %d", config->tun_mtu);

    if (strcmp(config->mode, "client") == 0) {
        log_info("  remote_address  = %s", config->remote_address);
        log_info("  remote_port     = %d", config->remote_port);
    }

    if (strcmp(config->mode, "server") == 0) {
        log_info("  bind_address    = %s", config->bind_address);
        log_info("  bind_port       = %d", config->bind_port);
    }

    /* Convert log level back to string for display */
    const char *level_str = "UNKNOWN";
    switch (config->log_level) {
        case LOG_DEBUG: level_str = "debug"; break;
        case LOG_INFO:  level_str = "info";  break;
        case LOG_WARN:  level_str = "warn";  break;
        case LOG_ERROR: level_str = "error"; break;
        case LOG_FATAL: level_str = "fatal"; break;
    }
    log_info("  log_level       = %s", level_str);
}
