/*
 * ipv6.c - IPv6 Packet Parsing Utilities Implementation
 *
 * Implements lightweight utilities for parsing and logging IPv6 packet
 * headers. These functions are used for diagnostic purposes to provide
 * visibility into the traffic flowing through the tunnel.
 */

#include "ipv6.h"
#include "logger.h"

#if defined(_WIN32)
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <arpa/inet.h>
#endif
#include <string.h>

/*
 * Extract the IPv6 version from the first 32-bit word.
 */
static int ipv6_get_version(uint32_t vtc_flow)
{
    return (int)((ntohl(vtc_flow) >> 28) & 0x0F);
}

const char *ipv6_addr_to_str(const uint8_t addr[16], char *buf, size_t size)
{
    if (addr == NULL || buf == NULL || size < INET6_ADDRSTRLEN) {
        return NULL;
    }

    return inet_ntop(AF_INET6, addr, buf, (socklen_t)size);
}

int ipv6_parse_header(const uint8_t *data, size_t length,
                      const pipesix_ipv6_header_t **header)
{
    if (data == NULL || header == NULL) {
        return -1;
    }

    /* Must be at least as long as the IPv6 header */
    if (length < IPV6_HEADER_LEN) {
        return -1;
    }

    *header = (const pipesix_ipv6_header_t *)data;

    /* Validate IPv6 version */
    if (ipv6_get_version((*header)->vtc_flow) != 6) {
        return -1;
    }

    return 0;
}

int ipv6_validate_packet(const uint8_t *data, size_t length)
{
    const pipesix_ipv6_header_t *header;

    if (ipv6_parse_header(data, length, &header) != 0) {
        return -1;
    }

    if ((size_t)ntohs(header->payload_length) + (size_t)IPV6_HEADER_LEN !=
        length) {
        return -1;
    }

    return 0;
}

int ipv6_prefix_match(const uint8_t prefix[16], int prefix_len,
                      const uint8_t addr[16])
{
    int whole_bytes;
    int remainder;
    uint8_t mask;

    if (prefix == NULL || addr == NULL) {
        return 0;
    }
    if (prefix_len < 0 || prefix_len > 128) {
        return 0;
    }

    whole_bytes = prefix_len / 8;
    remainder = prefix_len % 8;

    if (whole_bytes > 0 &&
        memcmp(prefix, addr, (size_t)whole_bytes) != 0) {
        return 0;
    }

    if (remainder == 0) {
        return 1;
    }

    /* whole_bytes <= 15 whenever remainder > 0, so this index is safe. */
    mask = (uint8_t)(0xFFu << (8 - remainder));

    return (prefix[whole_bytes] & mask) == (addr[whole_bytes] & mask);
}

void ipv6_log_packet(const uint8_t *data, size_t length, const char *prefix)
{
    const pipesix_ipv6_header_t *hdr;
    char src_str[INET6_ADDRSTRLEN];
    char dst_str[INET6_ADDRSTRLEN];
    const char *proto_str = "UNKN";

    (void)length;

    if (data == NULL || prefix == NULL) {
        return;
    }

    if (ipv6_parse_header(data, length, &hdr) != 0) {
        return;
    }

    /* Format source and destination addresses */
    ipv6_addr_to_str(hdr->source_addr, src_str, sizeof(src_str));
    ipv6_addr_to_str(hdr->dest_addr, dst_str, sizeof(dst_str));

    /* Map protocol number to human-readable string */
    switch (hdr->next_header) {
        case IPV6_NEXT_TCP:    proto_str = "TCP";   break;
        case IPV6_NEXT_UDP:    proto_str = "UDP";   break;
        case IPV6_NEXT_ICMPV6: proto_str = "ICMP6"; break;
        default:               proto_str = "UNKN";  break;
    }

    log_debug("[%s] %s %s -> %s (len=%u, hlim=%u)",
              prefix,
              proto_str,
              src_str,
              dst_str,
              (unsigned)ntohs(hdr->payload_length),
              (unsigned)hdr->hop_limit);
}
