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

/*
 * Add the big-endian 16-bit words of data to a one's-complement sum.
 */
static uint32_t checksum_add(uint32_t sum, const uint8_t *data, size_t len)
{
    size_t i;

    for (i = 0; i + 1 < len; i += 2) {
        sum += ((uint32_t)data[i] << 8) | (uint32_t)data[i + 1];
    }

    if (i < len) {
        sum += (uint32_t)data[i] << 8;
    }

    return sum;
}

static uint16_t checksum_fold(uint32_t sum)
{
    while ((sum >> 16) != 0) {
        sum = (sum & 0xFFFFu) + (sum >> 16);
    }

    return (uint16_t)(~sum & 0xFFFFu);
}

size_t ipv6_build_packet_too_big(uint8_t *buf, size_t bufsize,
                                 const uint8_t src[16], const uint8_t dst[16],
                                 uint32_t mtu,
                                 const uint8_t *packet, size_t packet_len)
{
    /* RFC 4443: quote as much as possible without exceeding 1280 bytes. */
    const size_t max_quote = 1280u - IPV6_HEADER_LEN - ICMPV6_PTB_HEADER_LEN;
    pipesix_ipv6_header_t *header;
    uint32_t sum = 0;
    uint8_t pseudo[40];
    size_t quote_len;
    size_t icmp_len;
    size_t total;
    uint16_t checksum;
    uint32_t icmp32;

    if (buf == NULL || src == NULL || dst == NULL || packet == NULL) {
        return 0;
    }

    quote_len = (packet_len < max_quote) ? packet_len : max_quote;
    icmp_len = ICMPV6_PTB_HEADER_LEN + quote_len;
    total = IPV6_HEADER_LEN + icmp_len;

    if (total > bufsize) {
        return 0;
    }

    memset(buf, 0, total);

    header = (pipesix_ipv6_header_t *)(void *)buf;
    header->vtc_flow = htonl(6u << 28);
    header->payload_length = htons((uint16_t)icmp_len);
    header->next_header = IPV6_NEXT_ICMPV6;
    header->hop_limit = 64;
    memcpy(header->source_addr, src, 16);
    memcpy(header->dest_addr, dst, 16);

    /* ICMPv6 header: type, code, checksum, MTU. */
    buf[IPV6_HEADER_LEN] = (uint8_t)ICMPV6_TYPE_PACKET_TOO_BIG;
    buf[IPV6_HEADER_LEN + 1] = 0;
    buf[IPV6_HEADER_LEN + 2] = 0;
    buf[IPV6_HEADER_LEN + 3] = 0;
    icmp32 = htonl(mtu);
    memcpy(&buf[IPV6_HEADER_LEN + 4], &icmp32, sizeof(icmp32));
    memcpy(&buf[IPV6_HEADER_LEN + ICMPV6_PTB_HEADER_LEN], packet, quote_len);

    /*
     * The kernel does not fill in the checksum of a packet written to a
     * TUN device, so compute it over the IPv6 pseudo-header.
     */
    memcpy(pseudo, src, 16);
    memcpy(pseudo + 16, dst, 16);
    icmp32 = htonl((uint32_t)icmp_len);
    memcpy(pseudo + 32, &icmp32, sizeof(icmp32));
    pseudo[36] = 0;
    pseudo[37] = 0;
    pseudo[38] = 0;
    pseudo[39] = (uint8_t)IPV6_NEXT_ICMPV6;

    sum = checksum_add(sum, pseudo, sizeof(pseudo));
    sum = checksum_add(sum, buf + IPV6_HEADER_LEN, icmp_len);
    checksum = checksum_fold(sum);

    buf[IPV6_HEADER_LEN + 2] = (uint8_t)(checksum >> 8);
    buf[IPV6_HEADER_LEN + 3] = (uint8_t)(checksum & 0xFFu);

    return total;
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
