/* *
 * Lightway Core
 * Copyright (C) 2023 Express VPN International Ltd.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 */

#ifndef HE_NETWORK_H
#define HE_NETWORK_H

#include "he.h"
#include "he_internal.h"

#pragma pack(1)

#define HE_IP_DONT_FRAGMENT (1 << 14)
#define HE_IP_NO_FRAG_OFFSET 0
#define HE_IP_MORE_FRAGMENTS (1 << 13)
#define HE_IP_FRAGMENT_OFFSET_MULTIPLIER 8
#define HE_IP_LENGTH_BITMASK 0x0F
typedef struct {
  uint8_t ver_ihl;  // 4 bits version and 4 bits internet header length
  uint8_t tos;
  uint16_t total_length;
  uint16_t id;
  uint16_t flags_fo;  // 3 bits flags and 13 bits fragment-offset
  uint8_t ttl;
  uint8_t protocol;
  uint16_t checksum;
  uint32_t src_addr;
  uint32_t dst_addr;
} ipv4_header_t;

#define HE_IP_TCP 0x06
#define HE_IP_UDP 0x11
#define HE_TCP_SYN 0x02
typedef struct {
  uint16_t src_port;
  uint16_t dst_port;
  uint32_t seq;
  uint32_t ack;
  uint8_t data_offset;  // 4 bits
  uint8_t flags;
  uint16_t window_size;
  uint16_t checksum;
  uint16_t urgent_p;
} tcp_header_t;

// https://www.rfc-editor.org/rfc/rfc9293.html#Option-Definitions
#define HE_TCP_OPT_END 0
#define HE_TCP_OPT_NOP 1
#define HE_TCP_OPT_MSS 2
#define HE_TCP_MSS_OPT_SIZE 4

typedef struct {
  uint8_t kind;
  uint8_t size;
} tcp_option_t;

typedef struct {
  uint16_t src_port;
  uint16_t dst_port;
  uint16_t length;
  uint16_t checksum;
} udp_header_t;

#pragma pack()

void he_internal_calculate_differential_checksum(uint16_t *cksum, void *newp, void *oldp, size_t n);
bool he_internal_is_ipv4_packet_valid(uint8_t *packet, size_t length);

#endif
