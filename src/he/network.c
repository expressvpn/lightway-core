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

#include "network.h"

void he_internal_calculate_differential_checksum(uint16_t *cksum, void *newp, void *oldp, size_t n) {
  size_t i;
  int32_t accumulate;
  uint16_t *newv = (uint16_t *)newp;
  uint16_t *oldv = (uint16_t *)oldp;

  accumulate = *cksum;
  for(i = 0; i < n; i++) {
    accumulate -= *newv;
    accumulate += *oldv;

    newv++;
    oldv++;
  }

  if(accumulate < 0) {
    accumulate = -accumulate;
    accumulate = (accumulate >> 16) + (accumulate & 0xffff);
    accumulate += accumulate >> 16;
    *cksum = (uint16_t)~accumulate;
  } else {
    accumulate = (accumulate >> 16) + (accumulate & 0xffff);
    accumulate += accumulate >> 16;
    *cksum = (uint16_t)accumulate;
  }
}

bool he_internal_is_ipv4_packet_valid(uint8_t *packet, size_t length) {
  if(packet == NULL || length < 1) {
    return false;
  }
  // for now just check that the packet is IPv4
  int proto = packet[0] >> 4;

  if(proto != 4) {
    return false;
  }

  // Assume it's good enough
  return true;
}
