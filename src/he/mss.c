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

#include "mss.h"
#include "network.h"

he_return_code_t he_clamp_mss(uint8_t *packet, size_t length, uint16_t mss) {
    // If packet is null or length is zero return
  if(!packet) {
    return HE_ERR_NULL_POINTER;
  }

  if (!length) {
    return HE_ERR_ZERO_SIZE;
  }

  // Ensure that the mss is a valid value
  if (mss < MIN_PLPMTU || mss > HE_MAX_WIRE_MTU) {
    return HE_ERR_FAILED;
  }

  // We only handle IPv4 packets for now
  if(!he_internal_is_ipv4_packet_valid(packet, length)) {
    return HE_ERR_BAD_PACKET;
  }

  // Check there's enough space
  if(sizeof(ipv4_header_t) > *length) {
    return;
  }

  // Apply IPv4 header
  ipv4_header_t *ip = (ipv4_header_t *)packet;

  // Check to see if this is TCP, ignore non-TCP packets
  if(ip->protocol != HE_IP_TCP) {
    return HE_SUCCESS;
  }

  // Make sure it isn't a fragment with an offset other than zero (first packet)
  uint16_t temp_frag_flags = ntohs(ip->flags_fo);

  // Remove the option flags
  temp_frag_flags = temp_frag_flags & ~(HE_IP_DONT_FRAGMENT | HE_IP_MORE_FRAGMENTS);

  if(temp_frag_flags != HE_IP_NO_FRAG_OFFSET) {
    // It has an offset so does not contain the TCP header
    return HE_SUCCESS;
  }

  // Calculate IP header length
  int ip_header_len = 4 * (ip->ver_ihl & 0x0F);

  // Check there's enough space
  if(ip_header_len + sizeof(tcp_header_t) > length) {
    return HE_SUCCESS;
  }

  // Apply TCP header
  tcp_header_t *tcp = (tcp_header_t *)(packet + ip_header_len);

  // Skip if not a SYN packet
  if(!(tcp->flags & HE_TCP_SYN)) {
    return HE_SUCCESS;
  }

  // Determine if there are any options
  uint8_t tcp_offset = tcp->data_offset >> 4;
  int tcp_header_len = (tcp_offset * 4);
  int options_len = tcp_header_len - sizeof(tcp_header_t);

  // Check to make sure we're in bounds
  if(ip_header_len + tcp_header_len > length) {
    return HE_SUCCESS;
  }

  // Pointer to where the options start
  uint8_t *options = (uint8_t *)(packet + ip_header_len + sizeof(tcp_header_t));

  // TCP Options - look for MSS
  while(options_len > 0) {
    tcp_option_t *opt = (tcp_option_t *)options;

    // NOP is just one byte, special handling
    if(opt->kind == HE_TCP_OPT_NOP) {
      options_len--;
      options++;
      continue;
    }

    // We found the MSS fix entry - let's change it
    if(opt->kind == HE_TCP_OPT_MSS) {
      // Copy out the current MSS value from the packet
      uint16_t current_mss = 0;
      uint16_t current_mss_be = 0;
      memcpy(&current_mss_be, (uint8_t *)opt + sizeof(tcp_option_t), sizeof(uint16_t));
      // Convert it to host byte order
      current_mss = ntohs(current_mss_be);

      // Don't do anything if the mss is lower than our setting
      if(current_mss <= mss) {
        // Nothing to do
        return HE_SUCCESS;
      }

      // We're going to need the BE version of our MSS to copy into the packet
      uint16_t mss_be = htons(mss);

      // Copy in the new MSS value
      memcpy((uint8_t *)opt + sizeof(tcp_option_t), &mss_be, sizeof(uint16_t));

      // Recompute the TCP checksum incrementally
      he_internal_calculate_differential_checksum(&tcp->checksum, &mss_be, &current_mss_be, 1);

      // Return as we don't care about other options
      return HE_SUCCESS;
    }

    // This is the end of options separator
    if(opt->kind == 0) {
      break;
    }

    // Skip over any other option types
    options_len -= opt->size;
    options += opt->size;
  }

  return HE_SUCCESS;
}
