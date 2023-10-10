/**
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

/**
 * @file pmtud.h
 * @brief Path MTU Discovery functions
 *
 */

#ifndef PMTUD_H
#define PMTUD_H

/// The maximum value of the PROBE_COUNT counter. MAX_PROBES represents the limit for the number of
/// consecutive probe attempts of any size.
#define MAX_PROBES 3

/// The smallest PMTU the discovery process will attempt to use
#define MIN_PLPMTU 512

/// The largest PMTU the discovery process will attempt to use
#define MAX_PLPMTU                                                                      \
  (HE_MAX_WIRE_MTU - HE_IPV4_HEADER_SIZE - HE_UDP_HEADER_SIZE - sizeof(he_wire_hdr_t) - \
   HE_WOLF_MAX_HEADER_SIZE - sizeof(he_msg_data_t))

// Internal functions for PMTUD

/**
 * @brief Change PMTUD state
 */
void he_internal_change_pmtud_state(he_conn_t *conn, he_pmtud_state_t state);

/**
 * @brief Update PMTUD state machine.
 */
void he_internal_pmtud_update(he_conn_t *conn);

/**
 * @brief Send PMTUD probe message with the given probe mtu size.
 */
he_return_code_t he_internal_pmtud_send_probe(he_conn_t *conn, uint16_t probe_mtu);

#endif  // PMTUD_H
