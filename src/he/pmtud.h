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

#include "he.h"

/// The maximum value of the PROBE_COUNT counter. MAX_PROBES represents the limit for the number of
/// consecutive probe attempts of any size.
#define MAX_PROBES 3

/// The smallest PMTU the discovery process will attempt to use
#define MIN_PLPMTU 512

/// The largest PMTU the discovery process will attempt to use
#define MAX_PLPMTU                                                                      \
  (HE_MAX_WIRE_MTU - HE_IPV4_HEADER_SIZE - HE_UDP_HEADER_SIZE - sizeof(he_wire_hdr_t) - \
   HE_WOLF_MAX_HEADER_SIZE - sizeof(he_msg_data_t))

/// The default timeout for waiting for an acknowledgement to a probe packet, in milliseconds.
#define PMTUD_PROBE_TIMEOUT_MS 5000

/// Number of bytes to increase for the next PROBED_SIZE
#define PMTUD_PROBE_BIG_STEP 32

/// The minimal number of bytes to increase for the next PROBED_SIZE
#define PMTUD_PROBE_SMALL_STEP 8

/// The default timeout for retrying a failed PMTUD probe
#define PMTUD_ERROR_RETRY_TIMEOUT_MS (60 * 1000)

// Internal functions for PMTUD

/**
 * @brief Send PMTUD probe message with the given probe mtu size.
 * @param conn A pointer to a valid connection conn
 * @return HE_SUCCESS if the probe message is sent successfully
 * @note This function triggers a pmtud_time_cb callback.
 */
he_return_code_t he_internal_pmtud_send_probe(he_conn_t *conn, uint16_t probe_mtu);

/**
 * @brief Called when the conn receives an acknowledgement of a probe message.
 * @param conn A pointer to a valid connection conn
 * @param probe_id Id of the probe message
 * @return HE_SUCCESS if the probe ack message is handled
 * @note This function may trigger pmtud_time_cb and/or pmtud_state_change callbacks depending on
 * current state.
 */
he_return_code_t he_internal_pmtud_handle_probe_ack(he_conn_t *conn, uint16_t probe_id);

/**
 * @brief Called when the timer of a probe expired.
 * @param conn A pointer to a valid connection conn
 * @return HE_SUCCESS if the probe timeout is handled
 * @note This function may trigger pmtud_time_cb and/or pmtud_state_change callbacks depending on
 * current state.
 */
he_return_code_t he_internal_pmtud_handle_probe_timeout(he_conn_t *conn);

/**
 * @brief Start PMTUD discovery and change state to BASE.
 * @param conn A pointer to a valid connection conn
 * @return HE_SUCCESS if the operation succeeds. HE_ERR_INVALID_STATE if current PMTUD state is not
 * DISABLED or SEARCHING or SEARCH_COMPLETE.
 * @note This function changes conn->pmtu_state and triggers a pmtud_state_change_cb callback.
 */
he_return_code_t he_internal_pmtud_start_base_probing(he_conn_t *conn);

/**
 * @brief Called when the acknowledgement of current BASE_PLPMTU probing received.
 * @param conn A pointer to a valid connection conn
 * @return HE_SUCCESS if the operation succeeds. HE_ERR_INVALID_STATE if current PMTUD state is not
 * BASE.
 * @note This function triggers a pmtud_state_change_cb callback to enter the Searching state.
 */
he_return_code_t he_internal_pmtud_base_confirmed(he_conn_t *conn);

/**
 * @brief Called when current state is BASE and PROBE_COUNT reaches MAX_PROBES.
 * @param conn A pointer to a valid connection conn
 * @return HE_SUCCESS if the operation succeeds. HE_ERR_INVALID_STATE if current PMTUD state is not
 * BASE.
 * @note This function changes conn->pmtu_state and triggers a pmtud_state_change_cb callback.
 */
he_return_code_t he_internal_pmtud_confirm_base_failed(he_conn_t *conn);

/**
 * @brief Called when probing for the BASE_PLPMTU completes.
 * @param conn A pointer to a valid connection conn
 * @return HE_SUCCESS if the operation succeeds. HE_ERR_INVALID_STATE if current PMTUD state is not
 * BASE or SEARCH_COMPLETE or ERROR.
 * @note This function changes conn->pmtu_state and triggers a pmtud_state_change_cb callback. While
 * PMTUD stays in the SEARCHING state, it will trigger the pmtud_time_cb callback for each probing
 * attempt.
 */
he_return_code_t he_internal_pmtud_start_searching(he_conn_t *conn);

/**
 * @brief Called when the PROBE_COUNT reaches MAX_PROBES, a validated PTB is received that
 * corresponds to the last successfully probed size (PL_PTB_SIZE = PLPMTU), or a probe of size
 * MAX_PLPMTU is acknowledged (PLPMTU = MAX_PLPMTU)
 * @param conn A pointer to a valid connection conn
 * @return HE_SUCCESS if the operation succeeds. HE_ERR_INVALID_STATE if current PMTUD state is not
 * SEARCHING.
 * @note This function changes conn->pmtu_state and triggers a pmtud_state_change_cb callback. This
 * function will also trigger a pmtud_time_cb callback to check the current PMTU periodically.
 */
he_return_code_t he_internal_pmtud_search_completed(he_conn_t *conn);

/**
 * @brief Called when a black hole situation is detected.
 * @param conn A pointer to a valid connection conn
 * @return HE_SUCCESS if the operation succeeds. HE_ERR_INVALID_STATE if current PMTUD state is not
 * SEARCHING.
 * @note This function triggers a pmtud_state_change_cb callback to enter the BASE state.
 */
he_return_code_t he_internal_pmtud_blackhole_detected(he_conn_t *conn);

/**
 * @brief Called when we want to retry probing
 * @param conn A pointer to a valid connection conn
 * @param delay_ms Delay in milliseconds to retry probing
 * @return HE_SUCCESS if the operation succeeds. HE_ERR_PMTUD_CALLBACKS_NOT_SET if PMTUD callbacks
 * are not set. Else it is the result of a pmtud_time_cb call.
 * @note This function will also trigger a pmtud_time_cb callback to start the probe after the
 * specified delay.
 */
he_return_code_t he_internal_pmtud_retry_probe(he_conn_t *conn, int delay_ms);

#endif  // PMTUD_H
