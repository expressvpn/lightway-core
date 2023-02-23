/* *
 * Lightway Core
 * Copyright (C) 2021 Express VPN International Ltd.
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
 * @file conn_internal.h
 * @brief Internal functions for managing the connection
 *
 */

#ifndef CONN_INTERNAL_H
#define CONN_INTERNAL_H

#include "he_internal.h"

he_return_code_t he_internal_conn_configure(he_conn_t *conn, he_ssl_ctx_t *ctx);

void he_internal_change_conn_state(he_conn_t *conn, he_conn_state_t state);

/**
 * @brief Sends a message over the secured tunnel
 * @param conn A pointer to a valid connection
 * @param message A pointer to the raw message to be sent
 * @param length The length of the message
 * @return he_conn_return_code_t HE_SUCCESS
 */
he_return_code_t he_internal_send_message(he_conn_t *conn, uint8_t *message, uint16_t length);
he_return_code_t he_internal_send_goodbye(he_conn_t *conn);
he_return_code_t he_internal_send_auth(he_conn_t *conn);

bool he_internal_is_valid_state_for_server_config(he_conn_t *conn);

he_return_code_t he_internal_renegotiate_ssl(he_conn_t *conn);

/**
 * @brief Updates the timeout for a connection and triggers the timeout callback if set
 * @param conn A pointer to a valid connection
 */
void he_internal_update_timeout(he_conn_t *conn);

void he_internal_generate_event(he_conn_t *conn, he_conn_event_t event);

size_t he_internal_calculate_data_packet_length(he_conn_t *conn, size_t length);

/**
 * @brief Generate a random session ID
 * @param conn A pointer to a valid server connection
 * @param session_id_out A pointer to a uint64_t, where we will write the session ID
 * @return HE_ERR_RNG_FAILURE An error occurred generating the session ID
 * @return HE_SUCCESS Random value generated correctly
 */
he_return_code_t he_internal_generate_session_id(he_conn_t *conn, uint64_t *session_id_out);

#endif  // CONN_INTERNAL_H
