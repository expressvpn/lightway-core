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
 * @file msg_handlers.h
 * @brief Functions to handle each message type, no public API
 */

#ifndef MSG_HANDLERS_H
#define MSG_HANDLERS_H

#include <he.h>

he_return_code_t he_handle_msg_noop(he_conn_t *conn, uint8_t *packet, int length);
he_return_code_t he_handle_msg_ping(he_conn_t *conn, uint8_t *packet, int length);
he_return_code_t he_handle_msg_pong(he_conn_t *conn, uint8_t *packet, int length);
he_return_code_t he_handle_msg_auth(he_conn_t *conn, uint8_t *packet, int length);
he_return_code_t he_handle_msg_data(he_conn_t *conn, uint8_t *packet, int length);
he_return_code_t he_handle_msg_config_ipv4(he_conn_t *conn, uint8_t *packet, int length);
he_return_code_t he_handle_msg_auth_response(he_conn_t *conn, uint8_t *packet, int length);
he_return_code_t he_handle_msg_auth_response_with_config(he_conn_t *conn, uint8_t *packet,
                                                         int length);
he_return_code_t he_handle_msg_deprecated_13(he_conn_t *conn, uint8_t *packet, int length);
he_return_code_t he_handle_msg_goodbye(he_conn_t *conn, uint8_t *packet, int length);
he_return_code_t he_handle_msg_server_config(he_conn_t *conn, uint8_t *packet, int length);

bool he_internal_is_ipv4_packet_valid(uint8_t *packet, int length);

#endif  // MSG_HANDLERS_H
