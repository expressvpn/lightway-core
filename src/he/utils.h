/* *
 * Lightway Core
 * Copyright (C) 2022 Express VPN International Ltd.
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
 * @file utils.h
 * @brief Utility functions for ease of use
 *
 */

#ifndef UTILS_H
#define UTILS_H

#include "he.h"

/**
 * Returns stringified version of an he_return_code_t.
 * @return The stringified name of the return code `rc` or `"HE_ERR_UNKNOWN"`.
 */
const char *he_return_code_name(he_return_code_t rc);

/**
 * Returns stringified version of an he_conn_state_t.
 * @return The stringified name of the state `st` or `"HE_STATE_UNKNOWN"`.
 */
const char *he_client_state_name(he_conn_state_t st);

/**
 * Returns stringified version of an he_conn_event_t.
 * @return The stringified name of the event `ev` or `"HE_EVENT_UNKNOWN"`.
 */
const char *he_client_event_name(he_conn_event_t ev);

/**
 * Returns stringified version of an he_connection_protocol_t.
 * @return The stringified name of the protocol `protocol` or `"HE_CONNECTION_PROTOCOL_UNKNOWN"`.
 */
const char *he_connection_protocol_name(he_connection_protocol_t protocol);

/**
 * Returns stringified version of an he_pmtud_state_t.
 */
const char *he_pmtud_state_name(he_pmtud_state_t state);

#endif  // UTILS_H
