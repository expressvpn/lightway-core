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

#include "bob.h"

// OK This is cool

/* This is a bare-star comment */

/** And this is a multiline star
 * comment that will hopefully be ignored
 */

#define BOB 42

/**
 * @brief Get the username that Helium will authenticate with, previously set by
 * he_client_set_username
 * @param client A pointer to a valid client context
 * @return const char* A pointer to the username
 */
const char *he_client_get_username(const he_client_t *client);

bool he_internal_config_is_string_too_long(const char *string);

/**
 * @brief Updates the timeout for a client context and triggers the timeout callback if set
 * @param client A pointer to a valid client context
 */
void he_internal_update_timeout(he_client_t *client);

he_return_code_t he_client_register_plugin(he_client_t *client, plugin_struct_t *plugin);

/**
 * Packet types the packet info method can infer.
 */
typedef enum he_packet_state {
  HE_BAD_PACKET = 0,
  HE_PACKET_IP4 = 1,
  HE_PACKET_IP6 = 2
} he_packet_state_t;

/**
 * @brief Internal lifecycle function for processing an outside UDP packet
 * @param client A valid client context
 * @param packet A pointer to the packet data
 * @param length The length of the packet
 * @return HE_SUCCESS The packet was processed normally.
 * @note Please see he_client_outside_data_received for other return values.
 */
he_return_code_t he_test_outside_packet_received(he_client_t *client, uint8_t *packet,
                                                 size_t length);
