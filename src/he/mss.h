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

#ifndef HE_MSS_H
#define HE_MSS_H

#include "he.h"
#include "he_internal.h"

/**
 * @brief Called when the host application needs to deliver an inside packet to Helium.
 * @param packet A pointer to the packet data
 * @param length The length of the packet
 * @param mss The maximum MSS a TCP connection can have
 * @return HE_ERR_NULL_POINTER A NULL pointer was specified as the packet
 * @return HE_ERR_FAILED An MSS of zero was specified
 * @return HE_ERR_ZERO_SIZE The packet has zero length
 * @return HE_SUCCESS Packet has been processed normally
 */
he_return_code_t he_clamp_mss(uint8_t *packet, size_t length, uint16_t mss);

#endif // HE_MSS_H
