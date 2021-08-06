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
 * @file wolf.h
 * @brief Functions for interfacing with WolfSSL
 *
 */

#ifndef WOLF_H
#define WOLF_H

#ifndef WOLFSSL_USER_SETTINGS
#include <wolfssl/options.h>
#endif
#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/ssl.h>

/**
 * @brief Callback function to handle WolfSSL read requests
 * @param ssl A pointer to the WolfSSL session that this callback relates to
 * @param buf A pointer to the buffer the callback writes data to
 * @param sz The maximum size that can be written to the buffer
 * @param ctx A pointer to the Helium context that this callback relates to
 * @return int The length of the data copied to the buffer
 * @return WOLFSSL_CBIO_ERR_WANT_READ Tells WolfSSL that there's no more data available
 *
 * Helium does not know about sockets and as such, neither can WolfSSL. Helium
 * overrides the standard socket calls with its own callback functions.
 *
 * This function simply copies data to WolfSSL's buffer and returns
 *
 * @note This function will be called twice per packet. This function will return
 * WOLFSSL_CBIO_ERR_WANT_READ on the second call.
 *
 */

int he_wolf_dtls_read(WOLFSSL *ssl, char *buf, int sz, void *ctx);

/**
 * @brief Callback function to handle WolfSSL write requests
 * @param ssl A pointer to the WolfSSL session that this callback relates to
 * @param buf A pointer to the buffer the callback reads data from
 * @param sz The size of the data to be read
 * @param ctx A pointer to the Helium context that this callback relates to
 * @return int The length of the data copied to the buffer
 *
 * Helium does not know about sockets and as such, neither can WolfSSL. Helium
 * overrides the standard socket calls with its own callback functions.
 *
 * This function simply calls the user provided write callback
 *
 * @note The buffer is only valid until this function returns. As such the user provided write
 * callback must copy the data from the buffer if it needs it to persist after that time.
 */

int he_wolf_dtls_write(WOLFSSL *ssl, char *buf, int sz, void *ctx);

/**
 * @brief Write the packet header into the header buffer
 * @param conn A pointer to a valid conn context
 * @param hdr A pointer to the header buffer to initialise
 * @return HE_SUCCESS Header has been initialised
 * @return HE_ERR_NULL_POINTER Either the conn or header pointers were NULL
 */
int he_internal_write_packet_header(he_conn_t *conn, he_wire_hdr_t *hdr);

/**
 * @brief Callback function to handle TLS WolfSSL read requests
 * @param ssl A pointer to the WolfSSL session that this callback relates to
 * @param buf A pointer to the buffer the callback writes data to
 * @param sz The maximum size that can be written to the buffer
 * @param ctx A pointer to the Helium context that this callback relates to
 * @return int The length of the data copied to the buffer
 * @return WOLFSSL_CBIO_ERR_WANT_READ Tells WolfSSL that there's no more data available
 *
 * Helium does not know about sockets and as such, neither can WolfSSL. Helium
 * overrides the standard socket calls with its own callback functions.
 *
 * This function simply copies data to WolfSSL's buffer and returns
 *
 * @note This function will be called twice per packet. This function will return
 * WOLFSSL_CBIO_ERR_WANT_READ on the second call.
 *
 */
int he_wolf_tls_read(WOLFSSL *ssl, char *buf, int sz, void *ctx);

// Todo document this
int he_wolf_tls_write(WOLFSSL *ssl, char *buf, int sz, void *ctx);

#endif  // WOLF_H
