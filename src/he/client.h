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
 * @file client.h
 * @brief Contains functions for dealing with the client convenience struct
 *
 */

#ifndef CLIENT_H
#define CLIENT_H

#include <he.h>

/**
 * @brief Creates a Helium client
 * @return he_client_t* Returns a pointer to a valid Helium context
 * @note This function allocates memory
 *
 * This function must be called to create the initial Helium context for use
 * with other functions
 */
he_client_t *he_client_create(void);

/**
 * @brief Releases all memory allocate by Helium including for the crypto layer
 * @param client A pointer to a valid client context
 * @return HE_SUCCESS This function cannot fail
 * @note The crypto layer initialises a limited amount of global state, which Helium does not free
 * because there could be multiple Helium instances. The memory used is minimal and will not impact
 * creating new Helium instances
 *
 * It will first remove all of the callbacks which means no Helium callbacks will be triggered after
 * calling this function. It is thus an error to call any Helium functions on this context after it
 * has been destroyed.
 */
he_return_code_t he_client_destroy(he_client_t *client);

/**
 * @brief Tries to establish a connection with a Helium server
 * @param client A pointer to a valid client context
 * @return HE_ERR_NULL_POINTER The client pointer supplied is NULL
 * @return HE_ERR_CONF_USERNAME_NOT_SET The username has not been set
 * @return HE_ERR_CONF_PASSWORD_NOT_SET The password has not been set
 * @return HE_ERR_CONF_CA_NOT_SET The CA has not been set
 * @return HE_ERR_CONF_MTU_NOT_SET The external MTU has not been set
 * @return HE_ERR_CONF_OUTSIDE_WRITE_CB_NOT_SET The outside write callback has not been set
 * @return HE_ERR_INIT_FAILED Helium was unable to initialise itself
 * @return HE_ERR_SSL_BAD_FILETYPE The SSL certificate was not provided in PEM format
 * @return HE_ERR_SSL_BAD_FILE The SSL certificate is corrupt or damaged
 * @return HE_ERR_SSL_OUT_OF_MEMORY The crypto engine ran out of memory
 * @return HE_ERR_SSL_ASN_INPUT The certificate does not comply to ASN formatting
 * @return HE_ERR_SSL_BUFFER Ran out of memory trying to allocate buffers for the SSL layer
 * @return HE_ERR_SSL_CERT Generic failure in the SSL engine
 * @return HE_ERR_CONNECT_FAILED There was an I/O issue trying to connect to the server.
 * @return HE_SUCCESS Helium is in the process of connecting
 * @note This function triggers the initialisation and initial connection to a Helium server.
 * However it is asynchronous, Helium is *not* connected when this function returns, merely that the
 * connection is in progress. Use event and state change callbacks to determine the actual state of
 * Helium
 *
 * This function has a lot of return codes as it is where Helium tries to apply and configure the
 * crypto engine. All of the return codes except for HE_SUCCESS are effectively fatal errors. Trying
 * to call *he_client_connect* again without changing the configuration is unlikely to succeed.
 */
he_return_code_t he_client_connect(he_client_t *client);

/**
 * @brief Try to cleanly disconnect from the remote server.
 * @param client A pointer to a valid client context
 * @return HE_ERR_NEVER_CONNECTED The client context has never been connected and so cannot be
 * disconnected. It is safe to destroy the client state here.
 * @return HE_ERR_INVALID_CLIENT_STATE This function should only be used when Helium is in the
 * online state. It is safe to destroy the client in other states.
 * @return HE_SUCCESS The disconnect process has started
 * @note Like he_client_connect, this is an asynchronous process. Watch state changes to determine
 * when Helium has actually disconnected
 * @note This function is not yet well described and is likely to change
 */
he_return_code_t he_client_disconnect(he_client_t *client);

/**
 * @brief Checks whether the client context has the basic configuration to allow Helium to connect.
 * @param client A pointer to a valid client context
 * @return HE_ERR_NULL_POINTER The client pointer supplied is NULL
 * @return HE_ERR_CONF_USERNAME_NOT_SET The username has not been set
 * @return HE_ERR_CONF_PASSWORD_NOT_SET The password has not been set
 * @return HE_ERR_CONF_CA_NOT_SET The CA has not been set
 * @return HE_ERR_CONF_MTU_NOT_SET The external MTU has not been set
 * @return HE_ERR_CONF_OUTSIDE_WRITE_CB_NOT_SET The outside write callback has not been set
 * @return HE_SUCCESS The basic configuration options have been set
 *
 * @note These return codes are similar to `he_client_connect` because that function will call
 *       this function before attempting to connect.
 */
he_return_code_t he_client_is_config_valid(he_client_t *client);

#endif  // CLIENT_H
