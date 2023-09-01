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
 * @file ssl_ctx.h
 * @brief Functions for managing the SSL context
 *
 */

#ifndef SSL_CTX_H
#define SSL_CTX_H

#include "he_internal.h"

/**
 * @brief Initialises Helium global state
 * @return HE_SUCCESS Initialisation successful
 * @return HE_INIT_FAILED Fatal error - couldn't initialise global state
 *
 * Helium doesn't itself use global state at present, however the underlying crypto library does.
 * To keep things clean so that Helium can be totally cleaned out of a process, init and cleanup
 * functions were added.
 *
 * @caution Call this first before any other Helium function!
 * @see he_cleanup()
 */
he_return_code_t he_init(void);

/**
 * @brief Cleans up all Helium global state
 * @return HE_SUCCESS clean up successful
 * @return HE_INIT_FAILED Couldn't clean up global state
 *
 * This cleans up any global state that Helium used.
 *
 * @caution Do not call any Helium function after calling this apart from he_init()
 *
 * @see he_init()
 */
he_return_code_t he_cleanup(void);

/**
 * @brief Checks whether the client context has the basic configuration to allow Helium to connect.
 * @param ctx A pointer to a valid SSL context configuration
 * @return HE_ERR_NULL_POINTER The ctx pointer supplied is NULL
 * @return HE_ERR_CONF_CA_NOT_SET The CA has not been set
 * @return HE_ERR_CONF_OUTSIDE_WRITE_CB_NOT_SET The outside write callback has not been set
 * @return HE_SUCCESS The basic configuration options have been set
 *
 * @note These return codes are similar to `he_ssl_ctx_start` because that function will call
 *       this function before attempting to connect.
 */
he_return_code_t he_ssl_ctx_is_valid_client(he_ssl_ctx_t *ctx);

/**
 * @brief Checks whether the server context has the basic configuration to allow Helium to connect.
 * @param ctx A pointer to a valid SSL context configuration
 * @return HE_ERR_NULL_POINTER The ctx pointer supplied is NULL
 * @return HE_ERR_CONF_CA_NOT_SET The CA has not been set
 * @return HE_ERR_CONF_OUTSIDE_WRITE_CB_NOT_SET The outside write callback has not been set
 * @return HE_SUCCESS The basic configuration options have been set
 *
 * @note These return codes are similar to `he_ssl_ctx_start_server` because that function will call
 *       this function before attempting to connect.
 */
he_return_code_t he_ssl_ctx_is_valid_server(he_ssl_ctx_t *ctx);

/**
 * @brief Creates a Helium SSL context
 * @return he_ssl_ctx_t* Returns a pointer to a valid Helium context ctx
 * @note This function allocates memory
 *
 * This function must be called to create the initial Helium SSL context
 * for use with other functions
 */
he_ssl_ctx_t *he_ssl_ctx_create(void);

/**
 * @brief Releases all memory allocate by Helium for this context
 * @param ctx A pointer to a valid SSL context
 * @note Make sure all connections created from this context are destroyed before calling
 * this function; once this function is called their behaviour is undefined.
 */
void he_ssl_ctx_destroy(he_ssl_ctx_t *ctx);

/**
 * @brief Sets up all internal state so that client connections can be created
 * @param context A pointer to a valid SSL context
 * @return HE_ERR_NULL_POINTER The ctx pointer supplied is NULL
 * @return HE_ERR_CONF_CA_NOT_SET The CA has not been set
 * @return HE_ERR_CONF_OUTSIDE_WRITE_CB_NOT_SET The outside write callback has not been set
 * @return HE_ERR_INIT_FAILED Helium was unable to initialise itself
 * @return HE_ERR_SSL_BAD_FILETYPE The SSL certificate was not provided in PEM format
 * @return HE_ERR_SSL_BAD_FILE The SSL certificate is corrupt or damaged
 * @return HE_ERR_SSL_OUT_OF_MEMORY The crypto engine ran out of memory
 * @return HE_ERR_SSL_ASN_INPUT The certificate does not comply to ASN formatting
 * @return HE_ERR_SSL_BUFFER Ran out of memory trying to allocate buffers for the SSL layer
 * @return HE_ERR_SSL_CERT Generic failure in the SSL engine
 * @return HE_SUCCESS Helium is in the process of connecting
 *
 * This function has a lot of return codes as it is where Helium tries to apply and configure the
 * crypto engine. All of the return codes except for HE_SUCCESS are effectively fatal errors. Trying
 * to call *he_ssl_ctx_start_* again without changing the configuration is unlikely to succeed.
 */
he_return_code_t he_ssl_ctx_start(he_ssl_ctx_t *context);

/**
 * @brief Sets up all internal state so that server connections can be created
 * @param context A pointer to a valid SSL context
 * @return HE_ERR_NULL_POINTER The ctx pointer supplied is NULL
 * @return HE_ERR_CONF_CA_NOT_SET The CA has not been set
 * @return HE_ERR_CONF_OUTSIDE_WRITE_CB_NOT_SET The outside write callback has not been set
 * @return HE_ERR_INIT_FAILED Helium was unable to initialise itself
 * @return HE_ERR_SSL_BAD_FILETYPE The SSL certificate was not provided in PEM format
 * @return HE_ERR_SSL_BAD_FILE The SSL certificate is corrupt or damaged
 * @return HE_ERR_SSL_OUT_OF_MEMORY The crypto engine ran out of memory
 * @return HE_ERR_SSL_ASN_INPUT The certificate does not comply to ASN formatting
 * @return HE_ERR_SSL_BUFFER Ran out of memory trying to allocate buffers for the SSL layer
 * @return HE_ERR_SSL_CERT Generic failure in the SSL engine
 * @return HE_SUCCESS Helium is in the process of connecting
 *
 * This function has a lot of return codes as it is where Helium tries to apply and configure the
 * crypto engine. All of the return codes except for HE_SUCCESS are effectively fatal errors. Trying
 * to call *he_ssl_ctx_start_* again without changing the configuration is unlikely to succeed.
 */
he_return_code_t he_ssl_ctx_start_server(he_ssl_ctx_t *context);

/**
 * @brief Try to cleanly stop the SSL context
 * @param context A pointer to a valid SSL context (client or server)
 * @return HE_SUCCESS The disconnect process has started
 * @note This function is not yet well described and is likely to change
 */
he_return_code_t he_ssl_ctx_stop(he_ssl_ctx_t *context);

/**
 * @brief Set the minimum supported wire protocol version by this SSL context
 * @param context A pointer to a valid SSL context
 * @param major_version The major version of the minimum supported protocol version
 * @param minor_version The minor version of the minimum supported protocol version
 * @return HE_SUCCESS if the support version is set successfully
 * @return HE_ERR_NULL_POINTER if the given SSL context is NULL
 * @return HE_ERR_INCORRECT_PROTOCOL_VERSION if the new version is not valid
 * @note This function is for server-side only.
 */
he_return_code_t he_ssl_ctx_set_minimum_supported_version(he_ssl_ctx_t *context,
                                                          uint8_t major_version,
                                                          uint8_t minor_version);

/**
 * @brief Set the maximum supported wire protocol version by this SSL context
 * @param context A pointer to a valid SSL context
 * @param major_version The major version of the maximum supported protocol version
 * @param minor_version The minor version of the maximum supported protocol version
 * @return HE_SUCCESS if the support version is set successfully
 * @return HE_ERR_NULL_POINTER if the given SSL context is NULL
 * @return HE_ERR_INCORRECT_PROTOCOL_VERSION if the new version is not valid
 * @note This function is for server-side only
 */
he_return_code_t he_ssl_ctx_set_maximum_supported_version(he_ssl_ctx_t *context,
                                                          uint8_t major_version,
                                                          uint8_t minor_version);
/**
 * @brief Validate whether a major/minor version is supported by this SSL context
 * @param context A pointer to a valid SSL context
 * @param major_version The major version to test
 * @param minor_version The minor version to test
 * @return true if this SSL context supports this major/minor version, false otherwise
 * @note There's no need for clients to use this function, they will always use the maximum
 */
bool he_ssl_ctx_is_supported_version(he_ssl_ctx_t *context, uint8_t major_version,
                                     uint8_t minor_version);

/**
 * @brief Validate whether the major/minor version is the latest
 * @param context A pointer to a valid SSL context
 * @param major_version The major version to test
 * @param minor_version The minor version to test
 * @return true if this major/minor version is the latest supported by this context
 * @note There's no need for clients to use this function, they will always use the maximum
 */
bool he_ssl_ctx_is_latest_version(he_ssl_ctx_t *context, uint8_t major_version,
                                  uint8_t minor_version);

// Setters and getters for the configuration
/**
 * @brief Set the expected Distinguished Name (DN) of the server.
 * @param ctx A pointer to a valid SSL context
 * @param distinguished_name A pointer to the distinguished name
 * @return HE_SUCCESS The DN has been set
 * @return HE_ERR_SSL_ERROR Generic failure - DN couldn't be set
 * @note This must be set before calling he_ssl_ctx_start[_server]
 *
 * If this option is set, Helium will verify the DN name of the server's certificate to provide
 * additional security. However, even without this set, Helium will still validate the certificate
 * chain.
 */
he_return_code_t he_ssl_ctx_set_server_dn(he_ssl_ctx_t *ctx, const char *distinguished_name);

/**
 * @brief Get the Distinguished Name that Helium will use to verify the server's certificate
 * @param ctx A pointer to a valid SSL context
 * @return const char* A pointer to the distinguished name
 */
const char *he_ssl_ctx_get_server_dn(he_ssl_ctx_t *ctx);

/**
 * @brief Check if the server DN has been set.
 * @param ctx A pointer to a valid SSL context
 * @return bool Returns true or false depending on whether it has been set
 *
 * It is anticipated that this feature will be used for implementing UIs that don't maintain their
 * own configuration state.
 */
bool he_ssl_ctx_is_server_dn_set(he_ssl_ctx_t *ctx);

/**
 * @brief Tell Helium to use CHACHA20 and Poly1305 instead of AES and SHA based encryption and
 * authentication.
 * @param ctx A pointer to a valid SSL context
 * @param use A boolean to indicate whether chacha20 should be used
 * @return HE_SUCCESS The use of CHACHA20 has been set successfully
 */
he_return_code_t he_ssl_ctx_set_use_chacha20(he_ssl_ctx_t *ctx, bool use);

/**
 * @brief Returns whether CHACHA20 is enabled or not
 * @param ctx A pointer to a valid SSL context
 * @return bool Whether CHACHA20 is enabled or not
 */
bool he_ssl_ctx_get_use_chacha20(he_ssl_ctx_t *ctx);

/**
 * @brief Set the location and size of the CA certificate chain
 * @param ctx A pointer to a valid SSL context
 * @param cert_buffer A pointer to the location of the CA certificate chain in memory
 * @param length The total size of the CA certificate chain
 * @return HE_SUCCESS CA has been set
 * @return HE_ERR_NULL_POINTER supplied cert_buffer was NULL
 * @return HE_ERR_ZERO_SIZE supplied length was 0
 *
 * @note The certificate chain should be in PEM format. Concatenated certificates (like you'd
 * find in a .pem file) are supported.
 */
he_return_code_t he_ssl_ctx_set_ca(he_ssl_ctx_t *ctx, uint8_t *cert_buffer, size_t length);

/**
 * @brief Check if the CA has been set
 * @param ctx A pointer to a valid SSL context
 * @return Returns true if the CA has been set, false otherwise
 */
bool he_ssl_ctx_is_ca_set(he_ssl_ctx_t *ctx);

/**
 * @brief Set the server cert and keys
 */
he_return_code_t he_ssl_ctx_set_server_cert_key_files(he_ssl_ctx_t *ctx, const char *server_cert,
                                                      const char *server_key);

/**
 * @brief Whether the server cert and keys have been set
 */
bool he_ssl_ctx_is_server_cert_key_set(he_ssl_ctx_t *ctx);

/**
 * @brief Set the connection type
 * @param ctx A pointer to a valid SSL context
 * @param connection_type A valid member of the he_connection_type_t ENUM
 * @return HE_SUCCESS Connection type has been set
 * @return HE_ERR_INVALID_CONNECTION_TYPE If an unknown connection type is passed
 */
he_return_code_t he_ssl_ctx_set_connection_type(he_ssl_ctx_t *ctx,
                                                he_connection_type_t connection_type);

/**
 * @brief Sets the function that should be called on Helium state changes.
 * @param ctx A pointer to a valid SSL context
 * @param state_change_cb The function to be called when Helium changes state
 *
 * Whenever Helium changes state internally, the supplied function will be called.
 */
void he_ssl_ctx_set_state_change_cb(he_ssl_ctx_t *ctx, he_state_change_cb_t state_change_cb);

/**
 * @brief Check if the state change callback has been set.
 * @param ctx A pointer to a valid SSL context
 * @return bool Returns true or false depending on whether it has been set
 *
 * It is anticipated that this feature will be used for implementing UIs that don't maintain their
 * own configuration state.
 */
bool he_ssl_ctx_is_state_change_cb_set(he_ssl_ctx_t *ctx);

/**
 * @brief Sets the function that will be called when Helium needs to do an inside write.
 * @param ctx A pointer to a valid SSL context
 * @param inside_write_cb The function to be called when Helium needs to do an inside write
 *
 * Helium is platform agnostic and as such does not handle its own I/O. This allows the developer
 * to hook up Helium using the most appropriate methods for their platform.
 *
 * Inside writes are triggered when decrypted packets need to be passed to the host operating
 * system. On Linux, the inside write would usually be to a tun device.
 */
void he_ssl_ctx_set_inside_write_cb(he_ssl_ctx_t *ctx, he_inside_write_cb_t inside_write_cb);

/**
 * @brief Check if the inside write callback has been set.
 * @param ctx A pointer to a valid SSL context
 * @return bool Returns true or false depending on whether it has been set
 *
 * It is anticipated that this feature will be used for implementing UIs that don't maintain their
 * own configuration state.
 */
bool he_ssl_ctx_is_inside_write_cb_set(he_ssl_ctx_t *ctx);

/**
 * @brief Sets the function that will be called when Helium needs to do an outside write.
 * @param ctx A pointer to a valid SSL context
 * @param outside_write_cb  The function to be called when Helium needs to do an outside write
 *
 * Helium is platform agnostic and as such does not handle its own I/O. This allows the developer
 * to hook up Helium using the most appropriate methods for their platform.
 *
 * Outside writes are triggered when encrypted packets need to be sent to the Helium server. On
 * Linux this would usually be a UDP socket.
 */
void he_ssl_ctx_set_outside_write_cb(he_ssl_ctx_t *ctx, he_outside_write_cb_t outside_write_cb);

/**
 * @brief Called when the host application needs to deliver outside data to be processed by Helium
 * @param conn A valid Helium connection
 * @param buffer A pointer to the packet data
 * @param length The length of the packet
 * @return HE_ERR_NULL_POINTER The pointer provided is a NULL pointer
 * @return HE_ERR_PACKET_TOO_SMALL The packet is too small to be a valid Helium packet
 * @return HE_ERR_NOT_HE_PACKET The packet is not a Helium packet (it does not have the Helium
 * header)
 * @return HE_ERR_SSL_ERROR Something went wrong decrypting the packet - this is a FATAL error for
 * the connection
 * @return HE_ERR_SERVER_DN_MISMATCH The name in the server's cert did not match local configuration
 * @return HE_ERR_CANNOT_VERIFY_SERVER_CERT The server certificate couldn't be verified using the
 * configured CA Cert
 * @return HE_ERR_SERVER_GOODBYE The server sent a goodbye message and the client should disconnect
 * and try to connect a different server
 * @return HE_SUCCESS The packet was processed normally.
 * @note These error codes may change before final release as new issues come to light.
 * @note If the conn has registered plugins, they may arbitrarily change the packet data,
 * but are restricted here to not exceeding the provided length. Users
 * who wish to have more control over this should *not* register plugins upon connection, but
 * instead call the plugin API explicitly prior to invoking this function.
 */
he_return_code_t he_conn_outside_data_received(he_conn_t *conn, uint8_t *buffer, size_t length);

/**
 * @brief Check if the outside write callback has been set.
 * @param ctx A pointer to a valid SSL context
 * @return bool Returns true or false depending on whether it has been set
 *
 * It is anticipated that this feature will be used for implementing UIs that don't maintain their
 * own configuration state.
 */
bool he_ssl_ctx_is_outside_write_cb_set(he_ssl_ctx_t *ctx);

/**
 * @brief Sets the function that will be called when Helium needs to pass network ctx to the host
 * application.
 * @param ctx A pointer to a valid SSL context
 * @param network_config_cb The function to be called when Helium needs to pass network ctx
 * to the host application.
 */
void he_ssl_ctx_set_network_config_ipv4_cb(he_ssl_ctx_t *ctx,
                                           he_network_config_ipv4_cb_t network_config_cb);

/**
 * @brief Check if the network ctx callback has been set.
 * @param ctx A pointer to a valid SSL context
 * @return bool Returns true or false depending on whether it has been set
 *
 * It is anticipated that this feature will be used for implementing UIs that don't maintain their
 * own configuration state.
 */
bool he_ssl_ctx_is_network_config_ipv4_cb_set(he_ssl_ctx_t *ctx);

/**
 * @brief Sets the function that will be called when Helium needs to pass server config to the host
 * application.
 * @param ctx A pointer to a valid SSL context
 * @param network_config_cb The function to be called when Helium needs to pass server config
 * to the host application.
 */
void he_ssl_ctx_set_server_config_cb(he_ssl_ctx_t *ctx, he_server_config_cb_t server_config_cb);

/**
 * @brief Sets the function that will be called when Helium needs to update the nudge time.
 * @param ctx A pointer to a valid SSL context
 * @param nudge_time_cb The function to be called when Helium needs to update the nudge time
 */
void he_ssl_ctx_set_nudge_time_cb(he_ssl_ctx_t *ctx, he_nudge_time_cb_t nudge_time_cb);

/**
 * @brief Check if the nudge time callback has been set.
 * @param ctx A pointer to a valid SSL context
 * @return bool Returns true or false depending on whether it has been set
 *
 * It is anticipated that this feature will be used for implementing UIs that don't maintain their
 * own configuration state.
 */
bool he_ssl_ctx_is_nudge_time_cb_set(he_ssl_ctx_t *ctx);

/**
 * @brief Sets the function that will be called when Helium needs to pass an event to the host
 * application.
 * @param ctx A pointer to a valid SSL context
 * @param event_cb The function to be called when Helium needs to pass an event to the host
 * application
 */
void he_ssl_ctx_set_event_cb(he_ssl_ctx_t *ctx, he_event_cb_t event_cb);

/**
 * @brief Sets the function that will be called when Helium needs to authenticate a user
 * @param ctx A pointer to a valid SSL context
 * @param auth_cb The function to be called when Helium needs to authenticate a user
 */
void he_ssl_ctx_set_auth_cb(he_ssl_ctx_t *ctx, he_auth_cb_t auth_cb);

/**
 * @brief Sets the function that will be called when Helium needs to authenticate a user
 * @param ctx A pointer to a valid SSL context
 * @param auth_buf_cb The function to be called when Helium needs to authenticate a user
 */
void he_ssl_ctx_set_auth_buf_cb(he_ssl_ctx_t *ctx, he_auth_buf_cb_t auth_buf_cb);

/**
 * @brief Check if at least one auth callback has been set.
 * @param ctx A pointer to a valid SSL context
 * @return bool Returns true or false depending on whether it has been set
 */
bool he_ssl_ctx_is_auth_cb_set(he_ssl_ctx_t *ctx);

/**
 * @brief Sets the function that will be called when Helium needs to provide network ctx to a
 * client
 * @param ctx A pointer to a valid SSL context
 * @param pop_network_cb The function to be called when Helium needs network ctx
 */
void he_ssl_ctx_set_populate_network_config_ipv4_cb(
    he_ssl_ctx_t *ctx, he_populate_network_config_ipv4_cb_t pop_network_cb);

/**
 * @brief Disables session roaming and removes the session ID from the packet header
 * @return HE_SUCCESS
 * This function removes the session ID from the external packet header so that an observer
 * cannot follow the session across Internet connections. However Helium also will not be
 * able to follow the connection and will trigger a session reject when a client changes source
 * IP or port.
 *
 * @caution This will hide the session ID but if the client's source port changes (such as a NAT
 * timeout), the connection will be reset and reestablished.
 */
he_return_code_t he_ssl_ctx_set_disable_roaming(he_ssl_ctx_t *ctx);

/**
 * @brief Check if roaming has been disabled
 * @param ctx A pointer to a valid SSL context
 * @return bool Returns true or false depending on whether it has been set
 *
 * It is anticipated that this feature will be used for implementing UIs that don't maintain their
 * own configuration state.
 */
bool he_ssl_ctx_is_roaming_disabled(he_ssl_ctx_t *ctx);

/**
 * @brief Sets the padding mode and hence the level of padding (if any) to be used
 * @return HE_SUCCESS
 */
he_return_code_t he_ssl_ctx_set_padding_type(he_ssl_ctx_t *ctx, he_padding_type_t padding_type);

/**
 * @brief Returns the current padding mode
 * @return he_padding_type_t
 */
he_padding_type_t he_ssl_ctx_get_padding_type(he_ssl_ctx_t *ctx);

/**
 * @brief Sets the client to aggressive mode, where it will send each message three times
 *        to help improve the chances of a faster connection and greater throughput despite packet
 * drops in D/TLS mode.
 * @return HE_SUCCESS Aggressive mode is enabled
 *
 */
he_return_code_t he_ssl_ctx_set_aggressive_mode(he_ssl_ctx_t *ctx);

#ifndef HE_NO_PQC

/**
 * @brief Sets the client to use PQC Keyshares
 * @return HE_SUCCESS PQC Keyshares are enabled
 *
 */
he_return_code_t he_ssl_ctx_set_use_pqc(he_ssl_ctx_t *ctx, bool enabled);

#endif  // HE_NO_PQC

#endif  // SSL_CTX_H
