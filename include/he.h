/**
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
 * @file he.h
 * @brief Core public header file for libhelium
 *
 * This file includes common type definitions and useful constants for ensuring consistency across
 * the code files for libhelium. It should be included by every header file.
 */

#ifndef HE
#define HE

// Needed headers
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

// Network headers
#include "he_plugin.h"

/// Default MTU sizes
#define HE_MAX_WIRE_MTU 1500
#define HE_MAX_MTU 1350
#define HE_MAX_MTU_STR "1350"

/// Default minimum and maximum wire protocol versions
#define HE_WIRE_MINIMUM_PROTOCOL_MAJOR_VERSION 1
#define HE_WIRE_MINIMUM_PROTOCOL_MINOR_VERSION 0
#define HE_WIRE_MAXIMUM_PROTOCOL_MAJOR_VERSION 1
#define HE_WIRE_MAXIMUM_PROTOCOL_MINOR_VERSION 2

/// Helpful deprecation macro
#ifdef __GNUC__
#define HE_DEPRECATED(name) __attribute__((deprecated("use " #name " instead")))
#elif defined(_MSC_VER)
#define HE_DEPRECATED(name) __declspec(deprecated("use " #name " instead"))
#endif

/// Maximum size of a text based config option.
#define HE_CONFIG_TEXT_FIELD_LENGTH 50
/// Maximum size of an IPV4 String
#define HE_MAX_IPV4_STRING_LENGTH 24
/// Maximum size of a hostname
#define HE_MAX_HOSTNAME_LENGTH 255

/**
 * @brief All possible return codes for helium
 */
typedef enum he_return_code {
  /// If the function call completed successfully, this will be returned.
  HE_SUCCESS = 0,
  /// This will be returned if a string parameter is too long to be stored.
  HE_ERR_STRING_TOO_LONG = -1,
  /// This will be returned if trying to set a configuration parameter to an empty string
  HE_ERR_EMPTY_STRING = -2,
  /**
   * @brief This will be returned if a function was called against a connection context that isn't
   * in a good state.
   *
   * For example this could happened when calling he_conn_connect_client() on an already connected
   * context.
   */
  HE_ERR_INVALID_CONN_STATE = -3,
  /// A null pointer was passed as an argument
  HE_ERR_NULL_POINTER = -4,
  /// An empty packet was passed to the function. Either a NULL pointer or a length of zero.
  HE_ERR_EMPTY_PACKET = -5,
  /// The packet passed to the function is too small to be valid
  HE_ERR_PACKET_TOO_SMALL = -6,
  /// The length parameter was set to zero
  HE_ERR_ZERO_SIZE = -7,
  /// A negative value was given but only an unsigned value is acceptable
  HE_ERR_NEGATIVE_NUMBER = -8,
  /// Initialisation failed - this is usually an issue with the SSL layer
  HE_ERR_INIT_FAILED = -9,
  /// Could not allocate memory
  HE_ERR_NO_MEMORY = -10,
  /// Packet provided does not have a Helium header
  HE_ERR_NOT_HE_PACKET = -11,
  /// The SSL certificate is not in PEM format
  HE_ERR_SSL_BAD_FILETYPE = -12,
  /// The SSL certificate is corrupt or missing
  HE_ERR_SSL_BAD_FILE = -13,
  /// The SSL layer was not able to allocate more memory
  HE_ERR_SSL_OUT_OF_MEMORY = -14,
  /// The SSL certificate is not in the correct format
  HE_ERR_SSL_ASN_INPUT = -15,
  /// The SSL layer ran out of buffers
  HE_ERR_SSL_BUFFER = -16,
  /// Generic issue with the SSL certificate - the SSL layer did not provide further information
  HE_ERR_SSL_CERT = -17,
  /// Generic issue with the SSL layer
  HE_ERR_SSL_ERROR = -18,
  /// Username not set in config
  HE_ERR_CONF_USERNAME_NOT_SET = -19,
  /// Password not set in config
  HE_ERR_CONF_PASSWORD_NOT_SET = -20,
  /// CA not set in config
  HE_ERR_CONF_CA_NOT_SET = -21,
  /// MTU not set in config
  HE_ERR_CONF_MTU_NOT_SET = -22,
  /// Helium needs to read more data before it can continue
  HE_WANT_READ = -23,
  /// Helium needs to write more data before it can continue
  HE_WANT_WRITE = -24,
  /// Outside write callback not set in config
  HE_ERR_CONF_OUTSIDE_WRITE_CB_NOT_SET = -25,
  /// General connection failed error
  HE_ERR_CONNECT_FAILED = -26,
  /// The SSL Connection has failed due to timeout
  HE_CONNECTION_TIMED_OUT = -27,
  /// Helium is not connected
  HE_ERR_NOT_CONNECTED = -28,
  /// Helium only supports IPv4 and IPv6
  HE_ERR_UNSUPPORTED_PACKET_TYPE = -29,
  /// The connection was closed
  HE_ERR_CONNECTION_WAS_CLOSED = -30,
  /// The packet was invalid (wrong length, bad type etc)
  HE_ERR_BAD_PACKET = -31,
  /// Callback failed
  HE_ERR_CALLBACK_FAILED = -32,
  /// Generic issue
  HE_ERR_FAILED = -33,
  /// Domain Name mismatch - supplied DN didn't match server certificate
  HE_ERR_SERVER_DN_MISMATCH = -34,
  /// Unable to verify the server certificate. Usually bad CA chain but could be caused by other
  /// weird issues
  HE_ERR_CANNOT_VERIFY_SERVER_CERT = -35,
  /// Attempted to call disconnect before connect. If this error is received, the state can be
  /// safely destroyed
  HE_ERR_NEVER_CONNECTED = -36,
  /// MTU size was invalid
  HE_ERR_INVALID_MTU_SIZE = -37,
  /// Failed to clean up global state
  HE_ERR_CLEANUP_FAILED = -38,
  /// The server rejected or couldn't find our session
  HE_ERR_REJECTED_SESSION = -39,
  /// The server rejected the login
  HE_ERR_ACCESS_DENIED = -40,
  /// Packet provided was too large
  HE_ERR_PACKET_TOO_LARGE = -41,
  /// Disconnect due to inactivity timeout
  HE_ERR_INACTIVITY_TIMEOUT = -42,
  /// Pointer would overflow
  HE_ERR_POINTER_WOULD_OVERFLOW = -43,
  /// Connection type argument is not defined in he_connection_type_t
  HE_ERR_INVALID_CONNECTION_TYPE = -46,
  /// RNG Failure
  HE_ERR_RNG_FAILURE = -47,
  /// Auth callback not set on a server
  HE_ERR_CONF_AUTH_CB_NOT_SET = -48,
  /// A plugin requested that we drop the packet without further processing
  HE_ERR_PLUGIN_DROP = -49,
  /// Inconsistent session received on server side
  HE_ERR_UNKNOWN_SESSION = -50,
  /// An SSL error occurred on a D/TLS packet but it does not need to terminate the connection
  HE_ERR_SSL_ERROR_NONFATAL = -51,
  /// Protocol version for connection changed after creation
  HE_ERR_INCORRECT_PROTOCOL_VERSION = -52,
  /// Client has both username/password set AND authentication buffer set
  HE_ERR_CONF_CONFLICTING_AUTH_METHODS = -53,
  /// Server has received an auth_buf message but does not have a handler configured
  HE_ERR_ACCESS_DENIED_NO_AUTH_BUF_HANDLER = -54,
  /// Server has received an auth_userpass message but does not have a handler configured
  HE_ERR_ACCESS_DENIED_NO_AUTH_USERPASS_HANDLER = -55,
  /// The client has received the goodbye message from server
  HE_ERR_SERVER_GOODBYE = -56,
  /// Invalid authentication type
  HE_ERR_INVALID_AUTH_TYPE = -57,
  /// Server has received an auth_token message but does not have a handler configured
  HE_ERR_ACCESS_DENIED_NO_AUTH_TOKEN_HANDLER = -58,
} he_return_code_t;

/**
 * @brief Status codes for a Helium connection
 */
typedef enum he_conn_state {
  /// Connection has yet to be initialised
  HE_STATE_NONE = 0,
  /// Connection is in a disconnected state. Any resources used for the connection have been
  /// released.
  HE_STATE_DISCONNECTED = 1,
  /// Connection is currently trying to establish a D/TLS session with the server.
  HE_STATE_CONNECTING = 2,
  /// Connection is currently trying to cleanly disconnect from the server.
  HE_STATE_DISCONNECTING = 4,
  /// Connection has established a D/TLS session and is attempting to authenticate
  HE_STATE_AUTHENTICATING = 5,
  /// TLS link is up
  HE_STATE_LINK_UP = 6,
  /// Everything is done - we're online
  HE_STATE_ONLINE = 7,
  /// Configuring - config has been received and config callback will soon be made
  HE_STATE_CONFIGURING = 8,
} he_conn_state_t;

typedef enum he_conn_event {
  /// First packet / message was passed to Helium (i.e. a server response)
  HE_EVENT_FIRST_MESSAGE_RECEIVED = 1,
  /// Server replied to a PING request (NAT Keepalive)
  HE_EVENT_PONG = 2,
  /// Connection tried to send fragmented packets which were rejected as they are not supported by
  /// Helium
  HE_EVENT_REJECTED_FRAGMENTED_PACKETS_SENT_BY_HOST = 3,
  /// Helium has started a secure renegotiation
  HE_EVENT_SECURE_RENEGOTIATION_STARTED = 4,
  /// Helium has completed secure renegotiation
  HE_EVENT_SECURE_RENEGOTIATION_COMPLETED = 5,
  /// Pending Session Acknowledged
  HE_EVENT_PENDING_SESSION_ACKNOWLEDGED = 6,
  /// Path MTU Discovery Started
  HE_EVENT_PMTU_DISCOVERY_STARTED = 7,
  /// Path MTU Discovery Completed
  HE_EVENT_PMTU_DISCOVERY_COMPLETED = 8,
} he_conn_event_t;

/**
 * @brief Helium supports numerous padding levels, from none to full.
 * This enum defines which options can be chosen
 */
typedef enum he_padding_type {
  /// Tell Helium not to pad packets at all
  HE_PADDING_NONE = 0,
  /// Tell Helium to fully pad packets to the MTU, like IPSEC
  HE_PADDING_FULL = 1,
  /// Tell Helium to round packets to the nearest 450 bytes
  HE_PADDING_450 = 2
} he_padding_type_t;

/**
 * @brief Helium can operate in datagram or stream modes. This enum defines these two modes
 */
typedef enum he_connection_type {
  /// Datagram mode (i.e. UDP)
  HE_CONNECTION_TYPE_DATAGRAM = 0,
  /// Stream mode (i.e. TCP)
  HE_CONNECTION_TYPE_STREAM = 1
} he_connection_type_t;

/**
 * @brief Lightway can use different underlying protocols. This enum defines those protocols.
 */
typedef enum he_connection_protocol {
  /// Invalid Protocol
  HE_CONNECTION_PROTOCOL_NONE = 0,
  /// TLS 1.3
  HE_CONNECTION_PROTOCOL_TLS_1_3 = 1,
  /// DTLS 1.2
  HE_CONNECTION_PROTOCOL_DTLS_1_2 = 2,
  /// DTLS 1.3
  HE_CONNECTION_PROTOCOL_DTLS_1_3 = 3
} he_connection_protocol_t;

/**
 * @brief Lightway Path MTU Discovery states.
 * @see RFC 8899 and RFC 4821
 */
typedef enum he_pmtud_state {
  // The DISABLED state is the initial state before probing has started.
  // It is also entered from any other state, when the PL indicates loss of
  // connectivity. This state is left once the PL indicates connectivity to the
  // remote PL. When transitioning to the BASE state, a probe packet of size
  // BASE_PLPMTU can be sent immediately
  HE_PMTUD_STATE_DISABLED = 0,

  // The BASE state is used to confirm that the BASE_PLPMTU size is supported by
  // the network path and is designed to allow an application to continue working
  // when there are transient reductions in the actual PMTU. It also seeks to avoid
  // long periods when a sender searching for a larger PLPMTU is unaware that
  // packets are not being delivered due to a packet or ICMP black hole.
  HE_PMTUD_STATE_BASE = 1,

  // The SEARCHING state is the main probing state. This state is entered when
  // probing for the BASE_PLPMTU completes.
  HE_PMTUD_STATE_SEARCHING = 2,

  // The SEARCH_COMPLETE state indicates that a search has completed. This is the
  // normal maintenance state, where the PL is not probing to update the PLPMTU.
  // DPLPMTUD remains in this state until either the PMTU_RAISE_TIMER expires or a
  // black hole is detected.
  HE_PMTUD_STATE_SEARCH_COMPLETE = 3,

  // The ERROR state represents the case where either the network path is not known
  // to support a PLPMTU of at least the BASE_PLPMTU size or when there is
  // contradictory information about the network path that would otherwise result
  // in excessive variation in the MPS signaled to the higher layer. The state
  // implements a method to mitigate oscillation in the state-event engine.
  HE_PMTUD_STATE_ERROR = 4,
} he_pmtud_state_t;

typedef struct he_ssl_ctx he_ssl_ctx_t;
typedef struct he_conn he_conn_t;
typedef struct he_plugin_chain he_plugin_chain_t;
typedef struct he_network_config_ipv4 he_network_config_ipv4_t;

/**
 * @brief Data structure to hold all the state needed as a Helium client
 */
typedef struct he_client {
  he_ssl_ctx_t *ssl_ctx;
  he_conn_t *conn;
  he_plugin_chain_t *inside_plugins;
  he_plugin_chain_t *outside_plugins;
} he_client_t;

typedef void *(*he_malloc_t)(size_t size);
typedef void *(*he_calloc_t)(size_t nmemb, size_t size);
typedef void *(*he_realloc_t)(void *ptr, size_t size);
typedef void (*he_free_t)(void *ptr);

/**
 * @brief Lightway can use different authentication types. This enum defines those types.
 */
typedef enum he_auth_type {
  /// Authenticate with username and password
  HE_AUTH_TYPE_USERPASS = 1,

  /// Authenticate with token
  HE_AUTH_TYPE_TOKEN = 2,

  /// Authenticate with custom callback
  HE_AUTH_TYPE_CB = 23,

} he_auth_type_t;

/**
 * @brief The prototype for the state callback function
 * @param conn A pointer to the connection that triggered this callback
 * @param new_state The state that the context has just entered
 * @param context A pointer to the user defined context
 * @see he_conn_set_context Sets the value of the context pointer
 *
 * Whenever Helium changes state, this function will be called.
 */
typedef he_return_code_t (*he_state_change_cb_t)(he_conn_t *conn, he_conn_state_t new_state,
                                                 void *context);

/**
 * @brief The prototype for the inside write callback function
 * @param conn A pointer to the connection that triggered this callback
 * @param packet A pointer to the packet data
 * @param length The length of the entire packet in bytes
 * @param context A pointer to the user defined context
 * @see he_conn_set_context Sets the value of the context pointer
 *
 * Whenever Helium needs to do an inside write this function will be called. On Linux this would
 * usually be writing decrypted packets to a tun device.
 */
typedef he_return_code_t (*he_inside_write_cb_t)(he_conn_t *conn, uint8_t *packet, size_t length,
                                                 void *context);

/**
 * @brief The prototype for the outside write callback function
 * @param conn A pointer to the connection that triggered this callback
 * @param packet A pointer to the packet data
 * @param length The length of the entire packet in bytes
 * @param context A pointer to the user defined context
 * @see he_conn_set_context Sets the value of the context pointer
 *
 * Whenever Helium needs to do an outside write this function will be called. On Linux this would
 * usually be writing to a UDP socket to send encrypted data over the Internet.
 */
typedef he_return_code_t (*he_outside_write_cb_t)(he_conn_t *conn, uint8_t *packet, size_t length,
                                                  void *context);

/**
 * @brief The prototype for the network config callback function
 * @param conn A pointer to the connection that triggered this callback
 * @param config The network config data such as local IP, peer IP, DNS IP and MTU
 * @param context A pointer to the user defined context
 * @see he_conn_set_context Sets the value of the context pointer
 *
 * When network configuration data is sent to Helium from the server, this callback will be
 * triggered to allow to host application to configure its network accordingly.
 */
typedef he_return_code_t (*he_network_config_ipv4_cb_t)(he_conn_t *conn,
                                                        he_network_config_ipv4_t *config,
                                                        void *context);

/**
 * @brief The prototype for the server config callback function
 * @param conn A pointer to the connection that triggered this callback
 * @param buffer A pointer to the buffer containing the server configuration data
 * @param length The length of the buffer in bytes
 * @param context A pointer to the user defined context
 * @see he_conn_set_context Sets the value of the context pointer
 *
 * Whenever the client receives the server configuration data (pushed by the Helium server), this
 * callback will be triggered. The host application is responsible for parsing the data using
 * implementation specific format.
 */
typedef he_return_code_t (*he_server_config_cb_t)(he_conn_t *conn, uint8_t *buffer, size_t length,
                                                  void *context);

/**
 * @brief The prototype for the event callback function
 * @param conn A pointer to the connection that triggered this callback
 * @param event The event to trigger
 * @param context A pointer to the user defined context
 *
 * Whenever Helium generates an event, this function will be called.
 */

typedef he_return_code_t (*he_event_cb_t)(he_conn_t *conn, he_conn_event_t event, void *context);

/**
 * @brief The prototype for the nudge time callback function
 * @param conn A pointer to the connection that triggered this callback
 * @param timeout The number of milliseconds to wait before nudging Helium
 * @param context A pointer to the user defined context
 * @see he_conn_set_context Sets the value of the context pointer
 * @see he_conn_get_nudge_time
 *
 * Helium uses D/TLS which needs to be able to resend certain messages if they are not received in
 * time. As Helium does not have its own threads or timers, it is up to the host application to tell
 * Helium when a certain amount of time has passed. Because D/TLS implements exponential back off,
 * the amount of waiting time can change after every read.
 *
 * To avoid the host application having to remember to ask Helium after every read with
 * he_conn_get_nudge_time(), the host application can register this callback instead.
 *
 * @note Any pending timers should be reset with the value provided in the callback and there should
 * only ever be one timer per connection context. Whilst excessive nudging won't cause Helium to
 * misbehave, it will create unnecessary load.
 */
typedef he_return_code_t (*he_nudge_time_cb_t)(he_conn_t *conn, int timeout, void *context);

/**
 * @brief The prototype for the authentication callback
 * @param conn A pointer to the connection that triggered this callback
 * @param username A pointer to the username
 * @param password A pointer to the password
 * @param context A pointer to the user defined context
 * @see he_conn_set_context Sets the value of the context pointer
 *
 * The host is expected to return whether this username and password is valid for the connection.
 * Note that username and password are not guaranteed to be null terminated, but will be less than
 * or equal in length to HE_CONFIG_TEXT_FIELD_LENGTH.
 */
typedef bool (*he_auth_cb_t)(he_conn_t *conn, char const *username, char const *password,
                             void *context);

/**
 * @brief The prototype for the authentication token callback
 * @param conn A pointer to the connection that triggered this callback
 * @param token A pointer to buffer containing the auth token
 * @param len Length of the token in bytes
 * @param context A pointer to the user defined context
 * @see he_conn_set_context Sets the value of the context pointer
 *
 * The host is expected to return whether this auth token is valid for the connection.
 * Note that the token is not guaranteed to be null terminated, but will be less than in
 * length to HE_MAX_MTU.
 */
typedef bool (*he_auth_token_cb_t)(he_conn_t *conn, const uint8_t *token, size_t len,
                                   void *context);

/**
 * @brief The prototype for the authentication buffer callback
 * @param conn A pointer to the connection that triggered this callback
 * @param auth_type the authentication type
 * @param buffer An opaque buffer object
 * @param length The length of the buffer parameter
 * @param context A pointer to the user defined context
 * @see he_conn_set_context Sets the value of the context pointer
 *
 * The host is expected to interpret this buffer and return whether it considers this connection
 * authenticated.
 */
typedef bool (*he_auth_buf_cb_t)(he_conn_t *conn, uint8_t auth_type, uint8_t *buffer,
                                 uint16_t length, void *context);

/**
 * @brief The prototype for the population of the network config
 * @param conn A pointer to the connection that triggered this callback
 * @param [out] config A valid pointer to a network_config_ipv4_t, to be populated by the host
 * @param context A pointer to the user defined context
 * @see he_conn_set_context Sets the value of the context pointer
 *
 * The host is expected to populate the provided he_network_config_ipv4_t* object with the
 * correct values so that the client can successfully connect.
 *
 */
typedef he_return_code_t (*he_populate_network_config_ipv4_cb_t)(he_conn_t *conn,
                                                                 he_network_config_ipv4_t *config,
                                                                 void *context);

/**
 * @brief The prototype for the Path MTU Discovery (PMTUD) time callback function
 * @param conn A pointer to the connection that triggered this callback
 * @param timeout The number of milliseconds to wait before calling the he_conn_pmtud_timeout
 * function. If the timeout value is 0, the host application should cancel the timer.
 * @param context A pointer to the user defined context
 * @see he_conn_set_context Sets the value of the context pointer
 *
 * Lightway Path MTU Discovery needs to be able to resend probe messages if they are not received in
 * time. As Lightway Core does not have its own threads or timers, it is up to the host application
 * to tell Lightway Core when a certain amount of time has passed.
 *
 * The host application must register this callback to enable Path MTU discovery.
 *
 * @note Any pending timers should be reset with the value provided in the callback and there should
 * only ever be one timer per connection context.
 */
typedef he_return_code_t (*he_pmtud_time_cb_t)(he_conn_t *conn, int timeout, void *context);

/**
 * @brief The prototype for Lightway PMTUD state callback function
 * @param conn A pointer to the connection that triggered this callback
 * @param state The state that Lightway PMTUD has just entered
 * @param context A pointer to the user defined context
 * @see he_conn_set_context Sets the value of the context pointer
 *
 * Whenever Lightway PMTUD changes state, this function will be called.
 */
typedef he_return_code_t (*he_pmtud_state_change_cb_t)(he_conn_t *conn, he_pmtud_state_t state,
                                                       void *context);

typedef struct he_network_config_ipv4 {
  char local_ip[HE_MAX_IPV4_STRING_LENGTH];
  char peer_ip[HE_MAX_IPV4_STRING_LENGTH];
  char dns_ip[HE_MAX_IPV4_STRING_LENGTH];
  int mtu;
} he_network_config_ipv4_t;

#pragma pack(1)

/**
 * @brief The wire header format
 * It is strongly discouraged to interact with this header structure, however,
 * it is provided for specific use cases (such as a server rejecting a session,
 * where by definition we don't have a connection object).
 */
typedef struct he_wire_hdr {
  // First two bytes to contain the 'H' and 'e'
  char he[2];
  // Version of the wire protocol
  uint8_t major_version;
  uint8_t minor_version;
  // Request aggressive mode
  uint8_t aggressive_mode;
  // Three bytes reserved for future use
  uint8_t reserved[3];
  // 64 bit session identifier
  uint64_t session;
} he_wire_hdr_t;

#pragma pack()

/** Session codes **/
static const uint64_t HE_PACKET_SESSION_REJECT = 0xFFFFFFFFFFFFFFFF;
static const uint64_t HE_PACKET_SESSION_EMPTY = 0x0000000000000000;

#endif  // HE_H
