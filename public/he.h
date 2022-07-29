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
  /// PMTUD callbacks not set
  HE_ERR_PMTUD_CALLBACKS_NOT_SET = -59,
  /// The fragment was invalid
  HE_ERR_BAD_FRAGMENT = -60,
  /// Error occurred during secure renegotiation
  HE_ERR_SECURE_RENEGOTIATION_ERROR = -61,
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
 * @param timeout The number of milliseconds to wait before calling the he_conn_pmtud_probe_timeout
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
 * Whenever Lightway PMTUD changes state, this function will be called. This callback is
 * mostly for informational only, there's no hard expectation for the callback to do anything.
 * However, this callback may be useful for certain application logic which is triggered by the
 * state changes.
 *
 * The host application must register this callback to enable Path MTU discovery.
 *
 * @see RFC 8899 for more information about PMTUD state machines.
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

/**
 * @brief Set allocators for use by libhelium
 * @param malloc A function that conforms to the signature of malloc(3)
 * @param calloc A function that conforms to the signature of calloc(3)
 * @param realloc A function that conforms to the signature of realloc(3)
 * @param free A function that conforms to the signature of free(3)
 *
 * @return HE_SUCCESS Currently this function cannot fail
 * @note If this function is not called, Helium will use system allocators by default
 */
he_return_code_t he_set_allocators(he_malloc_t malloc, he_calloc_t calloc, he_realloc_t realloc,
                                   he_free_t free);

/**
 * @brief Allocate memory using the internal malloc function set by he_set_allocators()
 * @note The caller must call he_free when the allocated memory is no longer used
 */
void *he_malloc(size_t size);

/**
 * @brief Allocate memory using the internal calloc function set by he_set_allocators()
 * @note The caller must call he_free when the allocated memory is no longer used
 */
void *he_calloc(size_t nmemb, size_t size);

/**
 * @brief Allocate memory using the internal realloc function set by he_set_allocators()
 * @note The caller must call he_free when the allocated memory is no longer used
 */
void *he_realloc(void *ptr, size_t size);

/**
 * @brief Free memory using the internal free function set by he_set_allocators()
 */
void he_free(void *ptr);

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
 * @param server_config_cb The function to be called when Helium needs to pass server config
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
 * @param auth_token_cb The function to be called when Helium needs to authenticate a user
 */
void he_ssl_ctx_set_auth_token_cb(he_ssl_ctx_t *ctx, he_auth_token_cb_t auth_token_cb);

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
 * @brief Sets the function that will be called when Lightway PMTUD changes state.
 * @param ctx A pointer to a valid SSL context
 * @param pmtud_state_change_cb The function to be called when Lightway PMTUD changes state
 * @note This callback function is optional if the implementation never intends to use the PMTUD
 * feature.
 */
void he_ssl_ctx_set_pmtud_state_change_cb(he_ssl_ctx_t *ctx,
                                          he_pmtud_state_change_cb_t pmtud_state_change_cb);

/**
 * @brief Sets the function that will be called when Lightway PMTUD needs to start the timer
 * @param ctx A pointer to a valid SSL context
 * @param pmtud_time_cb The function to be called when Lightway PMTUD needs to start the timer
 * @note This callback function is optional if the implementation never intends to use the PMTUD
 * feature.
 */
void he_ssl_ctx_set_pmtud_time_cb(he_ssl_ctx_t *ctx, he_pmtud_time_cb_t pmtud_time_cb);

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

/**
 * @brief Sets the maximum number of entries the connection can use for reassembling fragments.
 * @param max_frag_entries Max number of entries for fragment assembly.
 * @return HE_SUCCESS if the value is set successfully.
 */
he_return_code_t he_ssl_ctx_set_max_frag_entries(he_ssl_ctx_t *ctx, size_t max_frag_entries);

/**
 * D/TLS is a UDP based protocol and requires the application
 * (rather than the OS as with TCP) to keep track of the need to do
 * retransmits on packet loss.
 *
 * Currently Wolf has timeouts based in seconds. However this is not
 * sufficient for our goal of sub-second connection times.
 *
 * As WolfSSL lacks millisecond timers we use its internal timers but
 * change its definition to be in 100 millisecond intervals instead of
 * seconds. So a wolf timeout of 1 second means 100 milliseconds.
 *
 * By default wolf's DTLS max timeout is 64 seconds which translates to
 * 6.4 seconds. Since it scales from 1 to 64 by a factor
 * of 2 each timeout. The total timeout is 12.7 seconds with this scaling
 * which for our purposes is plenty.
 */
#define HE_WOLF_TIMEOUT_MULTIPLIER 100

#define HE_WOLF_RENEGOTIATION_TIMEOUT_MULTIPLIER 100

/**
 * Divider to use when wolfSSL signals that it wants to perform a short
 * timeout to check for any additional out of order messages before
 * performing retransmission.
 */
#define HE_WOLF_QUICK_TIMEOUT_DIVIDER 4

/**
 * @brief Creates a Helium connection struct
 * @return he_conn_t* Returns a pointer to a valid Helium connection
 * @note This function allocates memory
 *
 * This function must be called to create the initial Helium connection
 * for use with other functions.
 */
he_conn_t *he_conn_create(void);

/**
 * @brief Releases all memory allocate by Helium for this connection
 * @param conn A pointer to a valid Helium connection
 *
 * It will first remove all of the callbacks which means no Helium callbacks will be triggered after
 * calling this function. It is thus an error to call any Helium functions on this connection after
 * it has been destroyed.
 */
void he_conn_destroy(he_conn_t *conn);

/**
 * @brief Checks whether the client conn has the basic values to allow Helium to connect.
 * @param ssl_ctx A pointer to a valid SSL context
 * @param conn A pointer to a valid connection conn
 * @return HE_ERR_NULL_POINTER The conn pointer supplied is NULL
 * @return HE_ERR_CONF_USERNAME_NOT_SET The username has not been set
 * @return HE_ERR_CONF_PASSWORD_NOT_SET The password has not been set
 * @return HE_ERR_CONF_MTU_NOT_SET The external MTU has not been set
 * @return HE_ERR_INCORRECT_PROTOCOL_VERSION The protocol version has been set but it's not equal to
 * the maximum supported version defined in the ssl_ctx
 * @return HE_SUCCESS The basic configuration options have been set
 *
 * @note These return codes are similar to `he_conn_client_connect` because that function will call
 *       this function before attempting to connect.
 */
he_return_code_t he_conn_is_valid_client(he_ssl_ctx_t *ssl_ctx, he_conn_t *conn);

/**
 * @brief Checks whether the client conn has the basic values to allow Helium to connect.
 * @param ssl_ctx A pointer to a valid SSL context
 * @param conn A pointer to a valid connection conn
 * @return HE_ERR_NULL_POINTER The conn pointer supplied is NULL
 * @return HE_ERR_CONF_MTU_NOT_SET The external MTU has not been set
 * @return HE_ERR_INCORRECT_PROTOCOL_VERSION The protocol version has been set to an unsupported
 * version
 * @return HE_SUCCESS The basic configuration options have been set
 *
 * @note These return codes are similar to `he_conn_server_connect` because that function will call
 *       this function before attempting to connect.
 */
he_return_code_t he_conn_is_valid_server(he_ssl_ctx_t *ssl_ctx, he_conn_t *conn);

/**
 * @brief Set the username to authenticate with
 * @param conn A pointer to a valid conn
 * @param username A pointer to the username
 * @return HE_SUCCESS Username has been set
 * @return HE_ERR_STRING_TOO_LONG Username is too long
 * @return HE_ERR_EMPTY_STRING String is empty
 */
int he_conn_set_username(he_conn_t *conn, const char *username);

/**
 * @brief Get the username that Helium will authenticate with, previously set by
 * he_conn_set_username
 * @param conn A pointer to a valid connection
 * @return const char* A pointer to the username
 */
const char *he_conn_get_username(const he_conn_t *conn);

/**
 * @brief Check if the password has been set.
 * @param conn A pointer to a valid connection
 * @return bool Returns true or false depending on whether it has been configured
 *
 * It is anticipated that this feature will be used for implementing UIs that don't maintain their
 * own connection state.
 */
bool he_conn_is_username_set(const he_conn_t *conn);

/**
 * @brief Sets the password Helium should use to authenticate with
 * @param conn A pointer to a valid connection
 * @param password A pointer to the password
 * @return HE_SUCCESS The password has been set
 * @return HE_ERR_STRING_TOO_LONG Password is too long
 * @return HE_ERR_EMPTY_STRING String is empty
 * @note There is no he_conn_get_password or equivalent for security reasons
 */
he_return_code_t he_conn_set_password(he_conn_t *conn, const char *password);

/**
 * @brief Check if the password has been set.
 * @param conn A pointer to a valid connection
 * @return bool Returns true or false depending on whether it has been configured
 *
 * It is anticipated that this feature will be used for implementing UIs that don't maintain their
 * own connection state.
 */
bool he_conn_is_password_set(const he_conn_t *conn);

/**
 * @brief Sets the authentication token the Lightway client should use to authenticate with.
 * @param conn A pointer to a valid connection
 * @param token A pointer to the buffer containing the token
 * @param len The length of the token in bytes, it must be smaller than HE_MAX_MTU
 * @return HE_SUCCESS The auth token has been set
 * @return HE_ERR_STRING_TOO_LONG The length of token is equal or greater than HE_MAX_MTU
 * @return HE_ERR_EMPTY_STRING String is empty
 * @note There is no he_conn_get_token or equivalent for security reasons
 *
 * It's recommended to use a signed JSON Web Token (JWT - RFC 7519) as the auth token, but
 * implementations might choose to use other formats.
 */
he_return_code_t he_conn_set_auth_token(he_conn_t *conn, const uint8_t *token, size_t len);

/**
 * @brief Check if the auth token has been set.
 * @param conn A pointer to a valid connection
 * @return bool Returns true or false depending on whether it has been configured
 *
 * It is anticipated that this feature will be used for implementing UIs that don't maintain their
 * own connection state.
 */
bool he_conn_is_auth_token_set(const he_conn_t *conn);

/**
 * @brief Sets the opaque buffer Helium should use to authenticate with
 * @param conn A pointer to a valid connection
 * @param buffer A pointer to the authentication buffer to use
 * @param length The length of the buffer in bytes.
 *
 * @return HE_SUCCESS the auth buffer has been set
 * @return HE_ERR_STRING_TOO_LONG if length is greater than the maximum buffer size
 */
he_return_code_t he_conn_set_auth_buffer2(he_conn_t *conn, const uint8_t *buffer, uint16_t length);

/**
 * @brief Check if the auth buffer has been set
 * @param conn A pointer to a valid connection
 * @return bool Returns true or false depending on whether it has been configured
 *
 * It is anticipated that this feature will be used for implementing UIs that don't maintain their
 * own connection state.
 */
bool he_conn_is_auth_buffer_set(const he_conn_t *conn);

/**
 * @brief Set the MTU for the outside transport mechanism. Usually this will be the MTU of the
 * device's internet connection.
 * @param conn A pointer to a valid connection
 * @param mtu The MTU of the outside transport mechanism in bytes
 * @return HE_SUCCESS The MTU value was set
 * @return HE_ERR_NULL_POINTER if the conn is NULL
 * @note A default value is not set as although Ethernet is almost always 1500, mobile devices have
 * a wide range of options.
 */
he_return_code_t he_conn_set_outside_mtu(he_conn_t *conn, uint16_t mtu);

/**
 * @brief Get the MTU value for the outside transport mechanism.
 * @param conn A pointer to a valid connection.
 * @return The MTU value in bytes.
 */
uint16_t he_conn_get_outside_mtu(he_conn_t *conn);

/**
 * @brief Check if the outside MTU has been set.
 * @param conn A pointer to a valid connection
 * @return bool Returns true or false depending on whether it has been configured
 *
 * It is anticipated that this feature will be used for implementing UIs that don't maintain their
 * own connection state.
 */
bool he_conn_is_outside_mtu_set(he_conn_t *conn);

/**
 * @brief Store a pointer in the context that will be made available in all Helium callbacks
 * @param conn A valid connection
 * @param data A pointer to a user provided data structure
 *
 * Helium will interact with the host application primarily through the use of callback functions.
 * To avoid the need for global variables, a pointer to some data structure can be set on the
 * context. This context will be passed in all function callbacks as void pointer.
 */
he_return_code_t he_conn_set_context(he_conn_t *conn, void *data);

/**
 * @brief Retrieve the pointer to the user supplied context.
 * @param conn A pointer to a valid HE context
 * @return void* The void pointer that was set previously or NULL if none was set
 */
void *he_conn_get_context(he_conn_t *conn);

/**
 * @brief Set SNI hostname
 * @param conn A valid connection
 * @param hostname A null-terminated string contains the SNI hostname
 *
 * If the hostname is not empty, the client will enable SNI and set the hostname in the ClientHello
 * message when connecting to the server. Available for TLS v1.3 only.
 */
he_return_code_t he_conn_set_sni_hostname(he_conn_t *conn, const char *hostname);

/**
 * @brief Tries to establish a connection with a Helium server
 * @param conn A pointer to a valid Helium connection
 * @param ssl_ctx A pointer to valid and started SSL context
 * @param inside_plugins A pointer to a valid plugin chain
 * @param outside_plugins A pointer to a valid plugin chain
 * @return HE_ERR_NULL_POINTER One or more required pointers are NULL
 * @return HE_ERR_CONF_USERNAME_NOT_SET The username has not been set
 * @return HE_ERR_CONF_PASSWORD_NOT_SET The password has not been set
 * @return HE_ERR_CONF_MTU_NOT_SET The external MTU has not been set
 * @return HE_ERR_INIT_FAILED Helium was unable to initialise itself
 * @return HE_ERR_SSL_CERT Generic failure in the SSL engine
 * @return HE_ERR_CONNECT_FAILED There was an I/O issue trying to connect to the server.
 * @return HE_SUCCESS Helium is in the process of connecting
 *
 * @note This function triggers the initialisation and initial connection to a Helium server.
 * However it is asynchronous, Helium is *not* connected when this function returns, merely that the
 * connection is in progress. Use event and state change callbacks to determine the actual state of
 * Helium
 *
 * This function has a lot of return codes as it is where Helium tries to apply and configure the
 * crypto engine. All of the return codes except for HE_SUCCESS are effectively fatal errors. Trying
 * to call *he_conn_client_connect* again without changing the connection is unlikely to succeed.
 */
he_return_code_t he_conn_client_connect(he_conn_t *conn, he_ssl_ctx_t *ssl_ctx,
                                        he_plugin_chain_t *inside_plugins,
                                        he_plugin_chain_t *outside_plugins);

/**
 * @brief Tries to establish a connection with a Helium client
 * @param conn A pointer to a valid Helium connection
 * @param ssl_ctx A pointer to valid and started SSL context
 * @param inside_plugins A pointer to a valid plugin chain
 * @param outside_plugins A pointer to a valid plugin chain
 * @return HE_ERR_NULL_POINTER One or more required pointers are NULL
 * @return HE_ERR_INIT_FAILED Helium was unable to initialise itself
 * @return HE_ERR_SSL_CERT Generic failure in the SSL engine
 * @return HE_ERR_CONNECT_FAILED There was an I/O issue trying to connect to the server.
 * @return HE_SUCCESS Helium is in the process of connecting
 *
 * @note This function triggers the initialisation and initial connection to a Helium client.
 * However it is asynchronous, Helium is *not* connected when this function returns, merely that the
 * connection is in progress. Use event and state change callbacks to determine the actual state of
 * Helium
 *
 * This function has a lot of return codes as it is where Helium tries to apply and configure the
 * crypto engine. All of the return codes except for HE_SUCCESS are effectively fatal errors. Trying
 * to call *he_conn_client_connect* again without changing the connection is unlikely to succeed.
 */
he_return_code_t he_conn_server_connect(he_conn_t *conn, he_ssl_ctx_t *ssl_ctx,
                                        he_plugin_chain_t *inside_plugins,
                                        he_plugin_chain_t *outside_plugins);

/**
 * @brief Try to cleanly disconnect from the remote Helium instance (client or server).
 * @return HE_ERR_NEVER_CONNECTED The connection has never been connected and so cannot be
 * disconnected. It is safe to destroy the connection state here.
 * @return HE_ERR_INVALID_CONN_STATE This function should only be used when Helium is in the
 * online state. It is safe to destroy the connection in other states.
 * @return HE_SUCCESS The disconnect process has started
 *
 * @note Like he_conn_client_connect, this is an asynchronous process. Watch state changes to
 * determine when Helium has actually disconnected
 * @note This function is not yet well described and is likely to change
 */
he_return_code_t he_conn_disconnect(he_conn_t *conn);

/**
 * @brief Tell Helium to send a keepalive message. This can be used to avoid NAT timing out.
 * @param conn A pointer to a valid connection
 * @return HE_SUCCESS Keep alive was sent
 *
 * This is used to send a heartbeat message to a Helium server and get a reply. Its primary use is
 * to ensure that the connection doesn't time out due to NAT traversal. This feature is not
 * mandatory, but as Helium cannot by itself know when to send these, it is up to the host
 * application to call this function at the required intervals.
 */
he_return_code_t he_conn_send_keepalive(he_conn_t *conn);

/**
 * @brief Tell Helium to send a server config message to client.
 * @param conn A pointer to a valid connection
 * @return HE_SUCCESS the server config was sent
 *
 * This is used to send a server config message to a Helium client from server. The server must have
already established the TLS connection, but it's OK the client is not authenticated yet.
*/
he_return_code_t he_conn_send_server_config(he_conn_t *conn, uint8_t *buffer, size_t length);

/**
 * @brief Tell Helium to schedule a renegotiation
 * @param conn A pointer to a valid connection
 * @return HE_SUCCESS A renegotiation is scheduled.
 *
 * Note that this schedules a key rotation or D/TLS renegotiation on the next time we process
 * data on this connection; calling this function provides *no* time-based guarantees, only that
 * when we see this connection again we will renegotiate.
 */
he_return_code_t he_conn_schedule_renegotiation(he_conn_t *conn);

/**
 * @brief Returns the number of milliseconds that host application should wait before nudging Helium
 * @param conn A pointer to a valid connection
 * @return The number of milliseconds to wait before nudging again
 *
 * @warning This value is updated after Helium completes a read cycle. It should be called directly
 * after those functions
 */
int he_conn_get_nudge_time(he_conn_t *conn);

/**
 * @brief Nudges Helium
 * @param conn A pointer to a valid connection
 * @return HE_SUCCESS The nudge was successful
 * @return HE_CONNECTION_TIMED_OUT Nudge timed out
 */
he_return_code_t he_conn_nudge(he_conn_t *conn);

/**
 * @brief Returns the state that the conn is currently in
 * @param conn A pointer to a valid connection
 * @return he_conn_state_t The state the connection is in
 * @see he_set_state_change_cb
 * @see he_conn_state_t
 */
he_conn_state_t he_conn_get_state(he_conn_t *conn);

/**
 * @brief Returns the session ID for this connection
 */
uint64_t he_conn_get_session_id(he_conn_t *conn);

/**
 * @brief Sets the session ID for this connection
 */
he_return_code_t he_conn_set_session_id(he_conn_t *conn, uint64_t session_id);

/**
 * @brief Returns the pending session ID for this connection, if there is one
 * @param conn A pointer to a valid connection
 * @return 0 If there is no pending session
 * @note On a conn connection this function will always return 0; there are no pending conn
 * session IDs
 */
uint64_t he_conn_get_pending_session_id(he_conn_t *conn);

/**
 * @brief Returns true if a given error (a return from libhelium where he_return_code_t !=
 * HE_SUCCESS) is obviously fatal and should terminate the connection.
 *
 * It is *not* required to call this function -- users are welcome to capture their errors,
 * close connections and reconnect even if this function returns false.
 */
bool he_conn_is_error_fatal(he_conn_t *conn, he_return_code_t error_msg);

/**
 * @brief Rotate the session ID for this connection
 *
 * After calling this function, the value returned by he_conn_get_session_id will NOT be updated.
 * The value returned by he_conn_get_pending_session_id is guaranteed to be the same as the value
 * pointed to by new_session_id if that parameter is not null.
 *
 * After the event "HE_EVENT_PENDING_SESSION_ACKNOWLEDGED" fires, he_conn_get_pending_session_id
 * will return 0, and the value for he_conn_get_session_id will be the same as the session ID
 * generated by this call.
 *
 * @param conn A pointer to a valid connection
 * @param new_session_id A uint64_t pointer; if not null the value will be updated with the new
 * session ID
 * @return HE_ERR_INVALID_CONN_STATE If this connection has not been started, or is a client
 * connection, or there is already a pending session rotation
 * @return HE_ERR_RNG_FAILURE if we were unable to generate a random number
 * @return HE_SUCCESS Session ID rotation begun
 */
he_return_code_t he_conn_rotate_session_id(he_conn_t *conn, uint64_t *new_session_id);

/**
 * @brief Whether this particular connection supports renegotiation
 *
 * Only pre-Dec 2020 clients won't support this.
 */
bool he_conn_supports_renegotiation(he_conn_t *conn);

/**
 * @brief On the server, sets the major/minor version number for this connection
 * @param conn A pointer to a valid server connection
 * @param major_version The connection major version
 * @param minor_version The connection minor version
 * @return HE_SUCCESS if the major/minor version was set successfully
 * @note It will result in an invalid state if the protocol version is set on a connection that is
 * later used as a client connection
 */
he_return_code_t he_conn_set_protocol_version(he_conn_t *conn, uint8_t major_version,
                                              uint8_t minor_version);

/**
 * @brief On the server, get the current major/minor version number for this connection
 * @param conn A pointer to a valid server connection
 * @param major_version Pointer to the connection major version
 * @param minor_version Pointer to the connection minor version
 * @return HE_SUCCESS if the major/minor version was get successfully.
 */
he_return_code_t he_conn_get_protocol_version(he_conn_t *conn, uint8_t *major_version,
                                              uint8_t *minor_version);

/**
 * @brief Returns the name of the cipher used by the ssl context.
 * @param conn A pointer to a valid connection
 * @return The string representation of the cipher
 */
const char *he_conn_get_current_cipher(he_conn_t *conn);

/**
 * @brief Returns the current connection protocol.
 * @param conn A pointer to a valid connection
 * @return Enum value of that protocol or the NONE if invalid.
 */
he_connection_protocol_t he_conn_get_current_protocol(he_conn_t *conn);

/**
 * @brief Returns the name of the curve used by the ssl context.
 * @param conn A pointer to a valid connection
 * @return The string representation of the curve
 */
const char *he_conn_get_curve_name(he_conn_t *conn);

/**
 * @brief Tell Helium to start a PMTU discovery
 * @param conn A pointer to a valid connection
 * @return HE_SUCCESS PMTU discovery is started
 * @return HE_ERR_INVALID_CONN_STATE if the connection hasn't established the TLS link yet
 * @return HE_ERR_PMTUD_CALLBACKS_NOT_SET if PMTUD callbacks are not set
 */
he_return_code_t he_conn_start_pmtu_discovery(he_conn_t *conn);

/**
 * @brief Get current effective PMTU of the connection
 * @param conn A pointer to a valid connection
 * @return Returns current effective PMTU. If PMTU discovery has never been run, it returns the
 * default HE_MAX_MTU.
 */
uint16_t he_conn_get_effective_pmtu(he_conn_t *conn);

/**
 * @brief Called when a PMTUD probe timer expired
 * @param conn A pointer to a valid connection
 * @return HE_SUCCESS if the probe timeout is handled successfully.
 */
he_return_code_t he_conn_pmtud_probe_timeout(he_conn_t *conn);

/**
 * @brief Returns detailed SSL error that corresponds to WolfSSL's detailed errors
 * @param conn A pointer to a valid server connection
 * @return Integer that corresponds to a WolfSSL error or 0 if no detailed
 * error is available
 */
int he_conn_get_ssl_error(he_conn_t *conn);

/**
 * @brief Called when the host application needs to deliver an inside packet to Helium.
 * @param conn A valid connection
 * @param packet A pointer to the packet data
 * @param length The length of the packet
 * @return HE_ERR_INVALID_CLIENT_STATE Helium will reject packets if it is not in the
 * HE_STATE_ONLINE state
 * @return HE_ERR_PACKET_TOO_SMALL The packet is too small to be a valid Helium packet
 * @return HE_ERR_UNSUPPORTED_PACKET_TYPE The packet is not an IPv4 packet
 * @return HE_ERR_FAILED The packet was rejected as it won't fit in internal buffers
 * @return HE_SUCCESS Packet was processed normally
 * @note It is expected that Helium will support IPv6 almost immediately, so it is worth keeping
 * this in mind.
 * @note These error codes may change before final release as new issues come to light.
 */
he_return_code_t he_conn_inside_packet_received(he_conn_t *conn, uint8_t *packet, size_t length);

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
 * @return HE_SUCCESS The packet was processed normally.
 * @note These error codes may change before final release as new issues come to light.
 * @note If the conn has registered plugins, they may arbitrarily change the packet data,
 * but are restricted here to not exceeding the provided length. Users
 * who wish to have more control over this should *not* register plugins upon connection, but
 * instead call the plugin API explicitly prior to invoking this function.
 */
he_return_code_t he_conn_outside_data_received(he_conn_t *conn, uint8_t *buffer, size_t length);

/**
 * @brief Creates a Helium plugin chain
 * @return he_plugin_chain_t* Returns a pointer to a valid plugin chain
 * @note This function allocates memory
 *
 * This function must be called to create the initial plugin chain for use
 * with other functions
 */
he_plugin_chain_t *he_plugin_create_chain(void);

/**
 * @brief Releases all memory allocated by Helium for this plugin chain
 * @param chain A pointer to a valid plugin chain
 * @note he_plugin_destroy_chain does NOT free the `plugin` objects registered to the plugin
 * chain.
 */
void he_plugin_destroy_chain(he_plugin_chain_t *chain);

/**
 * @brief Register the plugin to the plugin chain
 * @param chain A pointer to a valid plugin chain
 * @param plugin A pointer to the *initialised* plugin struct
 * @return HE_SUCCESS Plugin was successfully registered
 * @return HE_ERR_NULL_POINTER Either parameter was NULL
 * @return HE_ERR_INIT_FAILED Registering the plugin failed
 * @note The plugin chain only keeps a reference to the plugin object. The caller is still
 * responsible for freeing the memory used by the `plugin` object after use.
 */
he_return_code_t he_plugin_register_plugin(he_plugin_chain_t *chain, plugin_struct_t *plugin);

/**
 * @brief Execute the ingress function of each registered plugin
 * @param chain A pointer to a valid plugin chain
 * @param packet A pointer to the packet data
 * @param length A pointer to the length of the packet data. If the packet size changed after
 * processed by this function, the `length` will be set to the new length of the packet data.
 * @param capacity The length of the underlying buffer for packet
 * @return HE_SUCCESS All plugins executed successfully
 * @return HE_ERR_PLUGIN_DROP A plugin marked this packet for a drop
 * @return HE_ERR_FAILED An error occurred processing this packet
 * @note The content of packet may be modified, grow or shrunk, depending on the registered plugins
 */
he_return_code_t he_plugin_ingress(he_plugin_chain_t *chain, uint8_t *packet, size_t *length,
                                   size_t capacity);

/**
 * @brief Execute the egress function of each registered plugin
 * @param chain A pointer to a valid plugin chain
 * @param packet A pointer to the packet data
 * @param length A pointer to the length of the packet data. If the packet size changed after
 * processed by this function, the `length` will be set to the new length of the packet data.
 * @param capacity The length of the underlying buffer for packet
 * @return HE_SUCCESS All plugins executed successfully
 * @return HE_ERR_PLUGIN_DROP A plugin marked this packet for a drop
 * @return HE_ERR_FAILED An error occurred processing this packet
 * @note The content of packet may be modified, grow or shrunk, depending on the registered plugins
 */
he_return_code_t he_plugin_egress(he_plugin_chain_t *chain, uint8_t *packet, size_t *length,
                                  size_t capacity);

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

#endif  // HE_H
