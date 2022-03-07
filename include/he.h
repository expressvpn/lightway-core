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
 * @brief Core internal header file for libhelium
 *
 * This file includes common type definitions and useful constants for ensuring consistency across
 * the code files for libhelium. It should be included by every header file.
 *
 * Parts of this file are included in the public header, but other parts are considered "internal"
 * implementation details.
 *
 */

#ifndef HE
#define HE

// Needed headers
#include <stdbool.h>
#include <stdint.h>

// Network headers
#include "he_plugin.h"

// WolfSSL
#ifndef WOLFSSL_USER_SETTINGS
#include <wolfssl/options.h>
#endif
#include <wolfssl/ssl.h>
#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/random.h>

// Helper macros

/** Set sizes **/
#define HE_MAX_WIRE_MTU 1500
#define HE_MAX_MTU 1350
#define HE_MAX_MTU_STR "1350"

/** Set Maximum and Minimum Minor Versions **/
#define HE_WIRE_MINIMUM_PROTOCOL_MAJOR_VERSION 1
#define HE_WIRE_MINIMUM_PROTOCOL_MINOR_VERSION 0
#define HE_WIRE_MAXIMUM_PROTOCOL_MAJOR_VERSION 1
#define HE_WIRE_MAXIMUM_PROTOCOL_MINOR_VERSION 1

/** Begin Public Section **/

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

typedef struct he_ssl_ctx he_ssl_ctx_t;
typedef struct he_conn he_conn_t;
typedef struct he_plugin_chain he_plugin_chain_t;
typedef struct he_network_config_ipv4 he_network_config_ipv4_t;

/**
 * @brief Data structure to hold all the state needed as a Helium client
 *
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
 * or equal in length to  HE_CONFIG_TEXT_FIELD_LENGTH
 */
typedef bool (*he_auth_cb_t)(he_conn_t *conn, char const *username, char const *password,
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

/** End Public Section **/

typedef struct he_packet_buffer {
  // Buffer has data
  bool has_packet;
  // Size of packet
  int packet_size;
  // The packet itself
  uint8_t packet[HE_MAX_WIRE_MTU];
} he_packet_buffer_t;

// Note that this is *not* intended for use on the wire; this struct is part of
// the internal API and just conveniently connects these two numbers together.
typedef struct he_version_info {
  // Version of the wire protocol
  uint8_t major_version;
  uint8_t minor_version;
} he_version_info_t;

struct he_ssl_ctx {
  /// Server Distinguished Name -- room for a null on the end
  char server_dn[HE_CONFIG_TEXT_FIELD_LENGTH + 1];
  /// Whether or not to use the CHACHA20 cipher
  bool use_chacha;
  // Location of Client CA certificate in PEM format
  uint8_t *cert_buffer;
  /// The size of the Client CA certificate chain
  size_t cert_buffer_size;

  // Server certificate location
  char const *server_cert;
  // Server certificate key location
  char const *server_key;

  he_connection_type_t connection_type;
  /// State callback
  he_state_change_cb_t state_change_cb;
  /// Callback for writing to the inside (i.e. a TUN device)
  he_inside_write_cb_t inside_write_cb;
  /// Callback for writing to the outside (i.e. a socket)
  he_outside_write_cb_t outside_write_cb;
  /// Network config callback
  he_network_config_ipv4_cb_t network_config_ipv4_cb;
  /// Nudge timer
  he_nudge_time_cb_t nudge_time_cb;
  // Callback for events
  he_event_cb_t event_cb;
  // Callbacks for auth (server-only)
  he_auth_cb_t auth_cb;
  he_auth_buf_cb_t auth_buf_cb;
  // Callback for populating the network config (server-only)
  he_populate_network_config_ipv4_cb_t populate_network_config_ipv4_cb;
  /// Don't send session ID in packet header
  bool disable_roaming_connections;
  /// Which padding type to use
  he_padding_type_t padding_type;
  /// Use aggressive mode
  bool use_aggressive_mode;

  /// WolfSSL global context
  WOLFSSL_CTX *wolf_ctx;
  // Random number generator
  RNG wolf_rng;

  /// Supported versions for this context
  he_version_info_t minimum_supported_version;
  he_version_info_t maximum_supported_version;
};

struct he_conn {
  /// Internal Structure Member for client/server determination
  /// No explicit setter or getter, we internally set this in
  /// either client or server connect functions
  bool is_server;

  /// Client State
  he_conn_state_t state;

  /// Pointer to incoming data buffer
  uint8_t *incoming_data;
  /// Length of the data in the
  size_t incoming_data_length;
  // WolfSSL stuff
  WOLFSSL *wolf_ssl;
  /// Wolf Timeout
  int wolf_timeout;
  /// Write buffer
  uint8_t write_buffer[HE_MAX_WIRE_MTU];
  /// Packet seen
  bool packet_seen;
  /// Session ID
  uint64_t session_id;
  uint64_t pending_session_id;
  /// Read packet buffers // Datagram only
  he_packet_buffer_t read_packet;
  /// Has the first message been received?
  bool first_message_received;
  /// Bytes left to read in the packet buffer (Streaming only)
  size_t incoming_data_left_to_read;
  /// Index into the incoming data buffer
  uint8_t *incoming_data_read_offset_ptr;

  bool renegotiation_in_progress;
  bool renegotiation_due;

  /// Do we already have a timer running? If so, we don't want to generate new callbacks
  bool is_nudge_timer_running;

  he_plugin_chain_t *inside_plugins;
  he_plugin_chain_t *outside_plugins;

  uint8_t auth_type;

  /// VPN username -- room for a null on the end
  char username[HE_CONFIG_TEXT_FIELD_LENGTH + 1];
  /// VPN password -- room for a null on the end
  char password[HE_CONFIG_TEXT_FIELD_LENGTH + 1];

  uint8_t auth_buffer[HE_MAX_MTU];
  uint16_t auth_buffer_length;

  /// MTU Helium should use for the outside connection (i.e. Internet)
  int outside_mtu;

  void *data;

  // Data from the SSL contxt config copied here to make this hermetic
  /// Don't send session ID in packet header
  bool disable_roaming_connections;
  /// Which padding type to use
  he_padding_type_t padding_type;
  /// Use aggressive mode
  bool use_aggressive_mode;
  /// TCP or UDP?
  he_connection_type_t connection_type;

  /// State callback
  he_state_change_cb_t state_change_cb;
  /// Nudge timer
  he_nudge_time_cb_t nudge_time_cb;
  /// Callback for writing to the inside (i.e. a TUN device)
  he_inside_write_cb_t inside_write_cb;
  /// Callback for writing to the outside (i.e. a socket)
  he_outside_write_cb_t outside_write_cb;
  /// Network config callback
  he_network_config_ipv4_cb_t network_config_ipv4_cb;
  // Callback for events
  he_event_cb_t event_cb;
  // Callback for auth (server-only)
  he_auth_cb_t auth_cb;
  he_auth_buf_cb_t auth_buf_cb;
  // Callback for populating the network config (server-only)
  he_populate_network_config_ipv4_cb_t populate_network_config_ipv4_cb;

  /// Connection version -- set on client side, accepted on server side
  he_version_info_t protocol_version;

  /// Random number generator
  RNG wolf_rng;
};

struct he_plugin_chain {
  plugin_struct_t *plugin;
  he_plugin_chain_t *next;
};

// MSG IDs
typedef enum msg_ids {
  /// NOOP - nothing to do
  HE_MSGID_NOOP = 1,
  /// Ping reqest
  HE_MSGID_PING = 2,
  /// Pong - response to a Ping request
  HE_MSGID_PONG = 3,
  /// Authentication Request (only server should see this)
  HE_MSGID_AUTH = 4,
  /// Data packet - contains data to be sent to the tun device
  HE_MSGID_DATA = 5,
  /// Config
  HE_MSGID_CONFIG_IPV4 = 6,
  /// Auth response
  HE_MSGID_AUTH_RESPONSE = 7,
  /// Auth response with config (fast login)
  HE_MSGID_AUTH_RESPONSE_WITH_CONFIG = 8,
  /// Helium Extension message
  HE_MSGID_EXTENSION = 9,
  /// Session Request
  HE_MSGID_SESSION_REQUEST = 10,
  /// Session Response
  HE_MSGID_SESSION_RESPONSE = 11,
  /// Tell the other side that we're closing down
  HE_MSGID_GOODBYE = 12,
  /// Deprecated message - same as Data packet with an unused int flag
  HE_MSGID_DEPRECATED_13 = 13
} msg_ids_t;

typedef enum he_auth_type { HE_AUTH_TYPE_USERPASS = 1 } he_auth_type_t;

/** Begin Public Section **/

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

/** End Public Section **/

typedef struct he_msg_hdr {
  uint8_t msgid;
} he_msg_hdr_t;

typedef struct he_msg_ping {
  he_msg_hdr_t msg_header;
  uint32_t payload;
} he_msg_ping_t;

typedef struct he_msg_pong {
  he_msg_hdr_t msg_header;
  uint32_t payload;
} he_msg_pong_t;

typedef struct he_msg_auth_hdr {
  he_msg_hdr_t msg_header;
  uint8_t auth_type;
} he_msg_auth_hdr_t;

typedef struct he_msg_auth {
  he_msg_auth_hdr_t header;
  uint8_t username_length;
  uint8_t password_length;
  char username[HE_CONFIG_TEXT_FIELD_LENGTH];
  char password[HE_CONFIG_TEXT_FIELD_LENGTH];
} he_msg_auth_t;

typedef struct he_msg_auth_buf {
  he_msg_auth_hdr_t header;
  uint16_t buffer_length;
  uint8_t buffer[];
} he_msg_auth_buf_t;

typedef struct he_msg_config_ipv4 {
  he_msg_hdr_t msg_header;
  char local_ip[HE_MAX_IPV4_STRING_LENGTH];
  char peer_ip[HE_MAX_IPV4_STRING_LENGTH];
  char dns_ip[HE_MAX_IPV4_STRING_LENGTH];
  char mtu[HE_MAX_IPV4_STRING_LENGTH];
  uint64_t session;
} he_msg_config_ipv4_t;

typedef struct he_msg_data {
  he_msg_hdr_t msg_header;
  uint16_t length;
} he_msg_data_t;

typedef struct he_deprecated_msg_13 {
  he_msg_hdr_t msg_header;
  uint16_t length;
  uint16_t _unused;
} he_deprecated_msg_13_t;

#define HE_AUTH_STATUS_SUCCESS 0
#define HE_AUTH_STATUS_FAILURE 1

typedef struct he_msg_auth_response {
  he_msg_hdr_t msg_header;
  uint8_t status;
  uint8_t status_msg_length;
  char status_msg[HE_CONFIG_TEXT_FIELD_LENGTH];
} he_msg_auth_response_t;

typedef struct he_msg_session_request {
  he_msg_hdr_t msg_header;
} he_msg_session_request_t;

typedef struct he_msg_session_response {
  he_msg_hdr_t msg_header;
  uint64_t session;
} he_msg_session_response_t;

typedef struct he_msg_goodbye {
  he_msg_hdr_t msg_header;
} he_msg_goodbye_t;

#define HE_EXT_TYPE_REQUEST 1
#define HE_EXT_TYPE_RESPONSE 2

#define HE_EXT_ID_BLOCK_DNS_OVER_TLS 1

#define HE_EXT_PAYLOAD_TYPE_MSGPACK 1
#define HE_EXT_PAYLOAD_TYPE_BINARY 2
#define HE_EXT_PAYLOAD_TYPE_INT16 3

typedef struct he_msg_extension {
  he_msg_hdr_t msg_header;
  uint16_t extension_id;
  uint8_t msg_type;
  uint8_t payload_type;
  uint16_t payload_length;
  uint8_t data;

} he_msg_extension_t;

/** Begin Public Section **/
#pragma pack()

/** Session codes **/
static const uint64_t HE_PACKET_SESSION_REJECT = 0xFFFFFFFFFFFFFFFF;
static const uint64_t HE_PACKET_SESSION_EMPTY = 0x0000000000000000;

/** End Public Section **/

// D/TLS headers + AES crypto fields
#define HE_WOLF_MAX_HEADER_SIZE 37
#define HE_IPV4_HEADER_SIZE 20
#define HE_TCP_HEADER_SIZE 20
#define HE_UDP_HEADER_SIZE 8
// Add a gap to avoid normal ADSL / PPPoX type overhead
#define HE_HEADER_SAFE_GAP 28
static const size_t HE_PACKET_OVERHEAD = sizeof(he_deprecated_msg_13_t) + sizeof(he_wire_hdr_t) +
                                         HE_IPV4_HEADER_SIZE + HE_UDP_HEADER_SIZE +
                                         HE_WOLF_MAX_HEADER_SIZE + HE_HEADER_SAFE_GAP;

#define HE_MSS_OVERHEAD (HE_IPV4_HEADER_SIZE + HE_UDP_HEADER_SIZE)

#endif
