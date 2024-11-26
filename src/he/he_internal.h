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
 * @file he_internal.h
 * @brief Core internal header file for libhelium
 *
 * This file includes common type definitions and useful constants for ensuring consistency across
 * the code files for libhelium. It should be included by every header file.
 */

#ifndef HE_INTERNAL
#define HE_INTERNAL

#include "he.h"

// Needed headers
#include <stdbool.h>
#include <stdint.h>

#ifdef HE_ENABLE_MULTITHREADED
#include <stdatomic.h>
#endif

// Network headers
#include "he_plugin.h"

// Dynamic MTU
#include "pmtud.h"

// WolfSSL
#ifndef WOLFSSL_USER_SETTINGS
#include <wolfssl/options.h>
#endif
#include <wolfssl/ssl.h>
#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/random.h>

#ifdef HE_ENABLE_MULTITHREADED
# define HE_ATOMIC _Atomic
#else
# define HE_ATOMIC
#endif

#pragma pack(1)

#ifndef HE_THREAD_LOCAL
# if __STDC_VERSION__ >= 201112 && !defined __STDC_NO_THREADS__
#  define HE_THREAD_LOCAL _Thread_local
# elif defined _WIN32
#  define HE_THREAD_LOCAL __declspec(thread)
# elif defined __APPLE__
#  define HE_THREAD_LOCAL __thread
# else
#  error "Cannot define HE_THREAD_LOCAL"
# endif
#endif

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
  /// Server config callback
  he_server_config_cb_t server_config_cb;
  /// Nudge timer
  he_nudge_time_cb_t nudge_time_cb;
  // Callback for events
  he_event_cb_t event_cb;
  // Callbacks for auth (server-only)
  he_auth_cb_t auth_cb;
  he_auth_buf_cb_t auth_buf_cb;
  he_auth_token_cb_t auth_token_cb;
  // Callback for populating the network config (server-only)
  he_populate_network_config_ipv4_cb_t populate_network_config_ipv4_cb;
  // Callback for pmtud
  he_pmtud_time_cb_t pmtud_time_cb;
  he_pmtud_state_change_cb_t pmtud_state_change_cb;
  /// Don't send session ID in packet header
  bool disable_roaming_connections;
  /// Which padding type to use
  he_padding_type_t padding_type;
  /// Use aggressive mode
  bool use_aggressive_mode;
  /// Use PQC Keyshares
  bool use_pqc;

  /// WolfSSL global context
  WOLFSSL_CTX *wolf_ctx;
  // Random number generator
  RNG wolf_rng;

  /// Supported versions for this context
  he_version_info_t minimum_supported_version;
  he_version_info_t maximum_supported_version;

  /// Maximum Fragment Entries
  size_t max_frag_entries;
};

typedef struct he_fragment_table he_fragment_table_t;

struct he_conn {
  /// Internal Structure Member for client/server determination
  /// No explicit setter or getter, we internally set this in
  /// either client or server connect functions
  bool is_server;

  /// Client State
  HE_ATOMIC he_conn_state_t state;

  /// Pointer to incoming data buffer
  uint8_t *incoming_data;
  /// Length of the data in the
  size_t incoming_data_length;
  // WolfSSL stuff
  WOLFSSL *wolf_ssl;
  /// Wolf Timeout
  HE_ATOMIC int wolf_timeout;
  /// Write buffer
  uint8_t write_buffer[HE_MAX_WIRE_MTU];
  /// Packet seen
  bool packet_seen;
  /// Session ID
  HE_ATOMIC uint64_t session_id;
  HE_ATOMIC uint64_t pending_session_id;
  /// Read packet buffers
  he_packet_buffer_t read_packet;
  /// Has the first message been received?
  HE_ATOMIC bool first_message_received;
  /// Bytes left to read in the packet buffer (Streaming only)
  size_t incoming_data_left_to_read;
  /// Index into the incoming data buffer
  uint8_t *incoming_data_read_offset_ptr;

  bool renegotiation_in_progress;
  bool renegotiation_due;

  /// Do we already have a timer running? If so, we don't want to generate new callbacks
  HE_ATOMIC bool is_nudge_timer_running;

  he_plugin_chain_t *inside_plugins;
  he_plugin_chain_t *outside_plugins;

  uint8_t auth_type;

  /// VPN username -- room for a null on the end
  char username[HE_CONFIG_TEXT_FIELD_LENGTH + 1];
  /// VPN password -- room for a null on the end
  char password[HE_CONFIG_TEXT_FIELD_LENGTH + 1];

  /// SNI Hostname
  char sni_hostname[HE_MAX_HOSTNAME_LENGTH + 1];

  /// Authentication data for either HE_AUTH_TYPE_TOKEN or HE_AUTH_TYPE_CB
  uint8_t auth_buffer[HE_MAX_MTU];
  uint16_t auth_buffer_length;

  /// MTU Helium should use for the outside connection (i.e. Internet)
  uint16_t outside_mtu;

  void *data;

  // Data from the SSL context config copied here to make this hermetic
  /// Don't send session ID in packet header
  bool disable_roaming_connections;
  /// Which padding type to use
  he_padding_type_t padding_type;
  /// Use aggressive mode
  bool use_aggressive_mode;
  /// Use PQC Keyshares
  bool use_pqc;
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
  /// Server config callback
  he_server_config_cb_t server_config_cb;
  // Callback for events
  he_event_cb_t event_cb;
  // Callback for auth (server-only)
  he_auth_cb_t auth_cb;
  he_auth_token_cb_t auth_token_cb;
  he_auth_buf_cb_t auth_buf_cb;
  // Callback for populating the network config (server-only)
  he_populate_network_config_ipv4_cb_t populate_network_config_ipv4_cb;
  // Callback for pmtud
  he_pmtud_time_cb_t pmtud_time_cb;
  he_pmtud_state_change_cb_t pmtud_state_change_cb;

  /// Connection version -- set on client side, accepted on server side
  he_version_info_t protocol_version;

  /// Random number generator
  RNG wolf_rng;

  /// Identifier of the next ping message
  uint16_t ping_next_id;
  /// Identifier of the ping message pending reply
  uint16_t ping_pending_id;

  /// Path MTU Discovery state
  he_pmtud_state_t pmtud_state;

  /// Current effective PMTU
  uint16_t effective_pmtu;

  /// PMTUD internal data
  uint16_t pmtud_base;
  uint8_t pmtud_probe_count;
  uint16_t pmtud_probing_size;
  bool pmtud_is_using_big_step;
  uint16_t pmtud_probe_pending_id;

  /// UDP Fragmentation
  HE_ATOMIC uint16_t frag_next_id;
  he_fragment_table_t *frag_table;

#ifndef HE_ENABLE_MULTITHREADED
  /// Last wolfssl error
  int wolf_error;
#endif
};

struct he_plugin_chain {
  plugin_struct_t *plugin;
  he_plugin_chain_t *next;
};

// MSG IDs
typedef enum msg_ids {
  /// NOOP - nothing to do
  HE_MSGID_NOOP = 1,
  /// Ping request
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
  HE_MSGID_DEPRECATED_13 = 13,
  /// Server configuration data pushed to the client by the server
  HE_MSGID_SERVER_CONFIG = 14,
  /// Fragmented Data Packet
  HE_MSGID_DATA_WITH_FRAG = 15,
} msg_ids_t;

typedef struct he_msg_hdr {
  uint8_t msgid;
} he_msg_hdr_t;

typedef struct he_msg_ping {
  he_msg_hdr_t msg_header;
  /// Identifier for matching the reply message
  uint16_t id;
  /// Length of the payload
  uint16_t length;
  /// Payload
  uint8_t payload[];
} he_msg_ping_t;

typedef struct he_msg_pong {
  he_msg_hdr_t msg_header;
  /// Identifier of the matching ping message
  uint16_t id;
  /// Reserved for backward-compatibility
  uint16_t reserved;
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

typedef struct he_msg_auth_token {
  he_msg_auth_hdr_t header;
  uint16_t token_length;
  uint8_t token[];
} he_msg_auth_token_t;

typedef struct he_msg_auth_buf {
  he_msg_auth_hdr_t header;
  uint16_t buffer_length;
  uint8_t buffer[];
} he_msg_auth_buf_t;

typedef struct he_msg_server_config {
  he_msg_hdr_t msg_header;
  uint16_t buffer_length;
  uint8_t buffer[];
} he_msg_server_config_t;

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

#define HE_FRAG_MF_MASK 0x2000
#define HE_FRAG_OFF_MASK 0x1FFF
#define HE_FRAG_TTL 64

typedef struct he_msg_data_frag {
  he_msg_hdr_t msg_header;
  uint16_t length;
  uint16_t id;      // fragment id
  uint16_t offset;  // fragment offset and mf flag
} he_msg_data_frag_t;

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

#define HE_MSS_OVERHEAD (HE_IPV4_HEADER_SIZE + HE_TCP_HEADER_SIZE)

#pragma pack()

#endif
