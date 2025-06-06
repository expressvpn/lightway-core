#ifndef HE_TEST_DEFS
#define HE_TEST_DEFS

#include <stdint.h>
#include "he.h"
#include "he_internal.h"

#define FIXTURE_FATAL_ERROR -1

extern char *bad_string_too_long;

extern char *good_username;
extern char *good_password;
extern char *good_hostname;

extern uint8_t fake_cert[5];

extern uint8_t empty_data[1500];

extern uint8_t fake_ipv4_packet[24];
extern uint8_t bad_fake_ipv4_packet[24];

extern int call_counter;

extern uint8_t fake_he_packet[16];
extern uint8_t fake_he_packet_session_reject[16];

uint16_t calculate_wolf_mtu(uint16_t he_mtu);
he_return_code_t write_cb(he_conn_t *conn, uint8_t *packet, size_t length, void *context);

he_return_code_t state_cb(he_conn_t *conn, he_conn_state_t new_state, void *context);
he_return_code_t nudge_time_cb(he_conn_t *conn, int timeout, void *context);
he_return_code_t network_config_ipv4_cb(he_conn_t *conn, he_network_config_ipv4_t *config,
                                        void *context);
he_return_code_t server_config_cb(he_conn_t *conn, uint8_t *buffer, size_t length, void *context);
he_return_code_t state_change_cb(he_conn_t *conn, he_conn_state_t new_state, void *context);
he_return_code_t event_cb(he_conn_t *conn, he_conn_event_t event, void *context);
bool auth_cb(he_conn_t *conn, char const *username, char const *password, void *context);
bool auth_buf_cb(he_conn_t *conn, uint8_t auth_type, uint8_t *buffer, uint16_t length,
                 void *context);
he_return_code_t pop_network_config_cb(he_conn_t *conn, he_network_config_ipv4_t *config,
                                       void *context);
he_return_code_t pmtud_time_cb(he_conn_t *conn, int timeout, void *context);
he_return_code_t pmtud_state_change_cb(he_conn_t *conn, he_pmtud_state_t state, void *context);

he_return_code_t stub_overflow_plugin(he_plugin_chain_t *chain, uint8_t *packet, size_t *length,
                                      size_t capacity, int numCalls);
#endif  // HE_TEST_DEFS
