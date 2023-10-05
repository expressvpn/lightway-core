#ifndef HE_TEST_DEFS
#define HE_TEST_DEFS

#define FIXTURE_FATAL_ERROR -1

char *bad_string_too_long = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

char *good_username = "fsdfkjsfrwejkr";
char *good_password = "dsgfdfgghgfhgf";
char *good_hostname = "server1.expressvpn.com";

uint8_t fake_cert[] = {0x10, 0x11, 0x12, 0x13, 0x14};

uint8_t empty_data[1500] = {0};

uint8_t fake_ipv4_packet[] = {0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                              0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                              0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

uint8_t bad_fake_ipv4_packet[] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                                  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                                  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

uint8_t fake_he_packet[] = {0x48, 0x65, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00,
                            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

uint8_t fake_he_packet_session_reject[] = {0x48, 0x65, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00,
                                           0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};

uint16_t calculate_wolf_mtu(uint16_t he_mtu) {
  return he_mtu - HE_PACKET_OVERHEAD + HE_WOLF_MAX_HEADER_SIZE;
}

int call_counter;

he_return_code_t write_cb(he_conn_t *conn, uint8_t *packet, size_t length, void *context) {
  call_counter++;
  return HE_SUCCESS;
}

he_return_code_t write_cb_ex(he_conn_t *conn, uint8_t *packet, size_t length, uint32_t flags,
                             void *context) {
  call_counter++;
  return HE_SUCCESS;
}

he_return_code_t state_cb(he_conn_t *conn, he_conn_state_t new_state, void *context) {
  call_counter++;
  return HE_SUCCESS;
}

he_return_code_t nudge_time_cb(he_conn_t *conn, int timeout, void *context) {
  call_counter++;
  return HE_SUCCESS;
}

he_return_code_t network_config_ipv4_cb(he_conn_t *conn, he_network_config_ipv4_t *config,
                                        void *context) {
  call_counter++;
  return HE_SUCCESS;
}

he_return_code_t server_config_cb(he_conn_t *conn, uint8_t *buffer, size_t length, void *context) {
  call_counter++;
  return HE_SUCCESS;
}

he_return_code_t state_change_cb(he_conn_t *conn, he_conn_state_t new_state, void *context) {
  call_counter++;
  return HE_SUCCESS;
}

he_return_code_t event_cb(he_conn_t *conn, he_conn_event_t event, void *context) {
  call_counter++;
  return HE_SUCCESS;
}

bool auth_cb(he_conn_t *conn, char const *username, char const *password, void *context) {
  call_counter++;
  return HE_SUCCESS;
}

bool auth_buf_cb(he_conn_t *conn, uint8_t auth_type, uint8_t *buffer, uint16_t length,
                 void *context) {
  call_counter++;
  return HE_SUCCESS;
}

he_return_code_t pop_network_config_cb(he_conn_t *conn, he_network_config_ipv4_t *config,
                                       void *context) {
  call_counter++;
  return HE_SUCCESS;
}

he_return_code_t stub_overflow_plugin(he_plugin_chain_t *chain, uint8_t *packet, size_t *length,
                                      size_t capacity, int numCalls) {
  *length = capacity + 1;
  return HE_SUCCESS;
}

#endif  // HE_TEST_DEFS
