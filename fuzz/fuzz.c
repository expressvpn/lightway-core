#include "flow.h"
#include "he_internal.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  he_conn_t *conn = calloc(1, sizeof(he_conn_t));
  conn->protocol_version.major_version = 1;
  conn->protocol_version.minor_version = 1;
  conn->outside_mtu = HE_MAX_WIRE_MTU;

  conn->read_packet.has_packet = true;
  conn->read_packet.packet_size = size;
  memcpy(conn->read_packet.packet, data, size);

  he_internal_flow_process_message(conn);

  free(conn);
  return 0;
}
