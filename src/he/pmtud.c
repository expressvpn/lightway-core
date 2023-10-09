#include "he.h"
#include "conn.h"
#include "conn_internal.h"
#include "he_internal.h"

#include "pmtud.h"

he_return_code_t he_internal_pmtud_send_probe(he_conn_t *conn, uint16_t probe_mtu) {
  if(!conn) {
    return HE_ERR_NULL_POINTER;
  }

  if(conn->state != HE_STATE_ONLINE || conn->pmtud_state == HE_PMTUD_STATE_DISABLED) {
    return HE_ERR_INVALID_CONN_STATE;
  }

  if(probe_mtu < MIN_PLPMTU || probe_mtu > MAX_PLPMTU) {
    return HE_ERR_INVALID_MTU_SIZE;
  }

  // Craft a PING message
  uint8_t buf[HE_MAX_WIRE_MTU] = {0};
  he_msg_ping_t *ping = (he_msg_ping_t *)buf;
  ping->msg_header.msgid = HE_MSGID_PING;

  // Set identifier
  uint16_t id = conn->ping_next_id++;
  ping->id = htons(id);

  // Set payload for keepalive
  uint16_t payload_size = probe_mtu + sizeof(he_msg_data_t) - sizeof(he_msg_ping_t);
  ping->length = payload_size;

  // TODO: fill payload with random data

  // Send it
  he_return_code_t res = he_internal_send_message(conn, buf, sizeof(he_msg_ping_t) + payload_size);
  if(res == HE_SUCCESS) {
    conn->ping_pending_id = id;
  }
  return res;
}

void he_internal_pmtud_pong_received(he_conn_t *conn) {
}

void he_internal_pmtud_update(he_conn_t *conn) {
  if(conn == NULL || conn->pmtud_state == HE_PMTUD_STATE_DISABLED) {
    // Invalid state, do nothing
    return;
  }
  switch(conn->pmtud_state) {
    case HE_PMTUD_STATE_BASE:
      break;
    case HE_PMTUD_STATE_SEARCHING:
      break;
    case HE_PMTUD_STATE_SEARCH_COMPLETE:
      break;
    case HE_PMTUD_STATE_ERROR:
      break;
    default:
      break;
  }
}
