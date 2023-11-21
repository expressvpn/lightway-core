/**
 * Lightway Core
 * Copyright (C) 2023 Express VPN International Ltd.
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

#include <assert.h>

#include "he.h"
#include "he_internal.h"
#include "frag.h"
#include "conn_internal.h"
#include "memory.h"

he_return_code_t he_internal_frag_and_send_message(he_conn_t *conn, uint8_t *packet,
                                                   uint16_t length, uint16_t frag_size) {
  if(!conn || !packet) {
    return HE_ERR_NULL_POINTER;
  }

  // Round the frag_size to the multiple of 8 bytes
  if(frag_size % 8 != 0) {
    frag_size = (frag_size / 8) * 8;
  }

  if(length <= frag_size) {
    // This should never happen, but we check it anyway.
    return HE_ERR_FAILED;
  }

  // Fragment identifier
  uint16_t frag_id = conn->frag_next_id++;

  uint16_t offset = 0;
  while(length > 0) {
    uint8_t bytes[HE_MAX_WIRE_MTU] = {0};

    // Allocate some space for the data message
    he_msg_data_frag_t *hdr = (he_msg_data_frag_t *)bytes;

    // Set message type
    hdr->msg_header.msgid = HE_MSGID_DATA_WITH_FRAG;

    // Set data length
    uint16_t frag_len = (length > frag_size) ? frag_size : length;
    hdr->length = htons(frag_len);

    // Set fragment id
    hdr->id = htons(frag_id);

    // Set fragment offset and mf flag
    uint8_t mf = (length > frag_size) ? 1 : 0;
    uint16_t off = (offset >> 3) | ((uint16_t)mf << 13);
    hdr->offset = htons(off);

    // Copy packet fragment to the buffer
    memcpy(bytes + sizeof(he_msg_data_frag_t), packet + offset, frag_len);

    // Send the message
    he_return_code_t ret =
        he_internal_send_message(conn, (uint8_t *)bytes, frag_len + sizeof(he_msg_data_frag_t));
    if(ret != HE_SUCCESS) {
      return ret;
    }

    length -= frag_len;
    offset += frag_len;
  };

  return HE_SUCCESS;
}

void he_fragment_entry_reset(he_fragment_entry_t *entry) {
  assert(entry);

  if(entry) {
    while(entry->fragments != NULL) {
      he_fragment_entry_node_t *next = entry->fragments->next;
      he_free(entry->fragments);
      entry->fragments = next;
    }
    entry->timestamp = 0;
    memset(entry->data, 0, sizeof(entry->data));
  }
}

he_return_code_t he_fragment_entry_update(he_fragment_entry_t *entry, uint8_t *data,
                                          uint16_t offset, size_t length, uint8_t mf,
                                          bool *assembled) {
  // Sanity checks
  if(entry == NULL || data == NULL || assembled == NULL) {
    return HE_ERR_NULL_POINTER;
  }
  if(offset + length > sizeof(entry->data)) {
    return HE_ERR_PACKET_TOO_LARGE;
  }

  // We haven't received any fragment yet
  if(entry->fragments == NULL) {
    he_fragment_entry_node_t *node = he_calloc(1, sizeof(he_fragment_entry_node_t));
    node->begin = offset;
    node->end = offset + length;
    node->last_frag = (mf == 0);
    entry->fragments = node;
    memcpy(entry->data + offset, data, length);
    return HE_SUCCESS;
  }

  // Add new fragment to the list
  he_fragment_entry_node_t *prev = NULL;
  he_fragment_entry_node_t *curr = entry->fragments;
  while(curr) {
    if(offset == curr->end) {
      // Expand current node and continue check all remaining nodes
      curr->end = offset + length;
      curr->last_frag = (mf == 0);
      curr = curr->next;
      continue;
    }
    if(offset + length == curr->begin) {
      // Prepend to current node
      curr->begin = offset;
      break;
    }
    if(offset > curr->end) {
      // There's a gap, try next node or insert a new node here
      if(curr->next) {
        // Try combine the two existing nodes first
        if(curr->next->begin == curr->end) {
          he_fragment_entry_node_t *next = curr->next;
          curr->end = next->begin;
          curr->next = next->next;
          curr->last_frag = next->last_frag;
          he_free(next);
        }
        prev = curr;
        curr = curr->next;
        continue;
      } else {
        he_fragment_entry_node_t *node = he_calloc(1, sizeof(he_fragment_entry_node_t));
        node->begin = offset;
        node->end = offset + length;
        node->last_frag = (mf == 0);
        curr->next = node;
        break;
      }
    }
    if(offset + length < curr->begin) {
      // There's a gap, insert a new node between previous and current nodes
      he_fragment_entry_node_t *node = he_calloc(1, sizeof(he_fragment_entry_node_t));
      node->begin = offset;
      node->end = offset + length;
      node->last_frag = (mf == 0);
      node->next = curr;
      if(prev == NULL) {
        entry->fragments = node;
      } else {
        prev->next = node;
      }
      break;
    }
    // The new fragment overlaps with existing fragments. Drop the packet and return error.
    return HE_ERR_BAD_FRAGMENT;
  }

  // Copy the packet data to the buffer
  memcpy(entry->data + offset, data, length);

  // Check if we can reassemble the full packet
  *assembled = (entry->fragments->last_frag && entry->fragments->begin == 0);

  return HE_SUCCESS;
}

he_fragment_table_t *he_internal_fragment_table_create(size_t num_entries) {
  he_fragment_table_t *tbl = he_calloc(1, sizeof(he_fragment_table_t));
  if(tbl == NULL) {
    return NULL;
  }
  if(num_entries == 0) {
    num_entries = MAX_FRAGMENT_ENTRIES;
  }
  tbl->entries = (he_fragment_entry_t **)he_calloc(num_entries, sizeof(he_fragment_entry_t *));
  if(tbl->entries == NULL) {
    // Not enough memory
    he_free(tbl);
    return NULL;
  }
  tbl->num_entries = num_entries;
  return tbl;
}

he_fragment_entry_t *he_internal_fragment_table_find(he_fragment_table_t *tbl, uint16_t frag_id) {
  if(!tbl) {
    return NULL;
  }
  uint16_t idx = frag_id % tbl->num_entries;
  he_fragment_entry_t *entry = tbl->entries[idx];
  if(entry == NULL) {
    // Fragment entry not found, create a new one
    entry = he_calloc(1, sizeof(he_fragment_entry_t));
    if(entry != NULL) {
      entry->timestamp = time(NULL);
      tbl->entries[idx] = entry;
    }
  }
  return entry;
}

void he_internal_fragment_table_delete(he_fragment_table_t *tbl, uint16_t frag_id) {
  if(!tbl) {
    return;
  }
  uint16_t idx = frag_id % tbl->num_entries;
  he_fragment_entry_t *entry = tbl->entries[idx];
  if(entry) {
    he_fragment_entry_reset(entry);
    he_free(entry);
    tbl->entries[idx] = NULL;
  }
}

void he_internal_fragment_table_destroy(he_fragment_table_t *tbl) {
  if(!tbl) {
    return;
  }
  // Free up all cached fragments
  for(size_t i = 0; i < tbl->num_entries; i++) {
    he_fragment_entry_t *entry = tbl->entries[i];
    if(entry) {
      he_fragment_entry_reset(entry);
      he_free(entry);
      tbl->entries[i] = NULL;
    }
  }
  he_free(tbl->entries);
  he_free(tbl);
}
