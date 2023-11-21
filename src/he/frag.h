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

/**
 * @file frag.h
 * @brief Internal header file for fragmentation support
 */

#ifndef FRAG_H
#define FRAG_H

#include <stddef.h>
#include <time.h>

#define MAX_FRAGMENT_ENTRIES 65536

// Forward declarations
typedef struct he_conn he_conn_t;
typedef struct he_fragment_entry_node he_fragment_entry_node_t;

// Information of a fragment
typedef struct he_fragment_entry_node {
  uint16_t begin;
  uint16_t end;
  bool last_frag;
  he_fragment_entry_node_t *next;
} he_fragment_entry_node_t;

// An entry of the fragment table
typedef struct he_fragment_entry {
  uint8_t data[HE_MAX_WIRE_MTU];
  time_t timestamp;
  // Linked list contains infomation of received fragments
  he_fragment_entry_node_t *fragments;
} he_fragment_entry_t;

// Fragment table for reassembling fragments
typedef struct he_fragment_table {
  he_fragment_entry_t **entries;
  size_t num_entries;
} he_fragment_table_t;

/**
 * @brief Fragment a packet and send it over the secured tunnel as multiple messages
 * @param conn A pointer to a valid connection
 * @param packet A pointer to the raw packet to be sent
 * @param length The length of the packet
 * @param frag_size Size of each fragment in bytes
 * @return HE_SUCCESS if the packet is fragmented and sent successfully
 */
he_return_code_t he_internal_frag_and_send_message(he_conn_t *conn, uint8_t *packet,
                                                   uint16_t length, uint16_t frag_size);

/**
 * @brief Reset the given fragment entry
 * @param entry A pointer to a valid fragment entry
 */
void he_fragment_entry_reset(he_fragment_entry_t *entry);

/**
 * @brief Update the given fragment entry with a new fragment.
 * @param entry A pointer to a valid fragment entry
 * @param data A pointer to the fragment data
 * @param offset Offset of the fragment in the original packet in bytes
 * @param length Length of the fragment
 * @param mf More Fragment flag
 * @param assembled (out) Indicate if the packet has been fully reassembled.
 * @return Returns HE_SUCCESS if the fragment entry is updated without error.
 * @note This function may allocates or free memory.
 */
int he_fragment_entry_update(he_fragment_entry_t *entry, uint8_t *data, uint16_t offset,
                             size_t length, uint8_t mf, bool *assembled);

/**
 * @brief Create and initialize a new fragment table.
 * @param num_entries Number of fragment entries can be used in the fragment table. If it's 0, the
 * default value MAX_FRAGMENT_ENTRIES will be used.
 * @return Pointer to a he_fragment_table_t struct.
 * @note This function allocates memory, the caller must call `he_internal_fragment_table_destroy`
 * after use.
 */
he_fragment_table_t *he_internal_fragment_table_create(size_t num_entries);

/**
 * @brief Find entry for the given fragment id.
 * @param tbl Pointer to a valid he_fragment_table_t struct.
 * @param frag_id Fragment Identifier
 * @return Pointer to the fragment entry of the given id. It may return NULL if the function failed
 * to allocate memory for a new entry.
 * @note This function may allocate memory.
 */
he_fragment_entry_t *he_internal_fragment_table_find(he_fragment_table_t *tbl, uint16_t frag_id);

/**
 * @brief Delete entry from the fragment table.
 * @param tbl Pointer to a valid he_fragment_table_t struct.
 * @param frag_id Fragment Identifier
 */
void he_internal_fragment_table_delete(he_fragment_table_t *tbl, uint16_t frag_id);

/**
 * @brief Destroy the given `he_fragment_table` and free up all memory.
 * @param tbl A pointer to a valid he_fragment_table struct.
 */
void he_internal_fragment_table_destroy(he_fragment_table_t *tbl);

#endif  // FRAG_H
