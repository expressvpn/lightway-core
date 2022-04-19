/* *
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

#include "config.h"

bool he_internal_config_is_string_length_okay(const char *string) {
  // This is used for checking strings passed internally to us and should be safe
  size_t len = strnlen(string, HE_CONFIG_TEXT_FIELD_LENGTH + 1);

  // Make sure the text will fit
  if(len > HE_CONFIG_TEXT_FIELD_LENGTH) {
    return false;
  }

  // Drop through
  return true;
}

bool he_internal_config_is_string_too_long(const char *string) {
  return !he_internal_config_is_string_length_okay(string);
}

bool he_internal_config_is_empty_string(const char *string) {
  // Check the first byte isn't a null byte
  if(string[0] == '\0') {
    return true;
  }

  // Drop through to okay
  return false;
}

he_return_code_t he_internal_set_config_string(char *field, const char *value) {
  // Check we didn't get passed any NULL pointers
  if(!field || !value) {
    return HE_ERR_NULL_POINTER;
  }

  // Check the string isn't empty
  if(he_internal_config_is_empty_string(value)) {
    return HE_ERR_EMPTY_STRING;
  }

  // Check it's not too big
  if(he_internal_config_is_string_too_long(value)) {
    return HE_ERR_STRING_TOO_LONG;
  }

  // Copy the string in and ensure it is always terminated
  strncpy(field, value, HE_CONFIG_TEXT_FIELD_LENGTH);
  field[HE_CONFIG_TEXT_FIELD_LENGTH - 1] = '\0';

  return HE_SUCCESS;
}

he_return_code_t he_internal_set_config_int(int *field, int value) {
  // Nothing accepts a negative so far - but we'll tidy this up later if needed
  if(value < 0) {
    // Reject negatives
    return HE_ERR_NEGATIVE_NUMBER;
  }

  // Set the value
  *field = value;

  // Return okay
  return HE_SUCCESS;
}
