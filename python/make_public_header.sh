#!/bin/bash
#
#
# Lightway Core
# Copyright (C) 2021 Express VPN International Ltd.
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
#

cat prod/he.h.header > he.h
python make_header.py ../include/he.h ../src/he/memory.h ../src/he/ssl_ctx.h ../src/he/conn.h ../src/he/flow.h ../src/he/plugin_chain.h ../src/he/client.h >> he.h
cat prod/he.h.footer >> he.h

# format he.h
clang-format -style=file -i he.h

