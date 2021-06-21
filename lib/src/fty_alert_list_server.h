/*  =========================================================================
    fty_alert_list_server - Providing information about active alerts

    Copyright (C) 2014 - 2020 Eaton

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License along
    with this program; if not, write to the Free Software Foundation, Inc.,
    51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
    =========================================================================
 */

#pragma once
#include <czmq.h>

///  zactor ready fnction
void fty_alert_list_server_stream(zsock_t* pipe, void* args);
void init_alert(bool verb);
void destroy_alert();
void save_alerts();
void fty_alert_list_server_mailbox(zsock_t* pipe, void* args);
void init_alert_private(const char* path, const char* filename, bool verb);
