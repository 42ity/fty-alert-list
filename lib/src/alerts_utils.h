/*  =========================================================================
    alerts_utils - Helper functions

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

#ifndef ALERTS_UTILS_H_INCLUDED
#define ALERTS_UTILS_H_INCLUDED

#ifdef __cplusplus
extern "C" {
#endif

#define ACTION_EMAIL  "EMAIL"
#define ACTION_SMS    "SMS"
    
// load alert state from disk
// 0 - success, -1 - error
FTY_ALERT_LIST_EXPORT int
    alert_load_state (zlistx_t *alerts, const char *path, const char *filename);

// save alert state to disk
// 0 - success, -1 - error
FTY_ALERT_LIST_EXPORT int
    alert_save_state (zlistx_t *alerts, const char *path, const char *filename, bool verbose);

// create new alert
// returns new alert on success, NULL on failure
FTY_ALERT_LIST_EXPORT fty_proto_t*
    alert_new (const char *rule,
               const char *element,
               const char *state,
               const char *severity,
               const char *description,
               uint64_t timestamp,
               zlist_t **action,
               int64_t ttl);

// czmq_comparator of two alert's identifiers; alert is identified by pair (name, element)
// 0 - same, 1 - different
FTY_ALERT_LIST_EXPORT int
    alert_id_comparator (fty_proto_t *alert1, fty_proto_t *alert2);

// Is given 'alert' identified by ('rule_name', 'element_name')
// 1 - Yes, 0 - No
FTY_ALERT_LIST_EXPORT int
    is_alert_identified (fty_proto_t *alert, const char *rule_name, const char *element_name);

// czmq_comparator of two alerts
// 0 - same, 1 - different
FTY_ALERT_LIST_EXPORT int
    alert_comparator (fty_proto_t *alert1, fty_proto_t *alert2);

// does 'state' represent valid acknowledge state?
// 1 - valid acknowledge state, 0 - NOT valid acknowledge state
FTY_ALERT_LIST_EXPORT int
    is_acknowledge_state (const char *state);

// does 'state' represent valid alert state?
// 1 - valid alert state, 0 - NOT valid alert state
FTY_ALERT_LIST_EXPORT int
    is_alert_state (const char *state);

// does 'state' represent valid rfc-alerts-list protocol request state?
// 1 - valid request state, 0 - NOT valid request state
FTY_ALERT_LIST_EXPORT int
    is_list_request_state (const char *state);

// Is alert state included in or equal to rfc-alerts-list request state?
// E.g. RESOLVED is not included or equal in ALL-ACTIVE, whereas ACK-IGNORE is.
// 1 - Yes, 0 - No
FTY_ALERT_LIST_EXPORT int
    is_state_included (const char *list_request_state, const char *alert);

// does 'state' represent valid rfc-alerts-acknowledge state?
// 1 - valid request state, 0 - NOT valid request state
FTY_ALERT_LIST_EXPORT int
    is_acknowledge_request_state (const char *state);

//  Self test of this class
FTY_ALERT_LIST_EXPORT void
    alerts_utils_test (bool verbose);

//  @end

#ifdef __cplusplus
}
#endif

#endif
