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

/*
@header
    alerts_utils - Helper functions
@discuss
@end
 */

#include "alerts_utils.h"
#include <fty_common.h>
#include <fty_log.h>
#include <string>

// encode a c-string S (z85 encoding)
// returns the encoded buffer (c-string)
// returns NULL if error or if input S string is NULL
// Note: returned ptr must be freed by caller

char* s_string_encode(const char* s)
{
    if (!s)
        return NULL;
    size_t s_size = strlen(s);

    // z85 padding, new size is the next bigger or equal multiple of 4
    size_t   padded_size = (s_size + 3) & 0xFFFFFFFC;
    uint8_t* s_padded    = reinterpret_cast<uint8_t*>(zmalloc(padded_size));
    if (!s_padded) {
        log_error("allocation failed");
        return NULL;
    }
    memcpy(s_padded, s, s_size);
    if (padded_size > s_size) // pad with ZEROs
        memset(s_padded + s_size, 0, padded_size - s_size);

    size_t encoded_size = 1 + (5 * padded_size) / 4;
    char*  s_encoded    = reinterpret_cast<char*>(zmalloc(encoded_size));
    if (!s_encoded) {
        free(s_padded);
        log_error("allocation failed");
        return NULL;
    }

    zmq_z85_encode(s_encoded, s_padded, padded_size);
    free(s_padded);

    log_trace("s_string_encode('%s') = '%s'", s, s_encoded);
    return s_encoded;
}

// decode a c-string S (assume z85 encoded, see s_string_encode())
// returns the decoded buffer (c-string)
// returns NULL if error or if input S string is NULL
// Note: returned ptr must be freed by caller

char* s_string_decode(const char* s)
{
    if (!s)
        return NULL;
    size_t s_size = strlen(s);

    size_t decoded_size = 1 + (5 * s_size) / 4;
    char*  s_decoded    = reinterpret_cast<char*>(zmalloc(decoded_size));
    if (!s_decoded) {
        log_error("alloc failed");
        return NULL;
    }

    zmq_z85_decode(reinterpret_cast<uint8_t*>(s_decoded), s);

    // remove end padding chars (if any)
    // std::string str(s_decoded);
    // std::string::size_type pos = str.find_last_not_of ("<padchar>");
    // if (pos != std::string::npos)
    //    s_decoded[pos + 1] = 0; // trim right

    log_trace("s_string_decode('%s') = '%s'", s, s_decoded);
    return s_decoded;
}

int alert_id_comparator(fty_proto_t* alert1, fty_proto_t* alert2)
{
    assert(alert1);
    assert(alert2);
    assert(fty_proto_id(alert1) == FTY_PROTO_ALERT);
    assert(fty_proto_id(alert2) == FTY_PROTO_ALERT);

    if (fty_proto_rule(alert1) == NULL || fty_proto_rule(alert2) == NULL) {
        return 1;
    }

    if (strcasecmp(fty_proto_rule(alert1), fty_proto_rule(alert2)) == 0 &&
        UTF8::utf8eq(fty_proto_name(alert1), fty_proto_name(alert2))) {
        return 0;
    } else {
        return 1;
    }
}

int is_alert_identified(fty_proto_t* alert, const char* rule_name, const char* element_name)
{
    assert(alert);
    assert(rule_name);
    assert(element_name);
    const char* element_src = fty_proto_name(alert);

    if (strcasecmp(fty_proto_rule(alert), rule_name) == 0 && UTF8::utf8eq(element_src, element_name)) {
        return 1;
    }
    return 0;
}

int alert_comparator(fty_proto_t* alert1, fty_proto_t* alert2)
{
    assert(alert1);
    assert(alert2);
    assert(fty_proto_id(alert1) == FTY_PROTO_ALERT);
    assert(fty_proto_id(alert2) == FTY_PROTO_ALERT);

    if (fty_proto_rule(alert1) == NULL || fty_proto_rule(alert2) == NULL) {
        return 1;
    }

    // rule
    if (strcasecmp(fty_proto_rule(alert1), fty_proto_rule(alert2)) != 0)
        return 1;
    // element_src
    if (!UTF8::utf8eq(fty_proto_name(alert1), fty_proto_name(alert2)))
        return 1;
    // state
    if (!streq(fty_proto_state(alert1), fty_proto_state(alert2)))
        return 1;
    // severity
    if (!streq(fty_proto_severity(alert1), fty_proto_severity(alert2)))
        return 1;
    // description
    if (!streq(fty_proto_description(alert1), fty_proto_description(alert2)))
        return 1;
    // time
    if (fty_proto_time(alert1) != fty_proto_time(alert2))
        return 1;
    // action
    // TODO: it might be needed to parse action and compare the individual actions
    //       i.e "EMAIL|SMS" eq "SMS|EMAIL". For now, we don't recognize this and for
    //       now it does not create a problem.
    const char* action1 = fty_proto_action_first(alert1);
    const char* action2 = fty_proto_action_first(alert2);
    while (NULL != action1 && NULL != action2) {
        if (!streq(action1, action2))
            return 1;
        action1 = fty_proto_action_next(alert1);
        action2 = fty_proto_action_next(alert2);
    }
    return 0;
}

int is_acknowledge_state(const char* state)
{
    if (NULL != state && (streq(state, "ACK-WIP") || streq(state, "ACK-IGNORE") || streq(state, "ACK-PAUSE") ||
                             streq(state, "ACK-SILENCE"))) {
        return 1;
    }
    return 0;
}

int is_alert_state(const char* state)
{
    if (NULL != state && (streq(state, "ACTIVE") || streq(state, "RESOLVED") || is_acknowledge_state(state))) {
        return 1;
    }
    return 0;
}

int is_list_request_state(const char* state)
{
    if (NULL != state && (streq(state, "ALL") || streq(state, "ALL-ACTIVE") || is_alert_state(state))) {
        return 1;
    }
    return 0;
}

int is_state_included(const char* list_request_state, const char* alert)
{
    if (!is_list_request_state(list_request_state))
        return 0;
    if (!is_alert_state(alert))
        return 0;

    if (streq(list_request_state, "ALL"))
        return 1;
    if (streq(list_request_state, "ALL-ACTIVE") && !streq(alert, "RESOLVED"))
        return 1;
    return streq(list_request_state, alert);
}

int is_acknowledge_request_state(const char* state)
{
    if (NULL != state && (streq(state, "ACTIVE") || is_acknowledge_state(state))) {
        return 1;
    }
    return 0;
}

// 0 - ok, -1 - error

static int s_alerts_input_checks(zlistx_t* alerts, fty_proto_t* alert)
{
    assert(alerts);
    assert(alert);

    fty_proto_t* cursor = reinterpret_cast<fty_proto_t*>(zlistx_first(alerts));
    while (cursor) {
        if (alert_id_comparator(cursor, alert) == 0) {
            // We already have 'alert' in zlistx 'alerts'
            return -1;
        }
        cursor = reinterpret_cast<fty_proto_t*>(zlistx_next(alerts));
    }

    return 0;
}

// load alert state from disk - legacy
// 0 - success, -1 - error
static int s_alert_load_state_legacy(zlistx_t* alerts, const char* path, const char* filename)
{
    assert(alerts);
    assert(path);
    assert(filename);

    log_debug("statefile: %s/%s", path, filename);
    zfile_t* file = zfile_new(path, filename);
    if (!file) {
        log_error("zfile_new (path = '%s', file = '%s') failed.", path, filename);
        return -1;
    }
    if (!zfile_is_regular(file)) {
        log_error("zfile_is_regular () == false");
        zfile_close(file);
        zfile_destroy(&file);
        return -1;
    }
    if (zfile_input(file) == -1) {
        zfile_close(file);
        zfile_destroy(&file);
        log_error("zfile_input () failed; filename = '%s'", zfile_filename(file, NULL));
        return -1;
    }

    off_t cursize = zfile_cursize(file);
    if (cursize == 0) {
        log_debug("state file '%s' is empty", zfile_filename(file, NULL));
        zfile_close(file);
        zfile_destroy(&file);
        return 0;
    }

    zchunk_t* chunk = zchunk_read(zfile_handle(file), size_t(cursize));
    assert(chunk);
    zframe_t* frame = zframe_new(zchunk_data(chunk), zchunk_size(chunk));
    assert(frame);
    zchunk_destroy(&chunk);

    zfile_close(file);
    zfile_destroy(&file);

    /* Note: Protocol data uses 8-byte sized words, and zmsg_XXcode and file
     * functions deal with platform-dependent unsigned size_t and signed off_t.
     * The off_t is a difficult one to print portably, SO suggests casting to
     * the intmax type and printing that :)
     * https://stackoverflow.com/questions/586928/how-should-i-print-types-like-off-t-and-size-t
     */
    off_t offset = 0;
    log_debug("zfile_cursize == %jd", cursize);

    while (offset < cursize) {
        byte* prefix = zframe_data(frame) + offset;
        byte* data   = zframe_data(frame) + offset + sizeof(uint64_t);
        offset += off_t(uint64_t(*prefix) + sizeof(uint64_t));

        /* Note: the CZMQ_VERSION_MAJOR comparison below actually assumes versions
         * we know and care about - v3.0.2 (our legacy default, already obsoleted
         * by upstream), and v4.x that is in current upstream master. If the API
         * evolves later (incompatibly), these macros will need to be amended.
         */
        zmsg_t* zmessage = NULL;
#if CZMQ_VERSION_MAJOR == 3
        zmessage = zmsg_decode(data, size_t(*prefix));
#else
        {
            zframe_t* fr = zframe_new(data, size_t(*prefix));
            zmessage     = zmsg_decode(fr);
            zframe_destroy(&fr);
        }
#endif
        assert(zmessage);
        fty_proto_t* alert = fty_proto_decode(&zmessage); // zmessage destroyed
        if (!alert) {
            log_warning("Ignoring malformed alert in %s/%s", path, filename);
            continue;
        }
        if (s_alerts_input_checks(alerts, alert) == 0) {
            zlistx_add_end(alerts, alert);
        } else {
            log_warning("Alert id (%s, %s) already read.", fty_proto_rule(alert), fty_proto_name(alert));
        }
        fty_proto_destroy(&alert);
    }

    zframe_destroy(&frame);
    return 0;
}

static int s_alert_load_state_new(zlistx_t* alerts, const char* path, const char* filename)
{
    if (!alerts || !path || !filename) {
        log_error("cannot load state");
        return -1;
    }

    char* state_file = zsys_sprintf("%s/%s", path, filename);
    /* This is unrolled version of zconfig_load() which deallocates file before handing it to config
     * in case of success.
     * I'm not sure whether we can do this always, or whether this is specific to fty-proto state files
     * - that's the reason for unrolling.
     */
    zconfig_t* state = NULL;
    zfile_t*   file  = zfile_new(path, filename);

    if (zfile_input(file) == 0) {
        zchunk_t* chunk = zfile_read(file, size_t(zfile_cursize(file)), 0);
        if (chunk) {
            state = zconfig_chunk_load(chunk);
            zchunk_destroy(&chunk);
            zfile_close(file);
            zfile_destroy(&file);
            file = NULL; //  Config tree now owns file handle
        }
    }
    zfile_destroy(&file);

    if (!state) {
        log_error("cannot load state from file %s", state_file);
        zconfig_destroy(&state);
        zstr_free(&state_file);
        return -1;
    }

    zconfig_t* cursor = zconfig_child(state);
    if (!cursor) {
        log_error("no correct alert in the file %s", state_file);
        zconfig_destroy(&state);
        zstr_free(&state_file);
        return -1;
    }

    log_debug("loading alerts from file %s", state_file);
    while (cursor) {
        fty_proto_t* alert = fty_proto_new_zpl(cursor);
        if (!alert) {
            log_warning("Ignoring malformed alert in %s", state_file);
            cursor = zconfig_next(cursor);
            continue;
        }

        // decode encoded attributes (see alert_save_state())
        {
            char* decoded;
            decoded = s_string_decode(fty_proto_description(alert));
            fty_proto_set_description(alert, "%s", decoded);
            zstr_free(&decoded);
            decoded = s_string_decode(fty_proto_metadata(alert));
            fty_proto_set_metadata(alert, "%s", decoded);
            zstr_free(&decoded);
        }

        fty_proto_print(alert);

        if (s_alerts_input_checks(alerts, alert)) {
            log_warning("Alert id (%s, %s) already read.", fty_proto_rule(alert), fty_proto_name(alert));
        } else {
            zlistx_add_end(alerts, alert);
        }

        cursor = zconfig_next(cursor);
    }

    zconfig_destroy(&state);
    zstr_free(&state_file);
    return 0;
}

int alert_load_state(zlistx_t* alerts, const char* path, const char* filename)
{
    log_info("loading alerts from %s/%s ...", path, filename);

    if (!alerts || !path || !filename) {
        log_error("cannot load state");
        return -1;
    }

    int rv = s_alert_load_state_new(alerts, path, filename);
    if (rv != 0) {
        log_warning("s_alert_load_state_new() failed (rv: %d)", rv);
        log_info("retry using s_alert_load_state_legacy()...");

        rv = s_alert_load_state_legacy(alerts, path, filename);
        if (rv != 0) {
            log_error("s_alert_load_state_legacy() failed (rv: %d)", rv);
        }
    }

    return rv;
}

// save alert state to disk
// 0 - success, -1 - error
int alert_save_state(zlistx_t* alerts, const char* path, const char* filename, bool /*verbose*/)
{
    log_info("saving alerts in %s/%s ...", path, filename);

    if (!alerts || !path || !filename) {
        log_error("cannot save state");
        return -1;
    }

    zconfig_t*   state  = zconfig_new("root", NULL);
    fty_proto_t* cursor = reinterpret_cast<fty_proto_t*>(zlistx_first(alerts));

    while (cursor) {
        fty_proto_print(cursor);

        // encode -complex- attributes of alert,
        // typically/mostly those who are json payloads or non ascii
        // *needed* due to zconfig_save()/zconfig_chunk_load() weakness
        {
            char* encoded;
            encoded = s_string_encode(fty_proto_description(cursor));
            fty_proto_set_description(cursor, "%s", encoded);
            zstr_free(&encoded);
            encoded = s_string_encode(fty_proto_metadata(cursor));
            fty_proto_set_metadata(cursor, "%s", encoded);
            zstr_free(&encoded);
        }

        fty_proto_zpl(cursor, state);
        cursor = reinterpret_cast<fty_proto_t*>(zlistx_next(alerts));
    }

    char* state_file = zsys_sprintf("%s/%s", path, filename);
    int   rv         = zconfig_save(state, state_file);
    if (rv == -1) {
        zstr_free(&state_file);
        zconfig_destroy(&state);
        return rv;
    }

    zstr_free(&state_file);
    zconfig_destroy(&state);
    return 0;
}

fty_proto_t* alert_new(const char* rule, const char* element, const char* state, const char* severity,
    const char* description, uint64_t timestamp, zlist_t** action, int64_t ttl)
{
    fty_proto_t* alert = fty_proto_new(FTY_PROTO_ALERT);
    if (!alert)
        return NULL;
    fty_proto_set_rule(alert, "%s", rule);
    fty_proto_set_name(alert, "%s", element);
    fty_proto_set_state(alert, "%s", state);
    fty_proto_set_severity(alert, "%s", severity);
    fty_proto_set_description(alert, "%s", description);
    fty_proto_set_metadata(alert, "%s", "");
    fty_proto_set_action(alert, action);
    fty_proto_set_time(alert, timestamp);
    fty_proto_aux_insert(alert, "TTL", "%" PRIi64, ttl);
    return alert;
}
