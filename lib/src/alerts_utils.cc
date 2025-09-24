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
    uint8_t* s_padded = reinterpret_cast<uint8_t*>(zmalloc(padded_size));
    if (!s_padded) {
        log_error("allocation failed");
        return NULL;
    }
    memcpy(s_padded, s, s_size);
    if (padded_size > s_size) // pad with ZEROs
        memset(s_padded + s_size, 0, padded_size - s_size);

    size_t encoded_size = 1 + (5 * padded_size) / 4;
    char* s_encoded = reinterpret_cast<char*>(zmalloc(encoded_size));
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

    if (!(fty_proto_rule(alert1) && fty_proto_rule(alert2))) {
        return 1;
    }

    if ((strcasecmp(fty_proto_rule(alert1), fty_proto_rule(alert2)) == 0)
        && UTF8::utf8eq(fty_proto_name(alert1), fty_proto_name(alert2))
    ) {
        return 0; // eq.
    }

    return 1;
}

int is_alert_identified(fty_proto_t* alert, const char* rule_name, const char* element_name)
{
    assert(alert);
    assert(rule_name);
    assert(element_name);

    if ((strcasecmp(fty_proto_rule(alert), rule_name) == 0)
        && UTF8::utf8eq(fty_proto_name(alert), element_name)
    ) {
        return 1;
    }
    return 0;
}

// returns 0 is equal, else 1
int alert_comparator(fty_proto_t* alert1, fty_proto_t* alert2)
{
    assert(alert1);
    assert(alert2);
    assert(fty_proto_id(alert1) == FTY_PROTO_ALERT);
    assert(fty_proto_id(alert2) == FTY_PROTO_ALERT);

    if (!(fty_proto_rule(alert1) && fty_proto_rule(alert2))) {
        return 1;
    }

    // misc properties diff
    if ((strcasecmp(fty_proto_rule(alert1), fty_proto_rule(alert2)) != 0) // rulename
        || !UTF8::utf8eq(fty_proto_name(alert1), fty_proto_name(alert2)) // assetname
        || !streq(fty_proto_state(alert1), fty_proto_state(alert2)) // state
        || !streq(fty_proto_severity(alert1), fty_proto_severity(alert2)) // severity
        || !streq(fty_proto_description(alert1), fty_proto_description(alert2)) // description
        || (fty_proto_time(alert1) != fty_proto_time(alert2)) // timestamp
    ) {
        return 1;
    }

    // action
    // TODO: it might be needed to parse action and compare the individual actions
    //       i.e "EMAIL|SMS" eq "SMS|EMAIL". For now, we don't recognize this and for
    //       now it does not create a problem.

    size_t size1 = fty_proto_action(alert1) ? zlist_size(fty_proto_action(alert1)) : 0;
    size_t size2 = fty_proto_action(alert2) ? zlist_size(fty_proto_action(alert2)) : 0;
    if (size1 != size2) {
        return 1;
    }

    const char* action1 = fty_proto_action_first(alert1);
    const char* action2 = fty_proto_action_first(alert2);
    while (action1 && action2) {
        if (!streq(action1, action2)) {
            return 1;
        }
        action1 = fty_proto_action_next(alert1);
        action2 = fty_proto_action_next(alert2);
    }

    return 0; // equal
}

int is_acknowledge_state(const char* state)
{
    if (!state) { return 0; }

    return streq(state, "ACK-WIP")
           || streq(state, "ACK-IGNORE")
           || streq(state, "ACK-PAUSE")
           || streq(state, "ACK-SILENCE");
}

int is_alert_state(const char* state)
{
    if (!state) { return 0; }

    return streq(state, "ACTIVE")
           || streq(state, "RESOLVED")
           || is_acknowledge_state(state);
}

int is_list_request_state(const char* state)
{
    if (!state) { return 0; }

    return streq(state, "ALL")
           || streq(state, "ALL-ACTIVE")
           || is_alert_state(state);
}

int is_state_included(const char* list_request_state, const char* alert)
{
    if (!is_list_request_state(list_request_state))
        { return 0; }
    if (!is_alert_state(alert))
        { return 0; }

    if (streq(list_request_state, "ALL"))
        { return 1; }
    if (streq(list_request_state, "ALL-ACTIVE") && !streq(alert, "RESOLVED"))
        { return 1; }

    return streq(list_request_state, alert);
}

int is_acknowledge_request_state(const char* state)
{
    if (!state) { return 0; }

    return streq(state, "ACTIVE")
           || is_acknowledge_state(state);
}

// 0 - ok, -1 - error

static int s_alerts_input_checks(zlistx_t* alerts, fty_proto_t* alert)
{
    if (!(alerts && alert)) { return -1; }

    for (void* it = zlistx_first(alerts); it; it = zlistx_next(alerts)) {
        fty_proto_t* cursor = reinterpret_cast<fty_proto_t*>(it);
        if (alert_id_comparator(cursor, alert) == 0) {
            return -1; // 'alert' already in 'alerts'
        }
    }

    return 0;
}

// load alert state from disk - legacy
// 0 - success, -1 - error
static int s_alert_load_state_legacy(zlistx_t* alerts, const char* path, const char* filename)
{
    if (!(alerts && path && filename)) { return -1; }

    log_debug("statefile: %s/%s", path, filename);
    zframe_t* frame = NULL;
    off_t cursize = 0;
    {
        bool fileIsEmpty = false;

        zfile_t* file = zfile_new(path, filename);
        if (!file) {
            log_error("zfile_new (path = '%s', file = '%s') failed.", path, filename);
        }
        else if (!zfile_is_regular(file)) {
            log_error("zfile_is_regular () == false");
        }
        else if (zfile_input(file) != 0) {
            log_error("zfile_input () failed; filename = '%s'", zfile_filename(file, NULL));
        }
        else {
            cursize = zfile_cursize(file);
            if (cursize == 0) {
                log_debug("state file '%s' is empty", zfile_filename(file, NULL));
                fileIsEmpty = true;
            }
            else {
                zchunk_t* chunk = zchunk_read(zfile_handle(file), size_t(cursize));
                frame = chunk ? zframe_new(zchunk_data(chunk), zchunk_size(chunk)) : NULL;
                zchunk_destroy(&chunk);
                if (!frame) {
                    log_error("zframe_new () failed");
                }
            }
        }

        zfile_close(file);
        zfile_destroy(&file);

        if (fileIsEmpty) {
            zframe_destroy(&frame);
            return 0; // ok
        }
    }

    if (!frame) {
        return -1;
    }

    /* Note: Protocol data uses 8-byte sized words, and zmsg_XXcode and file
     * functions deal with platform-dependent unsigned size_t and signed off_t.
     * The off_t is a difficult one to print portably, SO suggests casting to
     * the intmax type and printing that :)
     * https://stackoverflow.com/questions/586928/how-should-i-print-types-like-off-t-and-size-t
     */
    log_debug("zfile_cursize == %jd", cursize);

    off_t offset = 0;
    while (offset < cursize) {
        byte* prefix = zframe_data(frame) + offset;
        byte* data   = zframe_data(frame) + offset + sizeof(uint64_t);
        offset += off_t(uint64_t(*prefix) + sizeof(uint64_t));

        /* Note: the CZMQ_VERSION_MAJOR comparison below actually assumes versions
         * we know and care about - v3.0.2 (our legacy default, already obsoleted
         * by upstream), and v4.x that is in current upstream master. If the API
         * evolves later (incompatibly), these macros will need to be amended.
         */
        zmsg_t* msg = NULL;
#if CZMQ_VERSION_MAJOR == 3
        msg = zmsg_decode(data, size_t(*prefix));
#else
        {
            zframe_t* fr = zframe_new(data, size_t(*prefix));
            msg = zmsg_decode(fr);
            zframe_destroy(&fr);
        }
#endif

        fty_proto_t* alert = msg ? fty_proto_decode(&msg) : NULL;
        zmsg_destroy(&msg); // secure

        if (!alert) {
            log_warning("Ignoring malformed alert in %s/%s", path, filename);
        }
        else if (s_alerts_input_checks(alerts, alert) != 0) {
            log_warning("Alert id (%s, %s) already read.", fty_proto_rule(alert), fty_proto_name(alert));
        }
        else {
            // ASSUME alert dup. in alerts list (see zlistx_set_duplicator(alerts))
            zlistx_add_end(alerts, alert);
        }
        fty_proto_destroy(&alert);
    }

    zframe_destroy(&frame);
    return 0;
}

static int s_alert_load_state_new(zlistx_t* alerts, const char* path, const char* filename)
{
    if (!(alerts && path && filename)) {
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
    {
        zfile_t* file = zfile_new(path, filename);
        if (zfile_input(file) == 0) {
            zchunk_t* chunk = zfile_read(file, size_t(zfile_cursize(file)), 0);
            if (chunk) {
                state = zconfig_chunk_load(chunk); // zonfig now owns file handle
                zchunk_destroy(&chunk);
            }
            zfile_close(file);
        }
        zfile_destroy(&file);
    }

    if (!state) {
        log_error("cannot load state from file %s", state_file);
        zstr_free(&state_file);
        return -1;
    }

    zconfig_t* cursor = zconfig_child(state);
    if (!cursor) {
        log_error("no alert in file %s", state_file);
        zconfig_destroy(&state);
        zstr_free(&state_file);
        return -1;
    }

    log_debug("loading alerts from file %s", state_file);

    for (; cursor; cursor = zconfig_next(cursor)) {
        fty_proto_t* alert = fty_proto_new_zpl(cursor);

        if (alert) {
            // decode encoded attributes (see alert_save_state())
            char* decoded = s_string_decode(fty_proto_description(alert));
            fty_proto_set_description(alert, "%s", decoded);
            zstr_free(&decoded);
            decoded = s_string_decode(fty_proto_metadata(alert));
            fty_proto_set_metadata(alert, "%s", decoded);
            zstr_free(&decoded);

            fty_proto_print(alert);
        }

        if (!alert) {
            log_warning("Ignoring malformed alert in %s", state_file);
        }
        else if (s_alerts_input_checks(alerts, alert) != 0) {
            log_warning("Alert id (%s, %s) already read.", fty_proto_rule(alert), fty_proto_name(alert));
        }
        else {
            // ASSUME alert dup. in alerts list (see zlistx_set_duplicator(alerts))
            zlistx_add_end(alerts, alert);
        }
        fty_proto_destroy(&alert);
    }

    zconfig_destroy(&state);
    zstr_free(&state_file);

    return 0;
}

// read alert state from disk
// 0 - success, -1 - error
int alert_load_state(zlistx_t* alerts, const char* path, const char* filename)
{
    if (!(alerts && path && filename)) {
        log_error("cannot load state");
        return -1;
    }

    log_info("loading alerts from %s/%s ...", path, filename);

    int r = s_alert_load_state_new(alerts, path, filename);
    if (r != 0) {
        log_warning("s_alert_load_state_new() failed (r: %d)", r);
        log_info("retry using s_alert_load_state_legacy()...");

        r = s_alert_load_state_legacy(alerts, path, filename);
        if (r != 0) {
            log_error("s_alert_load_state_legacy() failed (r: %d)", r);
        }
    }

    return (r == 0) ? 0 : -1;
}

// save alert state to disk
// 0 - success, -1 - error
int alert_save_state(zlistx_t* alerts, const char* path, const char* filename, bool /*verbose*/)
{
    if (!(alerts && path  && filename)) {
        log_error("cannot save state");
        return -1;
    }

    log_info("saving alerts in %s/%s ...", path, filename);

    zconfig_t* state = zconfig_new("root", NULL);

    for (void* it = zlistx_first(alerts); it; it = zlistx_next(alerts)) {

        fty_proto_t* cursor = reinterpret_cast<fty_proto_t*>(it);
        fty_proto_print(cursor);

        // encode -complex- attributes of alert,
        // typically/mostly those who are json payloads or non ascii
        // *needed* due to zconfig_save()/zconfig_chunk_load() weakness
        {
            char* encoded = s_string_encode(fty_proto_description(cursor));
            fty_proto_set_description(cursor, "%s", encoded);
            zstr_free(&encoded);
            encoded = s_string_encode(fty_proto_metadata(cursor));
            fty_proto_set_metadata(cursor, "%s", encoded);
            zstr_free(&encoded);
        }

        fty_proto_zpl(cursor, state);
    }

    char* state_file = zsys_sprintf("%s/%s", path, filename);
    int r = zconfig_save(state, state_file);
    zstr_free(&state_file);

    zconfig_destroy(&state);

    return (r == 0) ? 0 : -1;
}
