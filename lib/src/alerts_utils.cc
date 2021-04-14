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

#include <string>
#include <fty_common_utf8.h>
#include "fty_alert_list_classes.h"

// encode a c-string S (z85 encoding)
// returns the encoded buffer (c-string)
// returns NULL if error or if input S string is NULL
// Note: returned ptr must be freed by caller

static char *
s_string_encode(const char *s)
{
    if (!s) return NULL;
    size_t s_size = strlen (s);

    // z85 padding, new size is the next bigger or equal multiple of 4
    size_t padded_size = (s_size + 3) & 0xFFFFFFFC;
    uint8_t *s_padded = (uint8_t *) zmalloc (padded_size);
    if (!s_padded)
        { log_error("allocation failed"); return NULL; }
    memcpy (s_padded, s, s_size);
    if (padded_size > s_size) // pad with ZEROs
        memset (s_padded + s_size, 0, padded_size - s_size);

    size_t encoded_size = 1 + (5 * padded_size) / 4;
    char *s_encoded = (char *) zmalloc (encoded_size);
    if (!s_encoded)
        { free(s_padded); log_error("allocation failed"); return NULL; }

    zmq_z85_encode (s_encoded, s_padded, padded_size);
    free(s_padded);

    log_trace ("s_string_encode('%s') = '%s'", s, s_encoded);
    return s_encoded;
}

// decode a c-string S (assume z85 encoded, see s_string_encode())
// returns the decoded buffer (c-string)
// returns NULL if error or if input S string is NULL
// Note: returned ptr must be freed by caller

static char *
s_string_decode(const char *s)
{
    if (!s) return NULL;
    size_t s_size = strlen (s);

    size_t decoded_size = 1 + (5 * s_size) / 4;
    char *s_decoded = (char *) zmalloc (decoded_size);
    if (!s_decoded)
        { log_error("alloc failed"); return NULL; }

    zmq_z85_decode ((uint8_t*)s_decoded, s);

    // remove end padding chars (if any)
    //std::string str(s_decoded);
    //std::string::size_type pos = str.find_last_not_of ("<padchar>");
    //if (pos != std::string::npos)
    //    s_decoded[pos + 1] = 0; // trim right

    log_trace ("s_string_decode('%s') = '%s'", s, s_decoded);
    return s_decoded;
}

int
alert_id_comparator(fty_proto_t *alert1, fty_proto_t *alert2) {
    assert(alert1);
    assert(alert2);
    assert(fty_proto_id(alert1) == FTY_PROTO_ALERT);
    assert(fty_proto_id(alert2) == FTY_PROTO_ALERT);

    if (fty_proto_rule(alert1) == NULL ||
            fty_proto_rule(alert2) == NULL) {
        return 1;
    }

    if (strcasecmp(fty_proto_rule(alert1), fty_proto_rule(alert2)) == 0 &&
            UTF8::utf8eq(fty_proto_name(alert1), fty_proto_name(alert2))) {
        return 0;
    } else {
        return 1;
    }
}

int
is_alert_identified(fty_proto_t *alert, const char *rule_name, const char *element_name) {
    assert(alert);
    assert(rule_name);
    assert(element_name);
    const char *element_src = fty_proto_name(alert);

    if (strcasecmp(fty_proto_rule(alert), rule_name) == 0 &&
            UTF8::utf8eq(element_src, element_name)) {
        return 1;
    }
    return 0;
}

int
alert_comparator(fty_proto_t *alert1, fty_proto_t *alert2) {
    assert(alert1);
    assert(alert2);
    assert(fty_proto_id(alert1) == FTY_PROTO_ALERT);
    assert(fty_proto_id(alert2) == FTY_PROTO_ALERT);

    if (fty_proto_rule(alert1) == NULL ||
            fty_proto_rule(alert2) == NULL) {
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
    const char *action1 = fty_proto_action_first(alert1);
    const char *action2 = fty_proto_action_first(alert2);
    while (NULL != action1 && NULL != action2) {
        if (!streq(action1, action2))
            return 1;
        action1 = fty_proto_action_next(alert1);
        action2 = fty_proto_action_next(alert2);
    }
    return 0;
}

int
is_acknowledge_state(const char *state) {
    if (NULL != state && (streq(state, "ACK-WIP") ||
            streq(state, "ACK-IGNORE") ||
            streq(state, "ACK-PAUSE") ||
            streq(state, "ACK-SILENCE"))) {
        return 1;
    }
    return 0;
}

int
is_alert_state(const char *state) {
    if (NULL != state && (streq(state, "ACTIVE") ||
            streq(state, "RESOLVED") ||
            is_acknowledge_state(state))) {
        return 1;
    }
    return 0;
}

int
is_list_request_state(const char *state) {
    if (NULL != state && (streq(state, "ALL") ||
            streq(state, "ALL-ACTIVE") ||
            is_alert_state(state))) {
        return 1;
    }
    return 0;
}

int
is_state_included(const char *list_request_state, const char *alert) {
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

int
is_acknowledge_request_state(const char *state) {
    if (NULL != state && (streq(state, "ACTIVE") ||
            is_acknowledge_state(state))) {
        return 1;
    }
    return 0;
}

// 0 - ok, -1 - error

static int
s_alerts_input_checks(zlistx_t *alerts, fty_proto_t *alert) {
    assert(alerts);
    assert(alert);

    fty_proto_t *cursor = (fty_proto_t *) zlistx_first(alerts);
    while (cursor) {
        if (alert_id_comparator(cursor, alert) == 0) {
            // We already have 'alert' in zlistx 'alerts'
            return -1;
        }
        cursor = (fty_proto_t *) zlistx_next(alerts);
    }

    return 0;
}

// load alert state from disk - legacy
// 0 - success, -1 - error
static int
s_alert_load_state_legacy (zlistx_t *alerts, const char *path, const char *filename)
{
    assert(alerts);
    assert(path);
    assert(filename);

    log_debug("statefile: %s/%s", path, filename);
    zfile_t *file = zfile_new(path, filename);
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

    zchunk_t *chunk = zchunk_read(zfile_handle(file), cursize);
    assert(chunk);
    zframe_t *frame = zframe_new(zchunk_data(chunk), zchunk_size(chunk));
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
    log_debug("zfile_cursize == %jd", (intmax_t) cursize);

    while (offset < cursize) {
        byte *prefix = zframe_data(frame) + offset;
        byte *data = zframe_data(frame) + offset + sizeof (uint64_t);
        offset += (uint64_t) * prefix + sizeof (uint64_t);

        /* Note: the CZMQ_VERSION_MAJOR comparison below actually assumes versions
         * we know and care about - v3.0.2 (our legacy default, already obsoleted
         * by upstream), and v4.x that is in current upstream master. If the API
         * evolves later (incompatibly), these macros will need to be amended.
         */
        zmsg_t *zmessage = NULL;
#if CZMQ_VERSION_MAJOR == 3
        zmessage = zmsg_decode(data, (size_t) * prefix);
#else
        {
            zframe_t *fr = zframe_new(data, (size_t) * prefix);
            zmessage = zmsg_decode(fr);
            zframe_destroy(&fr);
        }
#endif
        assert (zmessage);
        fty_proto_t *alert = fty_proto_decode (&zmessage); // zmessage destroyed
        if (!alert) {
            log_warning ("Ignoring malformed alert in %s/%s", path, filename);
            continue;
        }
        if (s_alerts_input_checks (alerts, alert) == 0) {
            zlistx_add_end (alerts, alert);
        }
        else {
            log_warning (
                    "Alert id (%s, %s) already read.",
                    fty_proto_rule(alert),
                    fty_proto_name(alert));
        }
        fty_proto_destroy(&alert);
    }

    zframe_destroy(&frame);
    return 0;
}

static int
s_alert_load_state_new (zlistx_t *alerts, const char *path, const char *filename) {
    if (!alerts || !path || !filename) {
        log_error ("cannot load state");
        return -1;
    }

    char *state_file = zsys_sprintf ("%s/%s", path, filename);
    /* This is unrolled version of zconfig_load() which deallocates file before handing it to config
     * in case of success.
     * I'm not sure whether we can do this always, or whether this is specific to fty-proto state files
     * - that's the reason for unrolling.
     */
    zconfig_t *state = NULL;
    zfile_t *file = zfile_new (path, filename);

    if (zfile_input (file) == 0) {
        zchunk_t *chunk = zfile_read (file, zfile_cursize (file), 0);
        if (chunk) {
            state = zconfig_chunk_load (chunk);
            zchunk_destroy (&chunk);
            zfile_close (file);
            zfile_destroy (&file);
            file = NULL;        //  Config tree now owns file handle
        }
    }
    zfile_destroy (&file);

    if (!state) {
        log_error ("cannot load state from file %s", state_file);
        zconfig_destroy (&state);
        zstr_free (&state_file);
        return -1;
    }

    zconfig_t *cursor = zconfig_child (state);
    if (!cursor) {
        log_error ("no correct alert in the file %s", state_file);
        zconfig_destroy (&state);
        zstr_free (&state_file);
        return -1;
    }

    log_debug ("loading alerts from file %s", state_file);
    while (cursor) {
        fty_proto_t *alert = fty_proto_new_zpl (cursor);
        if (!alert) {
            log_warning ("Ignoring malformed alert in %s", state_file);
            cursor = zconfig_next (cursor);
            continue;
        }

        // decode encoded attributes (see alert_save_state())
        {
            char* decoded;
            decoded = s_string_decode (fty_proto_description (alert));
            fty_proto_set_description (alert, "%s", decoded);
            zstr_free (&decoded);
            decoded = s_string_decode (fty_proto_metadata (alert));
            fty_proto_set_metadata (alert, "%s", decoded);
            zstr_free (&decoded);
        }

        fty_proto_print (alert);

        if (s_alerts_input_checks (alerts, alert)) {
            log_warning (
                    "Alert id (%s, %s) already read.",
                    fty_proto_rule(alert),
                    fty_proto_name(alert));
        }
        else {
            zlistx_add_end (alerts, alert);
        }

        cursor = zconfig_next (cursor);
    }

    zconfig_destroy (&state);
    zstr_free (&state_file);
    return 0;
}

int
alert_load_state (zlistx_t *alerts, const char *path, const char *filename)
{
    log_info("loading alerts from %s/%s ...", path, filename);

    if (!alerts || !path || !filename) {
        log_error ("cannot load state");
        return -1;
    }

    int rv = s_alert_load_state_new (alerts, path, filename);
    if (rv != 0) {
        log_warning("s_alert_load_state_new() failed (rv: %d)", rv);
        log_info("retry using s_alert_load_state_legacy()...");

        rv = s_alert_load_state_legacy (alerts, path, filename);
        if (rv != 0) {
            log_error("s_alert_load_state_legacy() failed (rv: %d)", rv);
        }
    }

    return rv;
}

// save alert state to disk
// 0 - success, -1 - error
int
alert_save_state(zlistx_t *alerts, const char *path, const char *filename, bool verbose)
{
    log_info("saving alerts in %s/%s ...", path, filename);

    if (!alerts || !path || !filename) {
        log_error ("cannot save state");
        return -1;
    }

    zconfig_t *state = zconfig_new ("root", NULL);
    fty_proto_t *cursor = (fty_proto_t *) zlistx_first (alerts);

    while (cursor) {
        fty_proto_print (cursor);

        // encode -complex- attributes of alert,
        // typically/mostly those who are json payloads or non ascii
        // *needed* due to zconfig_save()/zconfig_chunk_load() weakness
        {
            char *encoded;
            encoded = s_string_encode(fty_proto_description (cursor));
            fty_proto_set_description (cursor, "%s", encoded);
            zstr_free(&encoded);
            encoded = s_string_encode(fty_proto_metadata (cursor));
            fty_proto_set_metadata (cursor, "%s", encoded);
            zstr_free(&encoded);
        }

        fty_proto_zpl (cursor, state);
        cursor = (fty_proto_t *) zlistx_next (alerts);
    }

    char *state_file = zsys_sprintf ("%s/%s", path, filename);
    int rv = zconfig_save (state, state_file);
    if (rv == -1) {
        zstr_free (&state_file);
        zconfig_destroy (&state);
        return rv;
    }

    zstr_free (&state_file);
    zconfig_destroy (&state);
    return 0;
}

fty_proto_t*
alert_new(const char *rule,
        const char *element,
        const char *state,
        const char *severity,
        const char *description,
        uint64_t timestamp,
        zlist_t **action,
        int64_t ttl) {
    fty_proto_t *alert = fty_proto_new(FTY_PROTO_ALERT);
    if (!alert)
        return NULL;
    fty_proto_set_rule(alert, "%s", rule);
    fty_proto_set_name(alert, "%s", element);
    fty_proto_set_state(alert, "%s", state);
    fty_proto_set_severity(alert, "%s", severity);
    fty_proto_set_description(alert, "%s", description);
    fty_proto_set_metadata(alert, "%s" , "");
    fty_proto_set_action(alert, action);
    fty_proto_set_time(alert, timestamp);
    fty_proto_aux_insert(alert, "TTL", "%" PRIi64, ttl);
    return alert;
}

//  --------------------------------------------------------------------------
//  Self test of this class

void
alerts_utils_test(bool verbose) {

    //  @selftest

    log_debug(" * alerts_utils: ");

    //  **************************************
    //  *****   s_string_encode/decode   *****
    //  **************************************

    {
        const char* test[] = {
            "",
            "0",
            "01",
            "012",
            "0123",
            "01234",
            "012345",
            "0123456",
            "01234567",
            "012345678",
            "0123456789",

            "UTF-8: HЯɅȤ",
            "UTF-8: ሰማይ አይታረስ ንጉሥ አይከሰስ።",
            "UTF-8: ⡍⠜⠇⠑⠹ ⠺⠁⠎ ⠙⠑⠁⠙⠒ ⠞⠕ ⠃",

            "hello world!",
            "hello world!    ",
            "{ hello world! }",
            "{ \"hello\": \"world!\" }",

            "{"
            "  \"name\": \"John\","
            "  \"age\": 30,"
            "  \"cars\": ["
            "    { \"name\": \"Ford\", \"models\": [ \"Fiesta\", \"Focus\", \"Mustang\" ] },"
            "    { \"name\": \"BMW\",  \"models\": [ \"320\", \"X3\", \"X5\" ] },"
            "    { \"name\": \"Fiat\", \"models\": [ \"500\", \"Panda\" ] }"
            "  ]"
            "}",

            NULL
        };

        assert(s_string_encode(NULL) == NULL);
        assert(s_string_decode(NULL) == NULL);

        for (int i = 0; test[i]; i++) {
            const char* message = test[i];

            char* encoded = s_string_encode(message);
            assert(encoded);

            char* decoded = s_string_decode(encoded);
            assert(decoded);
            assert(streq(message, decoded));

            zstr_free(&encoded);
            zstr_free(&decoded);
        }

        log_debug("s_string_encode/decode: OK");
    }

    //  ************************************
    //  *****   is_acknowledge_state   *****
    //  ************************************

    assert(is_acknowledge_state("ACK-WIP") == 1);
    assert(is_acknowledge_state("ACK-IGNORE") == 1);
    assert(is_acknowledge_state("ACK-PAUSE") == 1);
    assert(is_acknowledge_state("ACK-SILENCE") == 1);

    assert(is_acknowledge_state("ACTIVE") == 0);
    assert(is_acknowledge_state("active") == 0);
    assert(is_acknowledge_state("RESOLVED") == 0);
    assert(is_acknowledge_state("RESOLVE") == 0);
    assert(is_acknowledge_state("resolve") == 0);
    assert(is_acknowledge_state("ack-wip") == 0);
    assert(is_acknowledge_state("ALL") == 0);
    assert(is_acknowledge_state("ALL-ACTIVE") == 0);
    assert(is_acknowledge_state("all") == 0);
    assert(is_acknowledge_state("all-active") == 0);
    assert(is_acknowledge_state("") == 0);
    assert(is_acknowledge_state(NULL) == 0);
    assert(is_acknowledge_state("ACK-xyfd") == 0);
    assert(is_acknowledge_state("aCK-WIP") == 0);
    assert(is_acknowledge_state("ACKWIP") == 0);
    assert(is_acknowledge_state("somethign") == 0);
    log_debug("is_acknowledge_state: OK");


    //  ******************************
    //  *****   is_alert_state   *****
    //  ******************************

    assert(is_alert_state("ACTIVE") == 1);
    assert(is_alert_state("ACK-WIP") == 1);
    assert(is_alert_state("ACK-IGNORE") == 1);
    assert(is_alert_state("ACK-PAUSE") == 1);
    assert(is_alert_state("ACK-SILENCE") == 1);
    assert(is_alert_state("RESOLVED") == 1);

    assert(is_alert_state("ALL") == 0);
    assert(is_alert_state("ALL-ACTIVE") == 0);
    assert(is_alert_state("") == 0);
    assert(is_alert_state(NULL) == 0);
    assert(is_alert_state("all") == 0);
    assert(is_alert_state("active") == 0);
    assert(is_alert_state("ACK") == 0);
    assert(is_alert_state("ack-wip") == 0);
    assert(is_alert_state("resolved") == 0);
    log_debug("is_alert_state: OK");

    //  *************************************
    //  *****   is_list_request_state   *****
    //  *************************************

    assert(is_list_request_state("ACTIVE") == 1);
    assert(is_list_request_state("ACK-WIP") == 1);
    assert(is_list_request_state("ACK-IGNORE") == 1);
    assert(is_list_request_state("ACK-PAUSE") == 1);
    assert(is_list_request_state("ACK-SILENCE") == 1);
    assert(is_list_request_state("RESOLVED") == 1);
    assert(is_list_request_state("ALL") == 1);
    assert(is_list_request_state("ALL-ACTIVE") == 1);

    assert(is_list_request_state("All") == 0);
    assert(is_list_request_state("all") == 0);
    assert(is_list_request_state("Active") == 0);
    assert(is_list_request_state("active") == 0);
    assert(is_list_request_state("ack-wip") == 0);
    assert(is_list_request_state("resolved") == 0);
    assert(is_list_request_state("") == 0);
    assert(is_list_request_state(NULL) == 0);
    assert(is_list_request_state("sdfsd") == 0);
    log_debug("is_list_request_state: OK");


    //  *********************************
    //  *****   is_state_included   *****
    //  *********************************

    assert(is_state_included("ALL", "ACTIVE") == 1);
    assert(is_state_included("ALL", "ACK-WIP") == 1);
    assert(is_state_included("ALL", "ACK-IGNORE") == 1);
    assert(is_state_included("ALL", "ACK-PAUSE") == 1);
    assert(is_state_included("ALL", "ACK-SILENCE") == 1);
    assert(is_state_included("ALL", "RESOLVED") == 1);

    assert(is_state_included("ALL-ACTIVE", "ACTIVE") == 1);
    assert(is_state_included("ALL-ACTIVE", "ACK-WIP") == 1);
    assert(is_state_included("ALL-ACTIVE", "ACK-IGNORE") == 1);
    assert(is_state_included("ALL-ACTIVE", "ACK-PAUSE") == 1);
    assert(is_state_included("ALL-ACTIVE", "ACK-SILENCE") == 1);
    assert(is_state_included("ALL-ACTIVE", "RESOLVED") == 0);

    assert(is_state_included("ACTIVE", "ACTIVE") == 1);
    assert(is_state_included("ACK-WIP", "ACK-WIP") == 1);
    assert(is_state_included("ACK-IGNORE", "ACK-IGNORE") == 1);
    assert(is_state_included("ACK-SILENCE", "ACK-SILENCE") == 1);
    assert(is_state_included("RESOLVED", "RESOLVED") == 1);

    assert(is_state_included("ACTIVE", "ALL") == 0);
    assert(is_state_included("ACTIVE", "RESOLVED") == 0);
    assert(is_state_included("ACTIVE", "ALL-ACTIVE") == 0);
    assert(is_state_included("ALL", "ALL-ACTIVE") == 0);
    assert(is_state_included("ALL-ACTIVE", "ALL-ACTIVE") == 0);
    assert(is_state_included("ALL", "ALL") == 0);
    assert(is_state_included("ACK-WIP", "ACTIVE") == 0);
    assert(is_state_included("ACK-IGNORE", "ACK-WIP") == 0);
    log_debug("is_state_included: OK");

    //  *********************************************
    //  *****   is_acknowledge_request_state    *****
    //  *********************************************

    assert(is_acknowledge_request_state("ACTIVE") == 1);
    assert(is_acknowledge_request_state("ACK-WIP") == 1);
    assert(is_acknowledge_request_state("ACK-IGNORE") == 1);
    assert(is_acknowledge_request_state("ACTIVE") == 1);
    assert(is_acknowledge_request_state("ACTIVE") == 1);

    assert(is_acknowledge_request_state("ALL") == 0);
    assert(is_acknowledge_request_state("RESOLVED") == 0);
    assert(is_acknowledge_request_state("ALL-ACTIVE") == 0);
    assert(is_acknowledge_request_state("active") == 0);
    assert(is_acknowledge_request_state("") == 0);
    assert(is_acknowledge_request_state(NULL) == 0);
    log_debug("is_acknowledge_request_state: OK");

    //  **************************
    //  *****   alert_new    *****
    //  **************************
    {
        zlist_t *actions = zlist_new();
        zlist_autofree(actions);
        zlist_append(actions, (void *) ACTION_EMAIL);
        zlist_append(actions, (void *) ACTION_SMS);
        fty_proto_t *alert = alert_new("Threshold", "ups", "ACTIVE", "high", "description", 1, &actions, 0);
        assert(streq(fty_proto_rule(alert), "Threshold"));
        assert(streq(fty_proto_name(alert), "ups"));
        assert(streq(fty_proto_state(alert), "ACTIVE"));
        assert(streq(fty_proto_severity(alert), "high"));
        assert(streq(fty_proto_description(alert), "description"));
        assert(streq(fty_proto_action_first(alert), "EMAIL"));
        assert(streq(fty_proto_action_next(alert), "SMS"));
        assert(NULL == fty_proto_action_next(alert));
        assert(fty_proto_time(alert) == (uint64_t) 1);
        fty_proto_destroy(&alert);
        if (NULL != actions)
            zlist_destroy(&actions);

        actions = zlist_new();
        zlist_autofree(actions);
        zlist_append(actions, (void *) ACTION_SMS);
        zlist_append(actions, (void *) "Holub");
        zlist_append(actions, (void *) "Morse code");
        alert = alert_new("Simple@Rule@Because", "karolkove zelezo", "ACTIVE", "high Severity", "Holiday \nInn hotel 243", 10101795, &actions, 0);
        assert(streq(fty_proto_rule(alert), "Simple@Rule@Because"));
        assert(streq(fty_proto_name(alert), "karolkove zelezo"));
        assert(streq(fty_proto_state(alert), "ACTIVE"));
        assert(streq(fty_proto_severity(alert), "high Severity"));
        assert(streq(fty_proto_description(alert), "Holiday \nInn hotel 243"));
        assert(streq(fty_proto_action_first(alert), "SMS"));
        assert(streq(fty_proto_action_next(alert), "Holub"));
        assert(streq(fty_proto_action_next(alert), "Morse code"));
        assert(NULL == fty_proto_action_next(alert));
        assert(fty_proto_time(alert) == (uint64_t) 10101795);
        fty_proto_destroy(&alert);
        if (NULL != actions)
            zlist_destroy(&actions);
    }

    //  ************************************
    //  *****   alert_id_comparator    *****
    //  ************************************


    // test case 1a:
    //  alerts are completely the same
    {
        zlist_t *actions1 = zlist_new();
        zlist_autofree(actions1);
        zlist_append(actions1, (void *) ACTION_EMAIL);
        fty_proto_t *alert1 = alert_new("temperature.average@DC-Roztoky", "ups-9", "ACTIVE", "some description", "low", 10, &actions1, 0);
        assert(alert1);
        zlist_t *actions2 = zlist_new();
        zlist_autofree(actions2);
        zlist_append(actions2, (void *) ACTION_EMAIL);
        fty_proto_t *alert2 = alert_new("temperature.average@DC-Roztoky", "ups-9", "ACTIVE", "some description", "low", 10, &actions2, 0);
        assert(alert2);

        assert(alert_id_comparator(alert1, alert2) == 0);

        if (NULL != actions1)
            zlist_destroy(&actions1);
        if (NULL != actions2)
            zlist_destroy(&actions2);
        fty_proto_destroy(&alert1);
        fty_proto_destroy(&alert2);
    }

    // test case 1b:
    //  alerts have the same identifier,
    //  different meta-data which represents real world use case of one alert
    //  at two different times
    {
        zlist_t *actions1 = zlist_new();
        zlist_autofree(actions1);
        zlist_append(actions1, (void *) ACTION_EMAIL);
        fty_proto_t *alert1 = alert_new("temperature.average@DC-Roztoky", "ups-9", "ACTIVE", "some description", "low", 10, &actions1, 0);
        assert(alert1);
        zlist_t *actions2 = zlist_new();
        zlist_autofree(actions2);
        zlist_append(actions2, (void *) ACTION_SMS);
        fty_proto_t *alert2 = alert_new("temperature.average@DC-Roztoky", "ups-9", "ACK-IGNORE", "some description", "high", 10, &actions2, 0);
        assert(alert2);

        assert(alert_id_comparator(alert1, alert2) == 0);

        if (NULL != actions1)
            zlist_destroy(&actions1);
        if (NULL != actions2)
            zlist_destroy(&actions2);
        fty_proto_destroy(&alert1);
        fty_proto_destroy(&alert2);
    }

    // test case 1c:
    //  alerts have the same identifier,
    //  different as well as missing meta-data
    {
        zlist_t *actions1 = zlist_new();
        zlist_autofree(actions1);
        zlist_append(actions1, (void *) ACTION_EMAIL);
        fty_proto_t *alert1 = alert_new("temperature.average@DC-Roztoky", "ups-9", "ACK-WIP", NULL, "high", 10, &actions1, 0);
        assert(alert1);
        zlist_t *actions2 = zlist_new();
        zlist_autofree(actions2);
        fty_proto_t *alert2 = alert_new("temperature.average@DC-Roztoky", "ups-9", "ACTIVE", "some description", "low", 20, &actions2, 0);
        assert(alert2);

        assert(alert_id_comparator(alert1, alert2) == 0);

        if (NULL != actions1)
            zlist_destroy(&actions1);
        if (NULL != actions2)
            zlist_destroy(&actions2);
        fty_proto_destroy(&alert1);
        fty_proto_destroy(&alert2);
    }

    // test case 1d:
    //  alerts have the same identifier - rule name has different case
    //  different as well as missing meta-data
    {
        zlist_t *actions1 = zlist_new();
        zlist_autofree(actions1);
        zlist_append(actions1, (void *) ACTION_EMAIL);
        fty_proto_t *alert1 = alert_new("temperature.average@DC-Roztoky", "ups-9", "ACK-WIP", NULL, "high", 10, &actions1, 0);
        assert(alert1);
        zlist_t *actions2 = zlist_new();
        zlist_autofree(actions2);
        fty_proto_t *alert2 = alert_new("Temperature.Average@dC-roztoky", "ups-9", "ACTIVE", "some description", "low", 20, &actions2, 0);
        assert(alert2);

        assert(alert_id_comparator(alert1, alert2) == 0);

        if (NULL != actions1)
            zlist_destroy(&actions1);
        if (NULL != actions2)
            zlist_destroy(&actions2);
        fty_proto_destroy(&alert1);
        fty_proto_destroy(&alert2);
    }

    // test case 2a:
    // alerts don't have the same identifier - different rule

    {
        zlist_t *actions1 = zlist_new();
        zlist_autofree(actions1);
        fty_proto_t *alert1 = alert_new("temperature.average@DC-Lab", "ups-9", "ACK-WIP", NULL, "high", 10, &actions1, 0);
        assert(alert1);
        zlist_t *actions2 = zlist_new();
        zlist_autofree(actions2);
        fty_proto_t *alert2 = alert_new("temperature.average@DC-Roztoky", "ups-9", "ACTIVE", NULL, "low", 20, &actions2, 0);
        assert(alert2);

        assert(alert_id_comparator(alert1, alert2) == 1);

        if (NULL != actions1)
            zlist_destroy(&actions1);
        if (NULL != actions2)
            zlist_destroy(&actions2);
        fty_proto_destroy(&alert1);
        fty_proto_destroy(&alert2);
    }

    // test case 2b:
    // alerts don't have the same identifier - different element_src

    {
        zlist_t *actions1 = zlist_new();
        zlist_autofree(actions1);
        fty_proto_t *alert1 = alert_new("temperature.average@DC-Roztoky", "epdu", "ACK-WIP", "xcuy;v weohuif", "high", 10, &actions1, 0);
        assert(alert1);
        zlist_t *actions2 = zlist_new();
        zlist_autofree(actions2);
        fty_proto_t *alert2 = alert_new("temperature.average@DC-Roztoky", "ups-9", "ACTIVE", NULL, "low", 20, &actions2, 0);
        assert(alert2);

        assert(alert_id_comparator(alert1, alert2) == 1);

        if (NULL != actions1)
            zlist_destroy(&actions1);
        if (NULL != actions2)
            zlist_destroy(&actions2);
        fty_proto_destroy(&alert1);
        fty_proto_destroy(&alert2);
    }

    // test case 2c:
    // alerts do have the same identifier - case of element_src is ignored now

    {
        zlist_t *actions1 = zlist_new();
        zlist_autofree(actions1);
        fty_proto_t *alert1 = alert_new("temperature.average@DC-Roztoky", "Ups-9", "ACK-WIP", NULL, "high", 10, &actions1, 0);
        assert(alert1);
        zlist_t *actions2 = zlist_new();
        zlist_autofree(actions2);
        fty_proto_t *alert2 = alert_new("temperature.average@DC-Roztoky", "ups-9", "ACTIVE", NULL, "low", 20, &actions2, 0);
        assert(alert2);

        assert(alert_id_comparator(alert1, alert2) == 0);

        if (NULL != actions1)
            zlist_destroy(&actions1);
        if (NULL != actions2)
            zlist_destroy(&actions2);
        fty_proto_destroy(&alert1);
        fty_proto_destroy(&alert2);
    }


    // test case 3:
    // alerts don't have the same identifier -different element_src, rule
    {
        zlist_t *actions1 = zlist_new();
        zlist_autofree(actions1);
        fty_proto_t *alert1 = alert_new("temperature.average@DC-Roztoky", "epdu", "ACK-WIP", NULL, "high", 10, &actions1, 0);
        assert(alert1);
        zlist_t *actions2 = zlist_new();
        zlist_autofree(actions2);
        fty_proto_t *alert2 = alert_new("temperature.humidity@DC-Roztoky", "ups-9", "ACTIVE", NULL, "low", 20, &actions2, 0);
        assert(alert2);

        assert(alert_id_comparator(alert1, alert2) == 1);

        if (NULL != actions1)
            zlist_destroy(&actions1);
        if (NULL != actions2)
            zlist_destroy(&actions2);
        fty_proto_destroy(&alert1);
        fty_proto_destroy(&alert2);
    }

    // unicode
    {
        zlist_t *actions1 = zlist_new();
        zlist_autofree(actions1);
        zlist_append(actions1, (void *) ACTION_EMAIL);
        fty_proto_t *alert1 = alert_new("realpower.DeFault", "ŽlUťOUčKý kůň супер", "ACTIVE", "some description", "low", 10, &actions1, 0);
        assert(alert1);
        zlist_t *actions2 = zlist_new();
        zlist_autofree(actions2);
        zlist_append(actions2, (void *) ACTION_EMAIL);
        zlist_append(actions2, (void *) ACTION_SMS);
        fty_proto_t *alert2 = alert_new("realpower.default", "\u017dlu\u0165ou\u010dk\xc3\xbd K\u016f\xc5\x88 супер", "ACK-SILENCE",
                "some description 2", "high", 100, &actions2, 0);
        assert(alert2);

        assert(alert_id_comparator(alert1, alert2) == 0);

        if (NULL != actions1)
            zlist_destroy(&actions1);
        if (NULL != actions2)
            zlist_destroy(&actions2);
        fty_proto_destroy(&alert1);
        fty_proto_destroy(&alert2);
    }

    {
        zlist_t *actions1 = zlist_new();
        zlist_autofree(actions1);
        zlist_append(actions1, (void *) ACTION_EMAIL);
        fty_proto_t *alert1 = alert_new("realpower.DeFault", "Žluťoučký kůň супер ", "ACTIVE", "some description", "low", 10, &actions1, 0);
        assert(alert1);
        zlist_t *actions2 = zlist_new();
        zlist_autofree(actions2);
        zlist_append(actions2, (void *) ACTION_EMAIL);
        zlist_append(actions2, (void *) ACTION_SMS);
        fty_proto_t *alert2 = alert_new("realpower.default", "Žluťoučký kůň супер", "ACK-SILENCE",
                "some description 2", "high", 100, &actions2, 0);
        assert(alert2);

        assert(alert_id_comparator(alert1, alert2) == 1);

        if (NULL != actions1)
            zlist_destroy(&actions1);
        if (NULL != actions2)
            zlist_destroy(&actions2);
        fty_proto_destroy(&alert1);
        fty_proto_destroy(&alert2);
    }

    //  *************************************
    //  *****   is_alert_identified     *****
    //  *************************************
    {
        zlist_t *actions = zlist_new();
        zlist_autofree(actions);
        zlist_append(actions, (void *) ACTION_EMAIL);
        fty_proto_t *alert = alert_new("temperature.average@DC-Roztoky", "ups-9", "ACTIVE", "some description", "low", 10, &actions, 0);
        assert(alert);
        assert(is_alert_identified(alert, "temperature.average@DC-Roztoky", "ups-9") == 1);
        assert(is_alert_identified(alert, "Temperature.Average@dC-Roztoky", "ups-9") == 1);
        assert(is_alert_identified(alert, "humidity@DC-Roztoky", "ups-9") == 0);
        assert(is_alert_identified(alert, "", "ups-9") == 0);
        assert(is_alert_identified(alert, "temperature.average@DC-Roztoky", "") == 0);
        assert(is_alert_identified(alert, "temperature.average@DC-Roztoky", "epDU") == 0);
        assert(is_alert_identified(alert, "Temperature.Average@dC-Roztoky", "epDU") == 0);
        fty_proto_destroy(&alert);
        if (NULL != actions)
            zlist_destroy(&actions);
    }

    {
        zlist_t *actions = zlist_new();
        zlist_autofree(actions);
        zlist_append(actions, (void *) ACTION_EMAIL);
        fty_proto_t *alert = alert_new("temperature.average@DC-Roztoky", "ta2€супер14159", "ACTIVE", "some description", "low", 10, &actions, 0);
        assert(alert);
        assert(is_alert_identified(alert, "temperature.average@DC-Roztoky", "ups-9") == 0);
        assert(is_alert_identified(alert, "temperature.average@dc-roztoky", "ta2\u20ac\u0441\u0443\u043f\u0435\u044014159") == 1);
        fty_proto_destroy(&alert);
        if (NULL != actions)
            zlist_destroy(&actions);
    }

    {
        zlist_t *actions = zlist_new();
        zlist_autofree(actions);
        zlist_append(actions, (void *) ACTION_EMAIL);
        fty_proto_t *alert = alert_new("temperature.average@DC-Roztoky", "ŽlUťOUčKý kůň", "ACTIVE", "some description", "low", 10, &actions, 0);
        assert(alert);
        assert(is_alert_identified(alert, "temperature.average@dc-roztoky", "ŽlUťOUčKý kůň") == 1);
        assert(is_alert_identified(alert, "temperature.averageDC-Roztoky", "ŽlUťOUčKý kůň") == 0);
        fty_proto_destroy(&alert);
        if (NULL != actions)
            zlist_destroy(&actions);
    }

    //  *********************************
    //  *****   alert_comparator    *****
    //  *********************************

    // test case 1a:
    //  alerts are completelly the same
    {
        zlist_t *actions1 = zlist_new();
        zlist_autofree(actions1);
        zlist_append(actions1, (void *) ACTION_SMS);
        fty_proto_t *alert1 = alert_new("temperature.average@DC-Roztoky", "ups-9", "ACTIVE", "low", "some description", 10, &actions1, 0);
        assert(alert1);
        zlist_t *actions2 = zlist_new();
        zlist_autofree(actions2);
        zlist_append(actions2, (void *) ACTION_SMS);
        fty_proto_t *alert2 = alert_new("temperature.average@DC-Roztoky", "ups-9", "ACTIVE", "low", "some description", 10, &actions2, 0);
        assert(alert2);

        assert(alert_comparator(alert1, alert2) == 0);

        if (NULL != actions1)
            zlist_destroy(&actions1);
        if (NULL != actions2)
            zlist_destroy(&actions2);
        fty_proto_destroy(&alert1);
        fty_proto_destroy(&alert2);
    }

    // test case 1b:
    //  alerts are same - rule different case
    {
        zlist_t *actions1 = zlist_new();
        zlist_autofree(actions1);
        zlist_append(actions1, (void *) ACTION_SMS);
        fty_proto_t *alert1 = alert_new("temperature.average@DC-Roztoky", "ups-9", "ACTIVE", "low", "some description", 10, &actions1, 0);
        assert(alert1);
        zlist_t *actions2 = zlist_new();
        zlist_autofree(actions2);
        zlist_append(actions2, (void *) ACTION_SMS);
        fty_proto_t *alert2 = alert_new("temperature.average@dC-Roztoky", "ups-9", "ACTIVE", "low", "some description", 10, &actions2, 0);
        assert(alert2);

        assert(alert_comparator(alert1, alert2) == 0);

        if (NULL != actions1)
            zlist_destroy(&actions1);
        if (NULL != actions2)
            zlist_destroy(&actions2);
        fty_proto_destroy(&alert1);
        fty_proto_destroy(&alert2);
    }

    // test case 2:
    //  other fields are case sensitive

    //  severity is case sensitive
    {
        zlist_t *actions1 = zlist_new();
        zlist_autofree(actions1);
        zlist_append(actions1, (void *) ACTION_SMS);
        fty_proto_t *alert1 = alert_new("temperature.average@DC-Roztoky", "ups-9", "ACTIVE", "low", "some description", 10, &actions1, 0);
        assert(alert1);
        zlist_t *actions2 = zlist_new();
        zlist_autofree(actions2);
        zlist_append(actions2, (void *) ACTION_SMS);
        fty_proto_t *alert2 = alert_new("temperature.average@DC-Roztoky", "ups-9", "ACTIVE", "lOw", "some description", 10, &actions2, 0);
        assert(alert2);

        assert(alert_comparator(alert1, alert2) == 1);

        if (NULL != actions1)
            zlist_destroy(&actions1);
        if (NULL != actions2)
            zlist_destroy(&actions2);
        fty_proto_destroy(&alert1);
        fty_proto_destroy(&alert2);
    }

    //  state is case sensitive
    {
        zlist_t *actions1 = zlist_new();
        zlist_autofree(actions1);
        zlist_append(actions1, (void *) ACTION_SMS);
        fty_proto_t *alert1 = alert_new("temperature.average@DC-Roztoky", "ups-9", "aCTIVE", "low", "some description", 10, &actions1, 0);
        assert(alert1);
        zlist_t *actions2 = zlist_new();
        zlist_autofree(actions2);
        zlist_append(actions2, (void *) ACTION_SMS);
        fty_proto_t *alert2 = alert_new("temperature.average@DC-Roztoky", "ups-9", "ACTIVE", "low", "some description", 10, &actions2, 0);
        assert(alert2);

        assert(alert_comparator(alert1, alert2) == 1);

        if (NULL != actions1)
            zlist_destroy(&actions1);
        if (NULL != actions2)
            zlist_destroy(&actions2);
        fty_proto_destroy(&alert1);
        fty_proto_destroy(&alert2);
    }

    //  element_src is case insensitive
    {
        zlist_t *actions1 = zlist_new();
        zlist_autofree(actions1);
        zlist_append(actions1, (void *) ACTION_SMS);
        fty_proto_t *alert1 = alert_new("temperature.average@DC-Roztoky", "ups-9", "ACTIVE", "low", "some description", 10, &actions1, 0);
        assert(alert1);
        zlist_t *actions2 = zlist_new();
        zlist_autofree(actions2);
        zlist_append(actions2, (void *) ACTION_SMS);
        fty_proto_t *alert2 = alert_new("temperature.average@DC-Roztoky", "Ups-9", "ACTIVE", "low", "some description", 10, &actions2, 0);
        assert(alert2);

        assert(alert_comparator(alert1, alert2) == 0);

        if (NULL != actions1)
            zlist_destroy(&actions1);
        if (NULL != actions2)
            zlist_destroy(&actions2);
        fty_proto_destroy(&alert1);
        fty_proto_destroy(&alert2);
    }

    //  description is case sensitive
    {
        zlist_t *actions1 = zlist_new();
        zlist_autofree(actions1);
        zlist_append(actions1, (void *) ACTION_SMS);
        fty_proto_t *alert1 = alert_new("temperature.average@DC-Roztoky", "ups-9", "ACTIVE", "low", "some description", 10, &actions1, 0);
        assert(alert1);
        zlist_t *actions2 = zlist_new();
        zlist_autofree(actions2);
        zlist_append(actions2, (void *) ACTION_SMS);
        fty_proto_t *alert2 = alert_new("temperature.average@DC-Roztoky", "ups-9", "ACTIVE", "low", "some Description", 10, &actions2, 0);
        assert(alert2);

        assert(alert_comparator(alert1, alert2) == 1);

        if (NULL != actions1)
            zlist_destroy(&actions1);
        if (NULL != actions2)
            zlist_destroy(&actions2);
        fty_proto_destroy(&alert1);
        fty_proto_destroy(&alert2);
    }

    //  time is different
    {
        zlist_t *actions1 = zlist_new();
        zlist_autofree(actions1);
        zlist_append(actions1, (void *) ACTION_SMS);
        fty_proto_t *alert1 = alert_new("temperature.average@DC-Roztoky", "ups-9", "ACTIVE", "low", "some description", 10, &actions1, 0);
        assert(alert1);
        zlist_t *actions2 = zlist_new();
        zlist_autofree(actions2);
        zlist_append(actions2, (void *) ACTION_SMS);
        fty_proto_t *alert2 = alert_new("temperature.average@DC-Roztoky", "ups-9", "ACTIVE", "low", "some description", 35, &actions2, 0);
        assert(alert2);

        assert(alert_comparator(alert1, alert2) == 1);

        if (NULL != actions1)
            zlist_destroy(&actions1);
        if (NULL != actions2)
            zlist_destroy(&actions2);
        fty_proto_destroy(&alert1);
        fty_proto_destroy(&alert2);
    }

    // test case 2g:
    //  action is case sensitive
    {
        zlist_t *actions1 = zlist_new();
        zlist_autofree(actions1);
        zlist_append(actions1, (void *) ACTION_SMS);
        fty_proto_t *alert1 = alert_new("temperature.average@DC-Roztoky", "ups-9", "ACTIVE", "low", "some description", 10, &actions1, 0);
        assert(alert1);
        zlist_t *actions2 = zlist_new();
        zlist_autofree(actions2);
        zlist_append(actions2, (void *) "sms");
        fty_proto_t *alert2 = alert_new("temperature.average@DC-Roztoky", "ups-9", "ACTIVE", "low", "some description", 10, &actions2, 0);
        assert(alert2);

        assert(alert_comparator(alert1, alert2) == 1);

        if (NULL != actions1)
            zlist_destroy(&actions1);
        if (NULL != actions2)
            zlist_destroy(&actions2);
        fty_proto_destroy(&alert1);
        fty_proto_destroy(&alert2);
    }

    // test case 3a:
    //  fields missing in both messages are equal
    {
        zlist_t *actions1 = zlist_new();
        zlist_autofree(actions1);
        fty_proto_t *alert1 = alert_new("temperature.average@DC-Roztoky", NULL, "ACTIVE", NULL, NULL, 10, &actions1, 0);
        assert(alert1);
        zlist_t *actions2 = zlist_new();
        zlist_autofree(actions2);
        fty_proto_t *alert2 = alert_new("temperature.average@DC-Roztoky", NULL, "ACTIVE", NULL, NULL, 10, &actions2, 0);
        assert(alert2);

        assert(alert_comparator(alert1, alert2) == 0);

        if (NULL != actions1)
            zlist_destroy(&actions1);
        if (NULL != actions2)
            zlist_destroy(&actions2);
        fty_proto_destroy(&alert1);
        fty_proto_destroy(&alert2);
    }

    // test case 3b:
    //  fields missing in either of messages is not equal
    {
        zlist_t *actions1 = zlist_new();
        zlist_autofree(actions1);
        zlist_append(actions1, (void *) ACTION_SMS);
        fty_proto_t *alert1 = alert_new("temperature.average@DC-Roztoky", "ups-9", "ACTIVE", "low", NULL, 10, &actions1, 0);
        assert(alert1);
        zlist_t *actions2 = zlist_new();
        zlist_autofree(actions2);
        zlist_append(actions2, (void *) ACTION_SMS);
        fty_proto_t *alert2 = alert_new("temperature.average@DC-Roztoky", "ups-9", "ACTIVE", "low", "some description", 10, &actions2, 0);
        assert(alert2);

        assert(alert_comparator(alert1, alert2) == 1);

        if (NULL != actions1)
            zlist_destroy(&actions1);
        if (NULL != actions2)
            zlist_destroy(&actions2);
        fty_proto_destroy(&alert1);
        fty_proto_destroy(&alert2);
    }

    {
        zlist_t *actions1 = zlist_new();
        zlist_autofree(actions1);
        zlist_append(actions1, (void *) ACTION_SMS);
        fty_proto_t *alert1 = alert_new("temperature.average@DC-Roztoky", "ups-9", "ACTIVE", "low", "some description", 10, &actions1, 0);
        assert(alert1);
        zlist_t *actions2 = zlist_new();
        zlist_autofree(actions2);
        zlist_append(actions2, (void *) ACTION_SMS);
        fty_proto_t *alert2 = alert_new(NULL, "ups-9", "ACTIVE", "low", "some description", 10, &actions2, 0);
        assert(alert2);

        assert(alert_comparator(alert1, alert2) == 1);

        if (NULL != actions1)
            zlist_destroy(&actions1);
        if (NULL != actions2)
            zlist_destroy(&actions2);
        fty_proto_destroy(&alert1);
        fty_proto_destroy(&alert2);
    }

    {
        zlist_t *actions1 = zlist_new();
        zlist_autofree(actions1);
        zlist_append(actions1, (void *) ACTION_SMS);
        fty_proto_t *alert1 = alert_new("temperature.average@DC-Roztoky", NULL, "ACTIVE", "low", "some description", 10, &actions1, 0);
        assert(alert1);
        zlist_t *actions2 = zlist_new();
        zlist_autofree(actions2);
        zlist_append(actions2, (void *) ACTION_SMS);
        fty_proto_t *alert2 = alert_new("temperature.average@DC-Roztoky", "ups-9", "ACTIVE", "low", "some description", 10, &actions2, 0);
        assert(alert2);

        assert(alert_comparator(alert1, alert2) == 1);

        if (NULL != actions1)
            zlist_destroy(&actions1);
        if (NULL != actions2)
            zlist_destroy(&actions2);
        fty_proto_destroy(&alert1);
        fty_proto_destroy(&alert2);
    }

    // test case 4:
    //  different fields
    {
        zlist_t *actions1 = zlist_new();
        zlist_autofree(actions1);
        zlist_append(actions1, (void *) ACTION_SMS);
        fty_proto_t *alert1 = alert_new("temperature.average@DC-Roztoky", "ups-9", "ACTIVE", "low", "some description", 10, &actions1, 0);
        assert(alert1);
        zlist_t *actions2 = zlist_new();
        zlist_autofree(actions2);
        zlist_append(actions2, (void *) ACTION_SMS);
        fty_proto_t *alert2 = alert_new("temperature.humidity@DC-Roztoky", "ups-9", "ACTIVE", "low", "some description", 10, &actions2, 0);
        assert(alert2);

        assert(alert_comparator(alert1, alert2) == 1);

        if (NULL != actions1)
            zlist_destroy(&actions1);
        if (NULL != actions2)
            zlist_destroy(&actions2);
        fty_proto_destroy(&alert1);
        fty_proto_destroy(&alert2);
    }

    {
        zlist_t *actions1 = zlist_new();
        zlist_autofree(actions1);
        zlist_append(actions1, (void *) ACTION_SMS);
        fty_proto_t *alert1 = alert_new("temperature.average@DC-Roztoky", "ups-9", "ACTIVE", "low", "some description", 10, &actions1, 0);
        assert(alert1);
        zlist_t *actions2 = zlist_new();
        zlist_autofree(actions2);
        zlist_append(actions2, (void *) ACTION_SMS);
        fty_proto_t *alert2 = alert_new("temperature.average@DC-Roztoky", "epdu", "ACTIVE", "low", "some description", 10, &actions2, 0);
        assert(alert2);

        assert(alert_comparator(alert1, alert2) == 1);

        if (NULL != actions1)
            zlist_destroy(&actions1);
        if (NULL != actions2)
            zlist_destroy(&actions2);
        fty_proto_destroy(&alert1);
        fty_proto_destroy(&alert2);
    }

    {
        zlist_t *actions1 = zlist_new();
        zlist_autofree(actions1);
        zlist_append(actions1, (void *) ACTION_SMS);
        fty_proto_t *alert1 = alert_new("temperature.average@DC-Roztoky", "epdu", "ACTIVE", "hugh", "some description", 10, &actions1, 0);
        assert(alert1);
        zlist_t *actions2 = zlist_new();
        zlist_autofree(actions2);
        zlist_append(actions2, (void *) ACTION_SMS);
        fty_proto_t *alert2 = alert_new("temperature.average@DC-Roztoky", "epdu", "ACTIVE", "low", "some description", 10, &actions2, 0);
        assert(alert2);

        assert(alert_comparator(alert1, alert2) == 1);

        if (NULL != actions1)
            zlist_destroy(&actions1);
        if (NULL != actions2)
            zlist_destroy(&actions2);
        fty_proto_destroy(&alert1);
        fty_proto_destroy(&alert2);
    }

    {
        zlist_t *actions1 = zlist_new();
        zlist_autofree(actions1);
        zlist_append(actions1, (void *) ACTION_SMS);
        fty_proto_t *alert1 = alert_new("temperature.average@DC-Roztoky", "epdu", "ACTIVE", "low", "some description", 10, &actions1, 0);
        assert(alert1);
        zlist_t *actions2 = zlist_new();
        zlist_autofree(actions2);
        zlist_append(actions2, (void *) ACTION_SMS);
        fty_proto_t *alert2 = alert_new("temperature.average@DC-Roztoky", "epdu", "ACK-WIP", "low", "some description", 10, &actions2, 0);
        assert(alert2);

        assert(alert_comparator(alert1, alert2) == 1);

        if (NULL != actions1)
            zlist_destroy(&actions1);
        if (NULL != actions2)
            zlist_destroy(&actions2);
        fty_proto_destroy(&alert1);
        fty_proto_destroy(&alert2);
    }

    {
        zlist_t *actions1 = zlist_new();
        zlist_autofree(actions1);
        zlist_append(actions1, (void *) ACTION_SMS);
        fty_proto_t *alert1 = alert_new("temperature.average@DC-Roztoky", "epdu", "ACK-WIP", "low", "shitty description", 10, &actions1, 0);
        assert(alert1);
        zlist_t *actions2 = zlist_new();
        zlist_autofree(actions2);
        zlist_append(actions2, (void *) ACTION_SMS);
        fty_proto_t *alert2 = alert_new("temperature.average@DC-Roztoky", "epdu", "ACK-WIP", "low", "some description", 10, &actions2, 0);
        assert(alert2);

        assert(alert_comparator(alert1, alert2) == 1);

        if (NULL != actions1)
            zlist_destroy(&actions1);
        if (NULL != actions2)
            zlist_destroy(&actions2);
        fty_proto_destroy(&alert1);
        fty_proto_destroy(&alert2);
    }

    {
        zlist_t *actions1 = zlist_new();
        zlist_autofree(actions1);
        zlist_append(actions1, (void *) ACTION_SMS);
        fty_proto_t *alert1 = alert_new("temperature.average@DC-Roztoky", "epdu", "ACK-WIP", "low", "some description", 1, &actions1, 0);
        assert(alert1);
        zlist_t *actions2 = zlist_new();
        zlist_autofree(actions2);
        zlist_append(actions2, (void *) ACTION_SMS);
        fty_proto_t *alert2 = alert_new("temperature.average@DC-Roztoky", "epdu", "ACK-WIP", "low", "some description", 10, &actions2, 0);
        assert(alert2);

        assert(alert_comparator(alert1, alert2) == 1);

        if (NULL != actions1)
            zlist_destroy(&actions1);
        if (NULL != actions2)
            zlist_destroy(&actions2);
        fty_proto_destroy(&alert1);
        fty_proto_destroy(&alert2);
    }

    {
        zlist_t *actions1 = zlist_new();
        zlist_autofree(actions1);
        zlist_append(actions1, (void *) ACTION_EMAIL);
        fty_proto_t *alert1 = alert_new("temperature.average@DC-Roztoky", "epdu", "ACK-WIP", "low", "some description", 10, &actions1, 0);
        assert(alert1);
        zlist_t *actions2 = zlist_new();
        zlist_autofree(actions2);
        zlist_append(actions2, (void *) ACTION_SMS);
        fty_proto_t *alert2 = alert_new("temperature.average@DC-Roztoky", "epdu", "ACK-WIP", "low", "some description", 10, &actions2, 0);
        assert(alert2);

        assert(alert_comparator(alert1, alert2) == 1);

        if (NULL != actions1)
            zlist_destroy(&actions1);
        if (NULL != actions2)
            zlist_destroy(&actions2);
        fty_proto_destroy(&alert1);
        fty_proto_destroy(&alert2);
    }

    // unicode
    {
        zlist_t *actions1 = zlist_new();
        zlist_autofree(actions1);
        zlist_append(actions1, (void *) ACTION_EMAIL);
        fty_proto_t *alert1 = alert_new("temperature.average@DC-Roztoky", "ŽlUťOUčKý kůň", "ACK-WIP", "low", "some description", 10, &actions1, 0);
        assert(alert1);
        zlist_t *actions2 = zlist_new();
        zlist_autofree(actions2);
        zlist_append(actions2, (void *) ACTION_SMS);
        fty_proto_t *alert2 = alert_new("temperature.average@DC-Roztoky", "\u017dlu\u0165ou\u010dk\xc3\xbd K\u016f\xc5\x88", "ACK-WIP", "low", "some description", 10, &actions2, 0);
        assert(alert2);

        assert(alert_comparator(alert1, alert2) == 1);

        if (NULL != actions1)
            zlist_destroy(&actions1);
        if (NULL != actions2)
            zlist_destroy(&actions2);
        fty_proto_destroy(&alert1);
        fty_proto_destroy(&alert2);
    }


    // TODO: action can be mixed

    //  *********************************
    //  *****   alert_save_state    *****
    //  *****   alert_load_state    *****
    //  *********************************

    {

        // Test case #1:
        //  Fill list, store, load, compare one by one
        zlistx_t *alerts = zlistx_new();
        assert(alerts);
        zlistx_set_destructor(alerts, (czmq_destructor *) fty_proto_destroy);
        zlistx_set_duplicator(alerts, (czmq_duplicator *) fty_proto_dup);

        zlist_t *actions1 = zlist_new();
        zlist_autofree(actions1);
        zlist_append(actions1, (void *) ACTION_EMAIL);
        zlist_append(actions1, (void *) ACTION_SMS);
        fty_proto_t *alert = alert_new("Rule1", "Element1", "ACTIVE", "high", "xyz", 1, &actions1, 0);
        assert(alert);
        zlistx_add_end(alerts, alert);
        fty_proto_destroy(&alert);

        zlist_t *actions2 = zlist_new();
        zlist_autofree(actions2);
        zlist_append(actions2, (void *) ACTION_EMAIL);
        zlist_append(actions2, (void *) ACTION_SMS);
        alert = alert_new("Rule1", "Element2", "RESOLVED", "high", "xyz", 20, &actions2, 0);
        assert(alert);
        zlistx_add_end(alerts, alert);
        fty_proto_destroy(&alert);

        zlist_t *actions3 = zlist_new();
        zlist_autofree(actions3);
        zlist_append(actions3, (void *) ACTION_SMS);
        alert = alert_new("Rule2", "Element1", "ACK-WIP", "low", "this is description", 152452412, &actions3, 0);
        assert(alert);
        zlistx_add_end(alerts, alert);
        fty_proto_destroy(&alert);

        zlist_t *actions4 = zlist_new();
        zlist_autofree(actions4);
        zlist_append(actions4, (void *) ACTION_EMAIL);
        alert = alert_new("Rule2", "Element2", "ACK-SILENCE", "high", "x", 5, &actions4, 0);
        assert(alert);
        zlistx_add_end(alerts, alert);
        fty_proto_destroy(&alert);

        zlist_t *actions5 = zlist_new();
        zlist_autofree(actions5);
        zlist_append(actions5, (void *) ACTION_EMAIL);
        zlist_append(actions5, (void *) ACTION_SMS);
        alert = alert_new("Rule1", "Element3", "RESOLVED", "a", "y", 50, &actions5, 0);
        assert(alert);
        zlistx_add_end(alerts, alert);
        fty_proto_destroy(&alert);

        zlist_t *actions6 = zlist_new();
        zlist_autofree(actions6);
        zlist_append(actions6, (void *) ACTION_EMAIL);
        zlist_append(actions6, (void *) ACTION_SMS);
        alert = alert_new("realpower.default", "ŽlUťOUčKý kůň супер", "ACTIVE", "low", "unicode test case #1", 60, &actions6, 0);
        assert(alert);
        zlistx_add_end(alerts, alert);
        fty_proto_destroy(&alert);

        int rv = alert_save_state(alerts, ".", "test_state_file", true);
        assert(rv == 0);

        zlistx_destroy(&alerts);

        zlistx_t *alerts2 = zlistx_new();
        assert(alerts2);
        zlistx_set_destructor(alerts2, (czmq_destructor *) fty_proto_destroy);
        //zlistx_set_duplicator(alerts2, (czmq_duplicator *) fty_proto_dup);
        rv = alert_load_state(alerts2, ".", "test_state_file");
        assert(rv == 0);

        log_debug("zlistx size == %d", zlistx_size(alerts2));

        // Check them one by one
        fty_proto_t *cursor = (fty_proto_t *) zlistx_first(alerts2);
        assert(streq(fty_proto_rule(cursor), "Rule1"));
        assert(streq(fty_proto_name(cursor), "Element1"));
        assert(streq(fty_proto_state(cursor), "ACTIVE"));
        assert(streq(fty_proto_severity(cursor), "high"));
        assert(streq(fty_proto_description(cursor), "xyz"));
        assert(streq(fty_proto_action_first(cursor), "EMAIL"));
        assert(streq(fty_proto_action_next(cursor), "SMS"));
        assert(NULL == fty_proto_action_next(cursor));
        assert(fty_proto_time(cursor) == (uint64_t) 1);

        cursor = (fty_proto_t *) zlistx_next(alerts2);
        assert(streq(fty_proto_rule(cursor), "Rule1"));
        assert(streq(fty_proto_name(cursor), "Element2"));
        assert(streq(fty_proto_state(cursor), "RESOLVED"));
        assert(streq(fty_proto_severity(cursor), "high"));
        assert(streq(fty_proto_description(cursor), "xyz"));
        assert(streq(fty_proto_action_first(cursor), "EMAIL"));
        assert(streq(fty_proto_action_next(cursor), "SMS"));
        assert(NULL == fty_proto_action_next(cursor));
        assert(fty_proto_time(cursor) == (uint64_t) 20);

        cursor = (fty_proto_t *) zlistx_next(alerts2);
        assert(streq(fty_proto_rule(cursor), "Rule2"));
        assert(streq(fty_proto_name(cursor), "Element1"));
        assert(streq(fty_proto_state(cursor), "ACK-WIP"));
        assert(streq(fty_proto_severity(cursor), "low"));
        assert(streq(fty_proto_description(cursor), "this is description"));
        assert(streq(fty_proto_action_first(cursor), "SMS"));
        assert(NULL == fty_proto_action_next(cursor));
        assert(fty_proto_time(cursor) == (uint64_t) 152452412);

        cursor = (fty_proto_t *) zlistx_next(alerts2);
        assert(streq(fty_proto_rule(cursor), "Rule2"));
        assert(streq(fty_proto_name(cursor), "Element2"));
        assert(streq(fty_proto_state(cursor), "ACK-SILENCE"));
        assert(streq(fty_proto_severity(cursor), "high"));
        assert(streq(fty_proto_description(cursor), "x"));
        assert(streq(fty_proto_action_first(cursor), "EMAIL"));
        assert(NULL == fty_proto_action_next(cursor));
        assert(fty_proto_time(cursor) == (uint64_t) 5);

        cursor = (fty_proto_t *) zlistx_next(alerts2);
        assert(streq(fty_proto_rule(cursor), "Rule1"));
        assert(streq(fty_proto_name(cursor), "Element3"));
        assert(streq(fty_proto_state(cursor), "RESOLVED"));
        assert(streq(fty_proto_severity(cursor), "a"));
        assert(streq(fty_proto_description(cursor), "y"));
        assert(streq(fty_proto_action_first(cursor), "EMAIL"));
        assert(streq(fty_proto_action_next(cursor), "SMS"));
        assert(NULL == fty_proto_action_next(cursor));
        assert(fty_proto_time(cursor) == (uint64_t) 50);

        cursor = (fty_proto_t *) zlistx_next(alerts2);
        assert(streq(fty_proto_rule(cursor), "realpower.default"));
        assert(UTF8::utf8eq(fty_proto_name(cursor), "ŽlUťOUčKý kůň супер"));
        assert(streq(fty_proto_state(cursor), "ACTIVE"));
        assert(streq(fty_proto_severity(cursor), "low"));
        assert(streq(fty_proto_description(cursor), "unicode test case #1"));
        assert(streq(fty_proto_action_first(cursor), "EMAIL"));
        assert(streq(fty_proto_action_next(cursor), "SMS"));
        assert(NULL == fty_proto_action_next(cursor));
        assert(fty_proto_time(cursor) == (uint64_t) 60);

        zlistx_destroy(&alerts2);

        if (NULL != actions1)
            zlist_destroy(&actions1);
        if (NULL != actions2)
            zlist_destroy(&actions2);
        if (NULL != actions3)
            zlist_destroy(&actions3);
        if (NULL != actions4)
            zlist_destroy(&actions4);
        if (NULL != actions5)
            zlist_destroy(&actions5);
        if (NULL != actions6)
            zlist_destroy(&actions6);

        zsys_file_delete ("./test_state_file");
    }

    // Test case #2:
    //  file does not exist
    {
        zlistx_t *alerts = zlistx_new();
        assert(alerts);
        zlistx_set_destructor(alerts, (czmq_destructor *) fty_proto_destroy);
        zlistx_set_duplicator(alerts, (czmq_duplicator *) fty_proto_dup);
        int rv = alert_load_state(alerts, ".", "does_not_exist");
        assert(rv == -1);
        zlistx_destroy(&alerts);
    }
    // State file with old format
    {
    zlistx_t *alerts = zlistx_new ();
    assert (alerts);
    zlistx_set_destructor (alerts, (czmq_destructor *) fty_proto_destroy);
    zlistx_set_duplicator (alerts, (czmq_duplicator *) fty_proto_dup);
    int rv = alert_load_state (alerts, "src/selftest-ro", "old_state_file");
    assert (rv == 0);
    assert (zlistx_size(alerts) == 0);
    zlistx_destroy (&alerts);
    }

    //  @end
    printf("OK\n");
}
