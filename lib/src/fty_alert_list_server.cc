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

/*
@header
    fty_alert_list_server - Providing information about active alerts
@discuss
@end
 */

#include "fty_alert_list_classes.h"

#include <string.h>
#include <map>
#include <mutex>

#define RFC_ALERTS_LIST_SUBJECT "rfc-alerts-list"
#define RFC_ALERTS_ACKNOWLEDGE_SUBJECT  "rfc-alerts-acknowledge"

static const char *STATE_PATH = "/var/lib/fty/fty-alert-list";
static const char *STATE_FILE = "state_file";

static zlistx_t *alerts = NULL;
static std::map<fty_proto_t*, time_t> alertsLastSent;
static std::mutex alertMtx;
static bool verbose = false;

static void
s_set_alert_lifetime (zhash_t *exp, fty_proto_t *msg) {
    if (!exp || !msg) return;

    int64_t ttl = fty_proto_ttl (msg);
    if (!ttl) return;
    const char *rule = fty_proto_rule (msg);
    if (!rule) return;
    int64_t *time = (int64_t *) malloc (sizeof (int64_t));
    if (!time) return;

    *time = zclock_mono () / 1000 + ttl;
    zhash_update (exp, rule, time);
    log_debug (" ##### rule %s with ttl %" PRIi64, rule, ttl);
    zhash_freefn (exp, rule, free);
}

static bool
s_alert_expired (zhash_t *exp, fty_proto_t *msg) {
    if (!exp || !msg) return false;

    const char *rule = fty_proto_rule (msg);
    if (!rule) return false;

    int64_t *time = (int64_t *) zhash_lookup (exp, rule);
    if (!time) {
        return false;
    }
    return (*time < zclock_mono () / 1000);
}

static void
s_clear_long_time_expired (zhash_t *exp) {
    if (!exp) return;

    zlist_t *keys = zhash_keys (exp);
    int64_t now = zclock_mono () / 1000;

    const char *rule = (char *) zlist_first (keys);
    while (rule) {
        int64_t *time = (int64_t *) zhash_lookup (exp, rule);
        if (*time < now - 3600) zhash_delete (exp, rule);
        rule = (char *) zlist_next (keys);
    }
    zlist_destroy (&keys);
}

static void
s_resolve_expired_alerts (zhash_t *exp) {
    if (!exp || !alerts) return;

    alertMtx.lock ();
    fty_proto_t *cursor = (fty_proto_t *) zlistx_first (alerts);
    while (cursor) {
        if (s_alert_expired (exp, cursor) && streq (fty_proto_state (cursor), "ACTIVE")) {
            fty_proto_set_state (cursor, "%s", "RESOLVED");
            std::string new_desc = JSONIFY ("%s - %s", fty_proto_description (cursor), "TTLCLEANUP");
            fty_proto_set_description (cursor, "%s", new_desc.c_str ());

            if (verbose) {
                log_debug ("s_resolve_expired_alerts: resolving alert");
                fty_proto_print (cursor);
            }
        }
        cursor = (fty_proto_t *) zlistx_next (alerts);
    }
    alertMtx.unlock ();

    s_clear_long_time_expired (exp);
}

static void
s_handle_stream_deliver (mlm_client_t *client, zmsg_t** msg_p, zhash_t *expirations) {
    assert (client);
    assert (msg_p);

    if (!is_fty_proto (*msg_p)) {
        log_error ("s_handle_stream_deliver (): Message not fty_proto");
        return;
    }

    fty_proto_t *newAlert = fty_proto_decode (msg_p);
    if (!newAlert || fty_proto_id (newAlert) != FTY_PROTO_ALERT) {
        fty_proto_destroy (&newAlert);
        log_warning ("s_handle_stream_deliver (): Message not FTY_PROTO_ALERT.");
        return;
    }

    // handle *only* ACTIVE or RESOLVED alerts
    if (!streq (fty_proto_state (newAlert), "ACTIVE") &&
            !streq (fty_proto_state (newAlert), "RESOLVED")) {
        fty_proto_destroy (&newAlert);
        log_warning ("s_handle_stream_deliver (): Message state not ACTIVE or RESOLVED. Not publishing any further.");
        return;
    }

    if (verbose) {
        log_debug ("----> printing alert ");
        fty_proto_print (newAlert);
    }

    alertMtx.lock ();

    fty_proto_t *cursor = (fty_proto_t *) zlistx_first (alerts);
    bool found = false;
    while (cursor) {
        if (alert_id_comparator (cursor, newAlert) == 0) {
            found = true;
            break;
        }
        cursor = (fty_proto_t *) zlistx_next (alerts);
    }

    bool send = true; // default, publish

    if (!found) {
        // Record creation time
        fty_proto_aux_insert (newAlert, "ctime", "%" PRIu64, fty_proto_time (newAlert));

        zlistx_add_end (alerts, newAlert);
        cursor = (fty_proto_t *) zlistx_last (alerts);
        alertsLastSent[cursor] = 0;
        s_set_alert_lifetime (expirations, newAlert);
    }
    else {
        // Append creation time to new alert
        fty_proto_aux_insert (newAlert, "ctime", "%" PRIu64, fty_proto_aux_number (cursor, "ctime", 0));

        bool sameSeverity = streq (fty_proto_severity (newAlert), fty_proto_severity (cursor));
        fty_proto_set_severity (cursor, "%s", fty_proto_severity (newAlert));

        // Wasn't specified, but common sense applied, it should be:
        // RESOLVED comes from _ALERTS_SYS
        //  * if stored !RESOLVED -> update stored time/state, publish original
        //  * if stored RESOLVED -> don't update stored time, don't publish original
        //
        //  ACTIVE comes form _ALERTS_SYS
        //  * if stored RESOLVED -> update stored time/state, publish modified
        //  * if stored ACK-XXX -> Don't change state or time, don't publish
        //  * if stored ACTIVE -> update time
        //                     -> if severity change => publish else don't publish

        if (streq (fty_proto_state (newAlert), "RESOLVED")) {
            if (!streq (fty_proto_state (cursor), "RESOLVED")) {
                // Record resolved time
                fty_proto_aux_insert (cursor,   "ctime", "%" PRIu64, fty_proto_time (newAlert));
                fty_proto_aux_insert (newAlert, "ctime", "%" PRIu64, fty_proto_time (newAlert));

                fty_proto_set_state (cursor, "%s", fty_proto_state (newAlert));
                fty_proto_set_time (cursor, fty_proto_time (newAlert));
                fty_proto_set_metadata (cursor, "%s", fty_proto_metadata (newAlert));
            }
            else {
                send = false;
            }
        }
        else { // state (newAlert) == ACTIVE
            s_set_alert_lifetime (expirations, newAlert);

            //copy the description only if the alert is active
            fty_proto_set_description (cursor, "%s", fty_proto_description (newAlert));

            if (streq (fty_proto_state (cursor), "RESOLVED")) {
                // Record reactivation time
                fty_proto_aux_insert (cursor,   "ctime", "%" PRIu64, fty_proto_time (newAlert));
                fty_proto_aux_insert (newAlert, "ctime", "%" PRIu64, fty_proto_time (newAlert));

                fty_proto_set_time (cursor, fty_proto_time (newAlert));
                fty_proto_set_state (cursor, "%s", fty_proto_state (newAlert));
                fty_proto_set_metadata (cursor, "%s", fty_proto_metadata (newAlert));
            }
            else if (!streq (fty_proto_state (cursor), "ACTIVE")) {
                // fty_proto_state (cursor) ==  ACK-XXXX
                if (sameSeverity) {
                    send = false;
                }
            }
            else { // state (cursor) == ACTIVE
                fty_proto_set_time (cursor, fty_proto_time (newAlert));

                // Always active and same severity => don't publish...
                if (sameSeverity) {
                    // ... if we're not at risk of timing out
                    time_t lastSent = alertsLastSent[cursor];
                    if ((zclock_mono ()/1000) < (lastSent + fty_proto_ttl (cursor)/2)) {
                        send = false;
                    }
                }
                // Severity changed => update creation time
                else {
                    fty_proto_aux_insert (cursor,   "ctime", "%" PRIu64, fty_proto_time (newAlert));
                    fty_proto_aux_insert (newAlert, "ctime", "%" PRIu64, fty_proto_time (newAlert));
                }
            }
        }

        //let's do the action at the end of the processing
        zlist_t *actions;
        if (NULL == fty_proto_action (newAlert)) {
            actions = zlist_new ();
            zlist_autofree (actions);
        }
        else {
            actions = zlist_dup (fty_proto_action (newAlert));
        }
        fty_proto_set_action (cursor, &actions);
    }

    alertMtx.unlock ();

    if (send) {
        log_info("send %s (%s/%s)",
            fty_proto_rule(newAlert), fty_proto_severity(newAlert), fty_proto_state(newAlert));

        fty_proto_t *alert_dup = fty_proto_dup (newAlert);
        zmsg_t *encoded = fty_proto_encode (&alert_dup);
        fty_proto_destroy (&alert_dup);
        assert (encoded);

        int rv = mlm_client_send (client, mlm_client_subject (client), &encoded);
        zmsg_destroy (&encoded);

        if (rv == -1) {
            log_error ("mlm_client_send (subject = '%s') failed", mlm_client_subject (client));
        }
        else { // Update last sent time
            alertsLastSent[cursor] = zclock_mono () / 1000;
        }
    }

    fty_proto_destroy (&newAlert);
}

static void
s_send_error_response (mlm_client_t *client, const char *subject, const char *reason) {
    assert (client);
    assert (subject);
    assert (reason);

    zmsg_t *reply = zmsg_new ();
    assert (reply);

    zmsg_addstr (reply, "ERROR");
    zmsg_addstr (reply, reason);

    int rv = mlm_client_sendto (client, mlm_client_sender (client), subject, NULL, 5000, &reply);
    if (rv != 0) {
        zmsg_destroy (&reply);
        log_error ("mlm_client_sendto (sender = '%s', subject = '%s', timeout = '5000') failed.",
                mlm_client_sender (client), subject);
    }
}

static void
s_handle_rfc_alerts_list (mlm_client_t *client, zmsg_t **msg_p) {
    assert (client);
    assert (msg_p && *msg_p);
    assert (alerts);

    zmsg_t *msg = *msg_p;
    char *command = zmsg_popstr (msg);
    if (!command || (!streq (command, "LIST") && !streq (command, "LIST_EX"))) {
        free (command);
        command = NULL;
        zmsg_destroy (&msg);
        std::string err = TRANSLATE_ME ("BAD_MESSAGE");
        s_send_error_response (client, RFC_ALERTS_LIST_SUBJECT, err.c_str ());
        return;
    }

    char *correlation_id = NULL;
    if (streq (command, "LIST_EX")) {
        correlation_id = zmsg_popstr (msg);
        if (!correlation_id) {
            free (command);
            command = NULL;
            free (correlation_id);
            correlation_id = NULL;
            zmsg_destroy (&msg);
            std::string err = TRANSLATE_ME ("BAD_MESSAGE");
            s_send_error_response (client, RFC_ALERTS_LIST_SUBJECT, err.c_str ());
            return;
        }
    }

    free (command);
    command = NULL;

    char *state = zmsg_popstr (msg);
    zmsg_destroy (msg_p);
    if (!state || !is_list_request_state (state)) {
        free (correlation_id);
        correlation_id = NULL;
        free (state);
        state = NULL;
        s_send_error_response (client, RFC_ALERTS_LIST_SUBJECT, "NOT_FOUND");
        return;
    }

    zmsg_t *reply = zmsg_new ();
    if (correlation_id) {
        zmsg_addstr (reply, "LIST_EX");
        zmsg_addstr (reply, correlation_id);
    }
    else {
        zmsg_addstr (reply, "LIST");
    }
    zmsg_addstr (reply, state);
    alertMtx.lock ();
    fty_proto_t *cursor = (fty_proto_t *) zlistx_first (alerts);
    while (cursor) {
        if (is_state_included (state, fty_proto_state (cursor))) {
            fty_proto_t *duplicate = fty_proto_dup (cursor);
            zmsg_t *result = fty_proto_encode (&duplicate);

            /* Note: the CZMQ_VERSION_MAJOR comparison below actually assumes versions
             * we know and care about - v3.0.2 (our legacy default, already obsoleted
             * by upstream), and v4.x that is in current upstream master. If the API
             * evolves later (incompatibly), these macros will need to be amended.
             */
            zframe_t *frame = NULL;
            // FIXME: should we check and assert (nbytes>0) here, for both API versions,
            // as we do in other similar cases?
#if CZMQ_VERSION_MAJOR == 3
            byte *buffer = NULL;
            size_t nbytes = zmsg_encode (result, &buffer);
            frame = zframe_new ((void *) buffer, nbytes);
            free (buffer);
            buffer = NULL;
#else
            frame = zmsg_encode (result);
#endif
            assert (frame);
            zmsg_destroy (&result);
            zmsg_append (reply, &frame);
            //FIXME: Should we zframe_destroy (&frame) here as we do in other similar cases?
        }
        cursor = (fty_proto_t *) zlistx_next (alerts);
    }
    alertMtx.unlock ();

    if (mlm_client_sendto (client, mlm_client_sender (client), RFC_ALERTS_LIST_SUBJECT, NULL, 5000, &reply) != 0) {
        log_error ("mlm_client_sendto (sender = '%s', subject = '%s', timeout = '5000') failed.",
                mlm_client_sender (client), RFC_ALERTS_LIST_SUBJECT);
    }
    free (correlation_id);
    correlation_id = NULL;
    free (state);
    state = NULL;
}

static void
s_handle_rfc_alerts_acknowledge (mlm_client_t *client, zmsg_t **msg_p) {
    assert (client);
    assert (msg_p);
    assert (alerts);

    zmsg_t *msg = *msg_p;
    if (!msg) {
        return;
    }

    char *rule = zmsg_popstr (msg);
    if (!rule) {
        zmsg_destroy (&msg);
        std::string err = TRANSLATE_ME ("BAD_MESSAGE");
        s_send_error_response (client, RFC_ALERTS_ACKNOWLEDGE_SUBJECT, err.c_str ());
        return;
    }
    char *element = zmsg_popstr (msg);
    if (!element) {
        zstr_free (&rule);
        zmsg_destroy (&msg);
        std::string err = TRANSLATE_ME ("BAD_MESSAGE");
        s_send_error_response (client, RFC_ALERTS_ACKNOWLEDGE_SUBJECT, err.c_str ());
        return;
    }
    char *state = zmsg_popstr (msg);
    if (!state) {
        zstr_free (&rule);
        zstr_free (&element);
        zmsg_destroy (&msg);
        std::string err = TRANSLATE_ME ("BAD_MESSAGE");
        s_send_error_response (client, RFC_ALERTS_ACKNOWLEDGE_SUBJECT, err.c_str ());
        return;
    }
    zmsg_destroy (&msg);
    // check 'state'
    if (!is_acknowledge_request_state (state)) {
        log_warning (
                "state '%s' is not an acknowledge request state according to protocol '%s'.",
                state, RFC_ALERTS_ACKNOWLEDGE_SUBJECT);
        zstr_free (&rule);
        zstr_free (&element);
        zstr_free (&state);
        s_send_error_response (client, RFC_ALERTS_ACKNOWLEDGE_SUBJECT, "BAD_STATE");
        return;
    }
    log_debug (
            "s_handle_rfc_alerts_acknowledge (): rule == '%s' element == '%s' state == '%s'",
            rule, element, state);
    // check ('rule', 'element') pair
    alertMtx.lock ();
    fty_proto_t *cursor = (fty_proto_t *) zlistx_first (alerts);
    int found = 0;
    while (cursor) {
        if (is_alert_identified (cursor, rule, element)) {
            found = 1;
            break;
        }
        cursor = (fty_proto_t *) zlistx_next (alerts);
    }
    if (found == 0) {
        zstr_free (&rule);
        zstr_free (&element);
        zstr_free (&state);
        s_send_error_response (client, RFC_ALERTS_ACKNOWLEDGE_SUBJECT, "NOT_FOUND");
        alertMtx.unlock ();
        return;
    }
    if (streq (fty_proto_state (cursor), "RESOLVED")) {
        zstr_free (&rule);
        zstr_free (&element);
        zstr_free (&state);
        s_send_error_response (client, RFC_ALERTS_ACKNOWLEDGE_SUBJECT, "BAD_STATE");
        alertMtx.unlock ();
        return;
    }
    // change stored alert state, don't change timestamp
    log_debug (
            "s_handle_rfc_alerts_acknowledge (): Changing state of (%s, %s) to %s",
            fty_proto_rule (cursor), fty_proto_name (cursor), state);
    fty_proto_set_state (cursor, "%s", state);

    zmsg_t *reply = zmsg_new ();
    zmsg_addstr (reply, "OK");
    zmsg_addstr (reply, rule);
    zmsg_addstr (reply, element);
    zmsg_addstr (reply, state);

    char *subject = zsys_sprintf ("%s/%s@%s", fty_proto_rule (cursor),
            fty_proto_severity (cursor), fty_proto_name (cursor));
    zstr_free (&rule);
    zstr_free (&element);
    zstr_free (&state);

    int rv = mlm_client_sendto (client, mlm_client_sender (client),
            RFC_ALERTS_ACKNOWLEDGE_SUBJECT, NULL, 5000, &reply);
    if (rv != 0) {
        zmsg_destroy (&reply);
        log_error ("mlm_client_sendto (sender = '%s', subject = '%s', timeout = '5000') failed.",
                mlm_client_sender (client), RFC_ALERTS_ACKNOWLEDGE_SUBJECT);
    }
    if (!subject) {
        log_error ("zsys_sprintf () failed");
        alertMtx.unlock ();
        return;
    }
    uint64_t timestamp = (uint64_t) ((uint64_t) zclock_time () / 1000);
    fty_proto_t *copy = fty_proto_dup (cursor);
    if (!copy) {
        log_error ("fty_proto_dup () failed");
        zstr_free (&subject);
        alertMtx.unlock ();
        return;
    }
    alertMtx.unlock ();

    fty_proto_set_time (copy, timestamp);
    reply = fty_proto_encode (&copy);
    if (!reply) {
        log_error ("fty_proto_encode () failed");
        fty_proto_destroy (&copy);
        zstr_free (&subject);
        return;
    }
    rv = mlm_client_send (client, subject, &reply);
    if (rv != 0) {
        zmsg_destroy (&reply);
        log_error ("mlm_client_send (subject = '%s') failed", subject);
    }
    zstr_free (&subject);
}

static void
s_handle_mailbox_deliver (mlm_client_t *client, zmsg_t** msg_p) {
    assert (client);
    assert (msg_p && *msg_p);
    assert (alerts);

    if (streq (mlm_client_subject (client), RFC_ALERTS_LIST_SUBJECT)) {
        s_handle_rfc_alerts_list (client, msg_p);
    } else if (streq (mlm_client_subject (client), RFC_ALERTS_ACKNOWLEDGE_SUBJECT)) {
        s_handle_rfc_alerts_acknowledge (client, msg_p);
    } else {
        std::string err = TRANSLATE_ME ("UNKNOWN_PROTOCOL");
        s_send_error_response (client, mlm_client_subject (client), err.c_str ());
        log_error ("Unknown protocol. Subject: '%s', Sender: '%s'.",
                mlm_client_subject (client), mlm_client_sender (client));
        zmsg_destroy (msg_p);
    }
}

void
fty_alert_list_server_stream (zsock_t *pipe, void *args) {
    log_info("Started");

    const char *endpoint = (const char *) args;
    log_debug ("Stream endpoint = %s", endpoint);

    zhash_t *expirations = zhash_new ();
    mlm_client_t *client = mlm_client_new ();
    mlm_client_connect (client, endpoint, 1000, "fty-alert-list-stream");
    mlm_client_set_consumer (client, "_ALERTS_SYS", ".*");
    mlm_client_set_producer (client, "ALERTS");

    zpoller_t *poller = zpoller_new (pipe, mlm_client_msgpipe (client), NULL);
    zsock_signal (pipe, 0);

    while (!zsys_interrupted) {

        void *which = zpoller_wait (poller, 1000);

        if (which == pipe) {
            zmsg_t *msg = zmsg_recv (pipe);
            char *cmd = zmsg_popstr (msg);
            if (streq (cmd, "$TERM")) {
                zstr_free (&cmd);
                zmsg_destroy (&msg);
                break;
            }
            else if (streq (cmd, "TTLCLEANUP")) {
                s_resolve_expired_alerts (expirations);
            }
            zstr_free (&cmd);
            zmsg_destroy (&msg);
        }
        else if (which == mlm_client_msgpipe (client)) {
            zmsg_t *msg = mlm_client_recv (client);
            if (!msg) {
                break;
            }
            else if (streq (mlm_client_command (client), "STREAM DELIVER")) {
                s_handle_stream_deliver (client, &msg, expirations);
            }
            else {
                log_warning ("Unknown command '%s'. Subject: '%s', Sender: '%s'.",
                        mlm_client_command (client), mlm_client_subject (client), mlm_client_sender (client));
                zmsg_destroy (&msg);
            }
        }
    }

    mlm_client_destroy (&client);
    zpoller_destroy (&poller);
    zhash_destroy (&expirations);

    log_info("Ended");
}

void
fty_alert_list_server_mailbox (zsock_t *pipe, void *args) {
    const char *endpoint = (const char *) args;
    log_debug ("Mailbox endpoint = %s", endpoint);

    mlm_client_t *client = mlm_client_new ();
    mlm_client_connect (client, endpoint, 1000, "fty-alert-list");
    mlm_client_set_producer (client, "ALERTS");

    zpoller_t *poller = zpoller_new (pipe, mlm_client_msgpipe (client), NULL);
    zsock_signal (pipe, 0);

    while (!zsys_interrupted) {

        void *which = zpoller_wait (poller, 1000);
        if (which == pipe) {
            zmsg_t *msg = zmsg_recv (pipe);
            char *cmd = zmsg_popstr (msg);
            if (streq (cmd, "$TERM")) {
                zstr_free (&cmd);
                zmsg_destroy (&msg);
                break;
            }
            zstr_free (&cmd);
            zmsg_destroy (&msg);
        }
        else if (which == mlm_client_msgpipe (client)) {
            zmsg_t *msg = mlm_client_recv (client);
            if (!msg) {
                break;
            }
            else if (streq (mlm_client_command (client), "MAILBOX DELIVER")) {
                s_handle_mailbox_deliver (client, &msg);
            }
            else {
                log_warning ("Unknown command '%s'. Subject: '%s', Sender: '%s'.",
                        mlm_client_command (client), mlm_client_subject (client), mlm_client_sender (client));
                zmsg_destroy (&msg);
            }
        }
    }

    mlm_client_destroy (&client);
    zpoller_destroy (&poller);
}

void save_alerts () {
    int rv = alert_save_state (alerts, STATE_PATH, STATE_FILE, verbose);
    log_debug ("alert_save_state () == %d", rv);
}

static void
init_alert_private (const char *path, const char *filename, bool verb)
{
    alerts = zlistx_new ();
    assert(alerts);
    zlistx_set_destructor (alerts, (czmq_destructor *) fty_proto_destroy);
    zlistx_set_duplicator (alerts, (czmq_duplicator *) fty_proto_dup);

    int rv = alert_load_state (alerts, path, filename);
    log_debug ("alert_load_state () == %d", rv);

    verbose = verb;
}

void
init_alert (bool verb) {
    init_alert_private(STATE_PATH, STATE_FILE, verb);
}

void
destroy_alert () {
    zlistx_destroy (&alerts);
}

//  --------------------------------------------------------------------------
//  Self test of this class.

// ---- Test Helper Functions

static void
test_print_zlistx (zlistx_t *list) {
    assert (list);
    fty_proto_t *cursor = (fty_proto_t *) zlistx_first (list);
    while (cursor) {
        log_debug ("| %-15s %-15s %-15s %-12s  %-12" PRIu64" count:%zu  %s  %s",
                fty_proto_rule (cursor),
                fty_proto_aux_string (cursor, FTY_PROTO_RULE_CLASS, ""),
                fty_proto_name (cursor),
                fty_proto_state (cursor),
                fty_proto_time (cursor),
                zlist_size (fty_proto_action (cursor)),
                fty_proto_severity (cursor),
                fty_proto_description (cursor));
        const char *actions = fty_proto_action_first (cursor);
        while (NULL != actions) {
            log_debug ("| %-15s %-15s %-15s %-12s  %-12" PRIu64" %s  %s  %s",
                    fty_proto_rule (cursor),
                    fty_proto_aux_string (cursor, FTY_PROTO_RULE_CLASS, ""),
                    fty_proto_name (cursor),
                    fty_proto_state (cursor),
                    fty_proto_time (cursor),
                    actions,
                    fty_proto_severity (cursor),
                    fty_proto_description (cursor));
            actions = fty_proto_action_next (cursor);
        }
        cursor = (fty_proto_t *) zlistx_next (list);
    }
}

static zmsg_t *
test_request_alerts_list (mlm_client_t *user_interface, const char *state, bool ex = false) {
    assert (user_interface);
    assert (state);
    assert (is_list_request_state (state));

    zmsg_t *send = zmsg_new ();
    assert (send);
    if (ex) {
        zmsg_addstr (send, "LIST_EX");
        zmsg_addstr (send, "1234");
    }
    else {
        zmsg_addstr (send, "LIST");
    }
    zmsg_addstr (send, state);
    if (mlm_client_sendto (user_interface, "fty-alert-list", RFC_ALERTS_LIST_SUBJECT, NULL, 5000, &send) != 0) {
        zmsg_destroy (&send);
        log_error ("mlm_client_sendto (address = 'fty-alert-list', subject = '%s') failed.", RFC_ALERTS_LIST_SUBJECT);
        return NULL;
    }
    zmsg_t *reply = mlm_client_recv (user_interface);
    assert (streq (mlm_client_command (user_interface), "MAILBOX DELIVER"));
    assert (streq (mlm_client_sender (user_interface), "fty-alert-list"));
    assert (streq (mlm_client_subject (user_interface), RFC_ALERTS_LIST_SUBJECT));
    assert (reply);
    return reply;
}

static void
test_request_alerts_acknowledge (mlm_client_t *ui, mlm_client_t *consumer, const char *rule,
        const char *element, const char *state, zlistx_t *alerts, int expect_fail) {
    assert (ui);
    assert (consumer);
    assert (rule);
    assert (element);
    assert (state);
    assert (alerts);

    // Update 'state' for ('rule', 'element') in EXPECTED structure
    fty_proto_t *cursor = (fty_proto_t *) zlistx_first (alerts);
    int found = 0;
    while (cursor) {
        if (is_alert_identified (cursor, rule, element)) {
            if (expect_fail == 0) {
                fty_proto_set_state (cursor, "%s", state);
            }
            found = 1;
            break;
        }
        cursor = (fty_proto_t *) zlistx_next (alerts);
    }

    // Send the request
    zmsg_t *send = zmsg_new ();
    assert (send);
    zmsg_addstr (send, rule);
    zmsg_addstr (send, element);
    zmsg_addstr (send, state);
    int rv = mlm_client_sendto (ui, "fty-alert-list", RFC_ALERTS_ACKNOWLEDGE_SUBJECT, NULL, 5000, &send);
    assert (rv == 0);

    if (expect_fail == 0) {
        // Suck the message off stream
        zmsg_t *published = mlm_client_recv (consumer);
        assert (published);
        fty_proto_t *decoded = fty_proto_decode (&published);
        assert (decoded);
        log_debug ("\t ALERTS published %s %s %s %" PRIu64" %s %s %s",
                fty_proto_rule (decoded),
                fty_proto_name (decoded),
                fty_proto_state (decoded),
                fty_proto_time (decoded),
                fty_proto_action (decoded),
                fty_proto_severity (decoded),
                fty_proto_description (decoded));
        assert (streq (rule, fty_proto_rule (decoded)));
        assert (UTF8::utf8eq (element, fty_proto_name (decoded)) == 1);
        assert (streq (state, fty_proto_state (decoded)));
        fty_proto_destroy (&decoded);
    }

    // Check protocol reply
    zmsg_t *reply = mlm_client_recv (ui);
    assert (streq (mlm_client_command (ui), "MAILBOX DELIVER"));
    assert (streq (mlm_client_sender (ui), "fty-alert-list"));
    assert (streq (mlm_client_subject (ui), RFC_ALERTS_ACKNOWLEDGE_SUBJECT));
    assert (reply);

    char *ok = zmsg_popstr (reply);
    if (expect_fail == 0) {
        char *rule_reply = zmsg_popstr (reply);
        char *element_reply = zmsg_popstr (reply);
        char *state_reply = zmsg_popstr (reply);
        assert (streq (ok, "OK"));
        assert (streq (rule_reply, rule));
        assert (UTF8::utf8eq (element_reply, element));
        assert (streq (state_reply, state));
        zstr_free (&rule_reply);
        zstr_free (&element_reply);
        zstr_free (&state_reply);
        assert (found == 1);
    } else {
        assert (streq (ok, "ERROR"));
        char *reason = zmsg_popstr (reply);
        assert (streq (reason, "BAD_STATE") || streq (reason, "NOT_FOUND"));
        if (streq (reason, "BAD_STATE")) {
            assert (found == 1);
        } else if (streq (reason, "NOT_FOUND")) {
            assert (found == 0);
        }
        zstr_free (&reason);
    }
    zstr_free (&ok);
    zmsg_destroy (&reply);
}

static int
test_zlistx_same (const char *state, zlistx_t *expected, zlistx_t *received) {
    assert (state);
    assert (expected);
    assert (received);
    fty_proto_t *cursor = (fty_proto_t *) zlistx_first (expected);
    while (cursor) {
        if (is_state_included (state, fty_proto_state (cursor))) {
            void *handle = zlistx_find (received, cursor);
            if (!handle) {
                return 0;
            }
            zlistx_delete (received, handle);
        }
        cursor = (fty_proto_t *) zlistx_next (expected);
    }
    if (zlistx_size (received) != 0) {
        return 0;
    }
    return 1;
}

static void
test_check_result (const char *state, zlistx_t *expected, zmsg_t **reply_p, int fail) {
    assert (state);
    assert (expected);
    assert (reply_p);
    if (!*reply_p) {
        return;
    }
    zmsg_t *reply = *reply_p;
    // check leading protocol frames (strings)
    char *part = zmsg_popstr (reply);
    assert (streq (part, "LIST") || streq (part, "LIST_EX"));
    if (streq (part, "LIST_EX")) {
        char *correlation_id = zmsg_popstr (reply);
        assert (streq (correlation_id, "1234"));
        free (correlation_id);
    }
    free (part);
    part = NULL;
    part = zmsg_popstr (reply);
    assert (streq (part, state));
    free (part);
    part = NULL;

    zlistx_t *received = zlistx_new ();
    zlistx_set_destructor (received, (czmq_destructor *) fty_proto_destroy);
    zlistx_set_duplicator (received, (czmq_duplicator *) fty_proto_dup);
    zlistx_set_comparator (received, (czmq_comparator *) alert_comparator);
    zframe_t *frame = zmsg_pop (reply);
    while (frame) {
        zmsg_t *decoded_zmsg = NULL;
        /* Note: the CZMQ_VERSION_MAJOR comparison below actually assumes versions
         * we know and care about - v3.0.2 (our legacy default, already obsoleted
         * by upstream), and v4.x that is in current upstream master. If the API
         * evolves later (incompatibly), these macros will need to be amended.
         */
#if CZMQ_VERSION_MAJOR == 3
        decoded_zmsg = zmsg_decode (zframe_data (frame), zframe_size (frame));
#else
        decoded_zmsg = zmsg_decode (frame);
#endif
        zframe_destroy (&frame);
        assert (decoded_zmsg);
        fty_proto_t *decoded = fty_proto_decode (&decoded_zmsg);
        assert (decoded);
        assert (fty_proto_id (decoded) == FTY_PROTO_ALERT);
        zlistx_add_end (received, decoded);
        fty_proto_destroy (&decoded);
        frame = zmsg_pop (reply);
    }

    log_debug ("=====================================================");
    log_debug (" REQUESTED LIST STATE == '%s'    SHOULD FAIL == '%s'", state, fail == 0 ? "NO" : "YES");
    log_debug ("-----    EXPECTED    --------------------------------");
    test_print_zlistx (expected);
    log_debug ("-----    RECEIVED    --------------------------------");
    test_print_zlistx (received);
    log_debug ("");

    // compare the two by iterative substraction
    int rv = test_zlistx_same (state, expected, received);
    if (fail) {
        assert (rv == 0);
    } else {
        assert (rv == 1);
    }
    zlistx_destroy (&received);
    zmsg_destroy (reply_p);
}

static void
test_alert_publish (mlm_client_t *producer, mlm_client_t *consumer, zlistx_t *alerts,
        fty_proto_t **message) {
    assert (message);
    assert (*message);
    assert (alerts);
    assert (producer);
    assert (consumer);

    void *handle = zlistx_find (alerts, (void *) *message);
    if (handle) {
        fty_proto_t *item = (fty_proto_t *) zlistx_handle_item (handle);

        fty_proto_set_rule (item, "%s", fty_proto_rule (*message));
        fty_proto_set_name (item, "%s", fty_proto_name (*message));
        fty_proto_set_severity (item, "%s", fty_proto_severity (*message));
        fty_proto_set_description (item, "%s", fty_proto_description (*message));
        zlist_t *actions;
        if (NULL == fty_proto_action (*message)) {
            actions = zlist_new ();
            zlist_autofree (actions);
        } else {
            actions = zlist_dup (fty_proto_action (*message));
        }
        fty_proto_set_action (item, &actions);

        if (streq (fty_proto_state (*message), "RESOLVED")) {
            if (!streq (fty_proto_state (item), "RESOLVED")) {
                fty_proto_set_state (item, "%s", fty_proto_state (*message));
                fty_proto_set_time (item, fty_proto_time (*message));
            }
        } else {
            if (streq (fty_proto_state (item), "RESOLVED")) {
                fty_proto_set_state (item, "%s", fty_proto_state (*message));
                fty_proto_set_time (item, fty_proto_time (*message));
            } else if (!streq (fty_proto_state (item), "ACTIVE")) {
                fty_proto_set_state (*message, "%s", fty_proto_state (item));
            }
        }
    } else {
        zlistx_add_end (alerts, *message);
    }

    fty_proto_t *copy = fty_proto_dup (*message);
    assert (copy);
    zmsg_t *zmessage = fty_proto_encode (&copy);
    assert (zmessage);
    int rv = mlm_client_send (producer, "Nobody here cares about this.", &zmessage);
    assert (rv == 0);
    zclock_sleep (100);
    zmessage = mlm_client_recv (consumer);
    assert (zmessage);
    fty_proto_t *received = fty_proto_decode (&zmessage);
    //    fty_proto_print (received);
    //    fty_proto_print (copy);

    assert (alert_comparator (*message, received) == 0);
    fty_proto_destroy (&received);
    fty_proto_destroy (message);
}

void
fty_alert_list_server_test (bool verb) {
    #define SELFTEST_RO "selftest-ro"

    verbose = verb;
    static const char* endpoint = "inproc://fty-lm-server-test";

    //  @selftest

    printf (" * fty_alerts_list_server: ");

    // Malamute
    zactor_t *server = zactor_new (mlm_server, (void *) "Malamute");
    zstr_sendx (server, "BIND", endpoint, NULL);
    if (verbose)
        zstr_send (server, "VERBOSE");

    // User Interface
    mlm_client_t *ui = mlm_client_new ();
    int rv = mlm_client_connect (ui, endpoint, 1000, "UI");
    assert (rv == 0);

    // Alert Producer
    mlm_client_t *producer = mlm_client_new ();
    rv = mlm_client_connect (producer, endpoint, 1000, "PRODUCER");
    assert (rv == 0);
    rv = mlm_client_set_producer (producer, "_ALERTS_SYS");
    assert (rv == 0);

    // Arbitrary Alert Consumer
    mlm_client_t *consumer = mlm_client_new ();
    rv = mlm_client_connect (consumer, endpoint, 1000, "CONSUMER");
    assert (rv == 0);
    rv = mlm_client_set_consumer (consumer, "ALERTS", ".*");
    assert (rv == 0);

    // Alert Lists (assume empty)
    init_alert_private (SELFTEST_RO, "_faked_empty_alerts_", verb);
    zactor_t *fty_al_server_stream = zactor_new (fty_alert_list_server_stream, (void *) endpoint);
    zactor_t *fty_al_server_mailbox = zactor_new (fty_alert_list_server_mailbox, (void *) endpoint);

    // maintain a list of active alerts (that serves as "expected results")
    zlistx_t *testAlerts = zlistx_new ();
    zlistx_set_destructor (testAlerts, (czmq_destructor *) fty_proto_destroy);
    zlistx_set_duplicator (testAlerts, (czmq_duplicator *) fty_proto_dup);
    zlistx_set_comparator (testAlerts, (czmq_comparator *) alert_id_comparator);

    zmsg_t *reply = test_request_alerts_list (ui, "ALL");
    assert (reply);
    test_check_result ("ALL", testAlerts, &reply, 0);

    reply = test_request_alerts_list (ui, "ACK-WIP");
    test_check_result ("ACK-WIP", testAlerts, &reply, 0);

    reply = test_request_alerts_list (ui, "ACK-IGNORE");
    test_check_result ("ACK-IGNORE", testAlerts, &reply, 0);

    reply = test_request_alerts_list (ui, "ALL-ACTIVE");
    test_check_result ("ALL-ACTIVE", testAlerts, &reply, 0);

    reply = test_request_alerts_list (ui, "RESOLVED");
    test_check_result ("RESOLVED", testAlerts, &reply, 0);

    // add new alert
    zlist_t *actions1 = zlist_new ();
    zlist_autofree (actions1);
    zlist_append (actions1, (void *) "EMAIL");
    zlist_append (actions1, (void *) "SMS");
    fty_proto_t *alert = alert_new ("Threshold", "ups", "ACTIVE", "high", "description", 1, &actions1, 0);
    test_alert_publish (producer, consumer, testAlerts, &alert);

    reply = test_request_alerts_list (ui, "ALL");
    test_check_result ("ALL", testAlerts, &reply, 0);

    reply = test_request_alerts_list (ui, "ACK-PAUSE");
    test_check_result ("ACK-PAUSE", testAlerts, &reply, 0);

    reply = test_request_alerts_list (ui, "ALL-ACTIVE");
    test_check_result ("ALL-ACTIVE", testAlerts, &reply, 0);

    reply = test_request_alerts_list (ui, "RESOLVED");
    test_check_result ("RESOLVED", testAlerts, &reply, 0);

    reply = test_request_alerts_list (ui, "ACTIVE");
    test_check_result ("ACTIVE", testAlerts, &reply, 0);

    // add new alert
    zlist_t *actions2 = zlist_new ();
    zlist_autofree (actions2);
    zlist_append (actions2, (void *) "EMAIL");
    zlist_append (actions2, (void *) "SMS");
    alert = alert_new ("Threshold", "epdu", "ACTIVE", "high", "description", 2, &actions2, 0);
    test_alert_publish (producer, consumer, testAlerts, &alert);

    reply = test_request_alerts_list (ui, "ALL");
    test_check_result ("ALL", testAlerts, &reply, 0);

    reply = test_request_alerts_list (ui, "ACTIVE");
    test_check_result ("ACTIVE", testAlerts, &reply, 0);

    // add new alert
    zlist_t *actions3 = zlist_new ();
    zlist_autofree (actions3);
    zlist_append (actions3, (void *) "EMAIL");
    zlist_append (actions3, (void *) "SMS");
    alert = alert_new ("SimpleRule", "ups", "ACTIVE", "high", "description", 3, &actions3, 0);
    test_alert_publish (producer, consumer, testAlerts, &alert);

    reply = test_request_alerts_list (ui, "ALL");
    test_check_result ("ALL", testAlerts, &reply, 0);

    reply = test_request_alerts_list (ui, "ACTIVE");
    test_check_result ("ACTIVE", testAlerts, &reply, 0);

    // add new alert
    zlist_t *actions4 = zlist_new ();
    zlist_autofree (actions4);
    zlist_append (actions4, (void *) "EMAIL");
    zlist_append (actions4, (void *) "SMS");
    alert = alert_new ("SimpleRule", "ŽlUťOUčKý kůň супер", "ACTIVE", "high", "description", 4, &actions4, 0);
    test_alert_publish (producer, consumer, testAlerts, &alert);

    reply = test_request_alerts_list (ui, "ALL");
    test_check_result ("ALL", testAlerts, &reply, 0);

    reply = test_request_alerts_list (ui, "ACTIVE");
    test_check_result ("ACTIVE", testAlerts, &reply, 0);

    reply = test_request_alerts_list (ui, "ALL-ACTIVE");
    test_check_result ("ALL-ACTIVE", testAlerts, &reply, 0);

    reply = test_request_alerts_list (ui, "RESOLVED");
    test_check_result ("RESOLVED", testAlerts, &reply, 0);

    // add new alert
    zlist_t *actions5 = zlist_new ();
    zlist_autofree (actions5);
    zlist_append (actions5, (void *) "EMAIL");
    zlist_append (actions5, (void *) "SMS");
    alert = alert_new ("Threshold", "ŽlUťOUčKý kůň супер", "RESOLVED", "high", "description", 4, &actions5, 0);
    test_alert_publish (producer, consumer, testAlerts, &alert);

    for (bool ex : { false, true }) {
        // exercise LIST_EX a bit
        reply = test_request_alerts_list (ui, "ALL", ex);
        test_check_result ("ALL", testAlerts, &reply, 0);

        reply = test_request_alerts_list (ui, "ALL-ACTIVE", ex);
        test_check_result ("ALL-ACTIVE", testAlerts, &reply, 0);

        reply = test_request_alerts_list (ui, "RESOLVED", ex);
        test_check_result ("RESOLVED", testAlerts, &reply, 0);

        reply = test_request_alerts_list (ui, "ACTIVE", ex);
        test_check_result ("ACTIVE", testAlerts, &reply, 0);

        reply = test_request_alerts_list (ui, "ACK-SILENCE", ex);
        test_check_result ("ACK-SILENCE", testAlerts, &reply, 0);
    }

    // change state (rfc-alerts-acknowledge)
    test_request_alerts_acknowledge (ui, consumer, "Threshold", "epdu", "ACK-WIP", testAlerts, 0);

    reply = test_request_alerts_list (ui, "ALL");
    test_check_result ("ALL", testAlerts, &reply, 0);

    reply = test_request_alerts_list (ui, "ALL-ACTIVE");
    test_check_result ("ALL-ACTIVE", testAlerts, &reply, 0);

    reply = test_request_alerts_list (ui, "RESOLVED");
    test_check_result ("RESOLVED", testAlerts, &reply, 0);

    reply = test_request_alerts_list (ui, "ACK-WIP");
    test_check_result ("ACK-WIP", testAlerts, &reply, 0);

    // change state back
    test_request_alerts_acknowledge (ui, consumer, "Threshold", "epdu", "ACTIVE", testAlerts, 0);

    reply = test_request_alerts_list (ui, "ALL");
    test_check_result ("ALL", testAlerts, &reply, 0);

    reply = test_request_alerts_list (ui, "ALL-ACTIVE");
    test_check_result ("ALL-ACTIVE", testAlerts, &reply, 0);

    reply = test_request_alerts_list (ui, "RESOLVED");
    test_check_result ("RESOLVED", testAlerts, &reply, 0);

    reply = test_request_alerts_list (ui, "ACTIVE");
    test_check_result ("ACTIVE", testAlerts, &reply, 0);

    // change state of two alerts
    test_request_alerts_acknowledge (ui, consumer, "Threshold", "ups", "ACK-PAUSE", testAlerts, 0);
    test_request_alerts_acknowledge (ui, consumer, "SimpleRule", "ups", "ACK-PAUSE", testAlerts, 0);

    reply = test_request_alerts_list (ui, "ALL");
    test_check_result ("ALL", testAlerts, &reply, 0);

    reply = test_request_alerts_list (ui, "ALL-ACTIVE");
    test_check_result ("ALL-ACTIVE", testAlerts, &reply, 0);

    reply = test_request_alerts_list (ui, "RESOLVED");
    test_check_result ("RESOLVED", testAlerts, &reply, 0);

    reply = test_request_alerts_list (ui, "ACK-PAUSE");
    test_check_result ("ACK-PAUSE", testAlerts, &reply, 0);

    reply = test_request_alerts_list (ui, "ACK-SILENCE");
    test_check_result ("ACK-SILENCE", testAlerts, &reply, 0);

    // some more state changes
    test_request_alerts_acknowledge (ui, consumer, "SimpleRule", "ups", "ACK-WIP", testAlerts, 0);
    test_request_alerts_acknowledge (ui, consumer, "Threshold", "ups", "ACK-SILENCE", testAlerts, 0);
    test_request_alerts_acknowledge (ui, consumer, "SimpleRule", "ŽlUťOučKý Kůň супер", "ACK-SILENCE", testAlerts, 0);
    test_request_alerts_acknowledge (ui, consumer, "Threshold", "epdu", "ACK-PAUSE", testAlerts, 0);
    // alerts/ack RESOLVED->anything must fail
    test_request_alerts_acknowledge (ui, consumer, "Threshold", "ŽlUťOUčKý Kůň супер", "ACTIVE", testAlerts, 1);
    test_request_alerts_acknowledge (ui, consumer, "Threshold", "ŽlUťOUčKý kůň супер", "ACK-WIP", testAlerts, 1);
    test_request_alerts_acknowledge (ui, consumer, "Threshold", "ŽLuťOUčKý kůň супер", "ACK-IGNORE", testAlerts, 1);
    test_request_alerts_acknowledge (ui, consumer, "Threshold", "ŽlUťOUčKý kůň супер", "ACK-SILENCE", testAlerts, 1);
    test_request_alerts_acknowledge (ui, consumer, "Threshold", "ŽlUťOUčKý kůň супер", "ACK-PAUSE", testAlerts, 1);

    reply = test_request_alerts_list (ui, "ALL");
    test_check_result ("ALL", testAlerts, &reply, 0);

    reply = test_request_alerts_list (ui, "ALL-ACTIVE");
    test_check_result ("ALL-ACTIVE", testAlerts, &reply, 0);

    reply = test_request_alerts_list (ui, "ACTIVE");
    test_check_result ("ACTIVE", testAlerts, &reply, 0);

    reply = test_request_alerts_list (ui, "ACK-WIP");
    test_check_result ("ACK-WIP", testAlerts, &reply, 0);

    reply = test_request_alerts_list (ui, "ACK-IGNORE");
    test_check_result ("ACK-IGNORE", testAlerts, &reply, 0);

    reply = test_request_alerts_list (ui, "ACK-PAUSE");
    test_check_result ("ACK-PAUSE", testAlerts, &reply, 0);

    reply = test_request_alerts_list (ui, "ACK-SILENCE");
    test_check_result ("ACK-SILENCE", testAlerts, &reply, 0);

    reply = test_request_alerts_list (ui, "RESOLVED");
    test_check_result ("RESOLVED", testAlerts, &reply, 0);

    // resolve alert
    zlist_t *actions6 = zlist_new ();
    zlist_autofree (actions6);
    zlist_append (actions6, (void *) "EMAIL");
    zlist_append (actions6, (void *) "SMS");
    alert = alert_new ("SimpleRule", "Žluťoučký kůň супер", "RESOLVED", "high", "description", 13, &actions6, 0);
    test_alert_publish (producer, consumer, testAlerts, &alert);

    reply = test_request_alerts_list (ui, "ALL");
    test_check_result ("ALL", testAlerts, &reply, 0);

    reply = test_request_alerts_list (ui, "ALL-ACTIVE");
    test_check_result ("ALL-ACTIVE", testAlerts, &reply, 0);

    reply = test_request_alerts_list (ui, "RESOLVED");
    test_check_result ("RESOLVED", testAlerts, &reply, 0);

    // test: For non-RESOLVED alerts timestamp of when first published is stored
    zlist_t *actions7 = zlist_new ();
    zlist_autofree (actions7);
    zlist_append (actions7, (void *) "EMAIL");
    zlist_append (actions7, (void *) "SMS");
    alert = alert_new ("#1549", "epdu", "ACTIVE", "high", "description", time (NULL), &actions7, 0);
    test_alert_publish (producer, consumer, testAlerts, &alert);

    reply = test_request_alerts_list (ui, "ALL");
    test_check_result ("ALL", testAlerts, &reply, 0);

    test_request_alerts_acknowledge (ui, consumer, "#1549", "epdu", "ACTIVE", testAlerts, 0);

    reply = test_request_alerts_list (ui, "ALL");
    test_check_result ("ALL", testAlerts, &reply, 0);

    test_request_alerts_acknowledge (ui, consumer, "#1549", "epdu", "ACTIVE", testAlerts, 0);

    reply = test_request_alerts_list (ui, "ALL");
    test_check_result ("ALL", testAlerts, &reply, 0);

    test_request_alerts_acknowledge (ui, consumer, "#1549", "epdu", "ACK-WIP", testAlerts, 0);

    reply = test_request_alerts_list (ui, "ALL");
    test_check_result ("ALL", testAlerts, &reply, 0);

    test_request_alerts_acknowledge (ui, consumer, "#1549", "epdu", "ACK-IGNORE", testAlerts, 0);

    reply = test_request_alerts_list (ui, "ALL");
    test_check_result ("ALL", testAlerts, &reply, 0);

    test_request_alerts_acknowledge (ui, consumer, "#1549", "epdu", "ACK-PAUSE", testAlerts, 0);

    reply = test_request_alerts_list (ui, "ALL");
    test_check_result ("ALL", testAlerts, &reply, 0);

    test_request_alerts_acknowledge (ui, consumer, "#1549", "epdu", "ACK-SILENCE", testAlerts, 0);

    reply = test_request_alerts_list (ui, "ALL");
    test_check_result ("ALL", testAlerts, &reply, 0);

    test_request_alerts_acknowledge (ui, consumer, "#1549", "epdu", "ACTIVE", testAlerts, 0);

    reply = test_request_alerts_list (ui, "ALL");
    test_check_result ("ALL", testAlerts, &reply, 0);

    reply = test_request_alerts_list (ui, "ACTIVE");
    test_check_result ("ACTIVE", testAlerts, &reply, 0);

    zlist_t *actions8 = zlist_new ();
    zlist_autofree (actions8);
    zlist_append (actions8, (void *) "EMAIL");
    zlist_append (actions8, (void *) "SMS");
    alert = alert_new ("#1549", "epdu", "RESOLVED", "high", "description", time (NULL) + 8, &actions8, 0);
    test_alert_publish (producer, consumer, testAlerts, &alert);

    reply = test_request_alerts_list (ui, "ALL");
    test_check_result ("ALL", testAlerts, &reply, 0);

    reply = test_request_alerts_list (ui, "ACTIVE");
    test_check_result ("ACTIVE", testAlerts, &reply, 0);

    reply = test_request_alerts_list (ui, "RESOLVED");
    test_check_result ("RESOLVED", testAlerts, &reply, 0);

    reply = test_request_alerts_list (ui, "ALL-ACTIVE");
    test_check_result ("ALL-ACTIVE", testAlerts, &reply, 0);

    zlist_t *actions9 = zlist_new ();
    zlist_autofree (actions9);
    zlist_append (actions9, (void *) "EMAIL");
    zlist_append (actions9, (void *) "SMS");
    alert = alert_new ("#1549", "epdu", "ACTIVE", "high", "description", time (NULL) + 9, &actions9, 0);
    test_alert_publish (producer, consumer, testAlerts, &alert);

    reply = test_request_alerts_list (ui, "ALL");
    test_check_result ("ALL", testAlerts, &reply, 0);

    reply = test_request_alerts_list (ui, "ACTIVE");
    test_check_result ("ACTIVE", testAlerts, &reply, 0);

    reply = test_request_alerts_list (ui, "RESOLVED");
    test_check_result ("RESOLVED", testAlerts, &reply, 0);

    reply = test_request_alerts_list (ui, "ALL-ACTIVE");
    test_check_result ("ALL-ACTIVE", testAlerts, &reply, 0);

    test_request_alerts_acknowledge (ui, consumer, "#1549", "epdu", "ACK-IGNORE", testAlerts, 0);

    reply = test_request_alerts_list (ui, "ALL");
    test_check_result ("ALL", testAlerts, &reply, 0);

    // Now, let's publish an alert as-a-byspass (i.e. we don't add it to expected)
    // and EXPECT A FAILURE (i.e. expected list != received list)
    zlist_t *actions10 = zlist_new ();
    zlist_autofree (actions10);
    zlist_append (actions10, (void *) "EMAIL");
    zlist_append (actions10, (void *) "SMS");
    zmsg_t *alert_bypass = fty_proto_encode_alert (NULL, 14, 0, "Pattern", "rack", "ACTIVE", "high", "description", actions10);
    rv = mlm_client_send (producer, "Nobody cares", &alert_bypass);
    assert (rv == 0);
    zclock_sleep (200);
    alert_bypass = mlm_client_recv (consumer);
    assert (alert_bypass);
    zmsg_destroy (&alert_bypass);

    reply = test_request_alerts_list (ui, "ALL");
    test_check_result ("ALL", testAlerts, &reply, 1);

    reply = test_request_alerts_list (ui, "ACTIVE");
    test_check_result ("ACTIVE", testAlerts, &reply, 1);

    reply = test_request_alerts_list (ui, "RESOLVED");
    test_check_result ("RESOLVED", testAlerts, &reply, 0);

    reply = test_request_alerts_list (ui, "ACK-WIP");
    test_check_result ("ACK-WIP", testAlerts, &reply, 0);

    reply = test_request_alerts_list (ui, "ALL-ACTIVE");
    test_check_result ("ALL-ACTIVE", testAlerts, &reply, 1);

    zlist_t *actions11 = zlist_new ();
    zlist_autofree (actions11);
    zlist_append (actions11, (void *) "EMAIL");
    zlist_append (actions11, (void *) "SMS");
    alert_bypass = fty_proto_encode_alert (NULL, 15, 0, "Pattern", "rack", "RESOLVED", "high", "description", actions11);
    mlm_client_send (producer, "Nobody cares", &alert_bypass);
    assert (rv == 0);
    zclock_sleep (100);
    alert_bypass = mlm_client_recv (consumer);
    assert (alert_bypass);
    zmsg_destroy (&alert_bypass);

    reply = test_request_alerts_list (ui, "ALL");
    test_check_result ("ALL", testAlerts, &reply, 1);

    reply = test_request_alerts_list (ui, "ACTIVE");
    test_check_result ("ACTIVE", testAlerts, &reply, 0);

    reply = test_request_alerts_list (ui, "RESOLVED");
    test_check_result ("RESOLVED", testAlerts, &reply, 1);

    reply = test_request_alerts_list (ui, "ACK-WIP");
    test_check_result ("ACK-WIP", testAlerts, &reply, 0);

    reply = test_request_alerts_list (ui, "ALL-ACTIVE");
    test_check_result ("ALL-ACTIVE", testAlerts, &reply, 0);

    zlist_t *actions12 = zlist_new ();
    zlist_autofree (actions12);
    zlist_append (actions12, (void *) "EMAIL");
    zlist_append (actions12, (void *) "SMS");
    alert = alert_new ("BlackBooks", "store", "ACTIVE", "high", "description", 16, &actions12, 2);
    test_alert_publish (producer, consumer, testAlerts, &alert);

    reply = test_request_alerts_list (ui, "ACTIVE");
    test_check_result ("ACTIVE", testAlerts, &reply, 0);

    // early cleanup should not change the alert
    zstr_send (fty_al_server_stream, "TTLCLEANUP");
    reply = test_request_alerts_list (ui, "ACTIVE");
    test_check_result ("ACTIVE", testAlerts, &reply, 0);

    zclock_sleep (3000);

    // cleanup should resolv alert
    zstr_send (fty_al_server_stream, "TTLCLEANUP");
    reply = test_request_alerts_list (ui, "RESOLVED");
    test_check_result ("RESOLVED", testAlerts, &reply, 1);

    // RESOLVED used to be an error response, but it's no more true
    zmsg_t *send = zmsg_new ();
    zmsg_addstr (send, "LIST");
    zmsg_addstr (send, "RESOLVED");
    rv = mlm_client_sendto (ui, "fty-alert-list", RFC_ALERTS_LIST_SUBJECT, NULL, 5000, &send);
    assert (rv == 0);
    reply = mlm_client_recv (ui);
    assert (streq (mlm_client_command (ui), "MAILBOX DELIVER"));
    assert (streq (mlm_client_sender (ui), "fty-alert-list"));
    assert (streq (mlm_client_subject (ui), RFC_ALERTS_LIST_SUBJECT));
    char *part = zmsg_popstr (reply);
    assert (streq (part, "LIST"));
    zstr_free (&part);
    part = zmsg_popstr (reply);
    assert (streq (part, "RESOLVED"));
    zstr_free (&part);
    zmsg_destroy (&reply);

    // Now, let's test an error response of rfc-alerts-list
    send = zmsg_new ();
    zmsg_addstr (send, "LIST");
    zmsg_addstr (send, "ACTIVE-ALL");
    rv = mlm_client_sendto (ui, "fty-alert-list", RFC_ALERTS_LIST_SUBJECT, NULL, 5000, &send);
    assert (rv == 0);
    reply = mlm_client_recv (ui);
    assert (streq (mlm_client_command (ui), "MAILBOX DELIVER"));
    assert (streq (mlm_client_sender (ui), "fty-alert-list"));
    assert (streq (mlm_client_subject (ui), RFC_ALERTS_LIST_SUBJECT));
    part = zmsg_popstr (reply);
    assert (streq (part, "ERROR"));
    zstr_free (&part);
    part = zmsg_popstr (reply);
    assert (streq (part, "NOT_FOUND"));
    zstr_free (&part);
    zmsg_destroy (&reply);

    send = zmsg_new ();
    zmsg_addstr (send, "LIST");
    zmsg_addstr (send, "Karolino");
    rv = mlm_client_sendto (ui, "fty-alert-list", RFC_ALERTS_LIST_SUBJECT, NULL, 5000, &send);
    assert (rv == 0);
    reply = mlm_client_recv (ui);
    assert (streq (mlm_client_command (ui), "MAILBOX DELIVER"));
    assert (streq (mlm_client_sender (ui), "fty-alert-list"));
    assert (streq (mlm_client_subject (ui), RFC_ALERTS_LIST_SUBJECT));
    part = zmsg_popstr (reply);
    assert (streq (part, "ERROR"));
    zstr_free (&part);
    part = zmsg_popstr (reply);
    assert (streq (part, "NOT_FOUND"));
    zstr_free (&part);
    zmsg_destroy (&reply);

    send = zmsg_new ();
    zmsg_addstr (send, "Hatatitla");
    zmsg_addstr (send, "Karolino");
    rv = mlm_client_sendto (ui, "fty-alert-list", RFC_ALERTS_LIST_SUBJECT, NULL, 5000, &send);
    zclock_sleep (100);
    assert (rv == 0);
    reply = mlm_client_recv (ui);
    assert (streq (mlm_client_command (ui), "MAILBOX DELIVER"));
    assert (streq (mlm_client_sender (ui), "fty-alert-list"));
    assert (streq (mlm_client_subject (ui), RFC_ALERTS_LIST_SUBJECT));
    part = zmsg_popstr (reply);
    assert (streq (part, "ERROR"));
    zstr_free (&part);
    part = zmsg_popstr (reply);
    assert (part);
    zstr_free (&part);
    zmsg_destroy (&reply);

    // Now, let's test an error response of rfc-alerts-acknowledge
    send = zmsg_new ();
    zmsg_addstr (send, "rule");
    zmsg_addstr (send, "element");
    zmsg_addstr (send, "state");
    rv = mlm_client_sendto (ui, "fty-alert-list", "sdfgrw rweg", NULL, 5000, &send);
    zclock_sleep (100);
    assert (rv == 0);
    reply = mlm_client_recv (ui);
    part = zmsg_popstr (reply);
    assert (streq (part, "ERROR"));
    zstr_free (&part);
    part = zmsg_popstr (reply);
    std::string err = TRANSLATE_ME ("UNKNOWN_PROTOCOL");
    assert (streq (part, err.c_str ()));
    zstr_free (&part);
    zmsg_destroy (&reply);

    send = zmsg_new ();
    zmsg_addstr (send, "rule");
    zmsg_addstr (send, "element");
    rv = mlm_client_sendto (ui, "fty-alert-list", RFC_ALERTS_ACKNOWLEDGE_SUBJECT, NULL, 5000, &send);
    zclock_sleep (100);
    assert (rv == 0);
    reply = mlm_client_recv (ui);
    part = zmsg_popstr (reply);
    assert (streq (part, "ERROR"));
    zstr_free (&part);
    part = zmsg_popstr (reply);
    err = TRANSLATE_ME ("BAD_MESSAGE");
    assert (streq (part, err.c_str ()));
    zstr_free (&part);
    zmsg_destroy (&reply);

    send = zmsg_new ();
    zmsg_addstr (send, "rule");
    zmsg_addstr (send, "element");
    zmsg_addstr (send, "ACTIVE");
    rv = mlm_client_sendto (ui, "fty-alert-list", RFC_ALERTS_ACKNOWLEDGE_SUBJECT, NULL, 5000, &send);
    zclock_sleep (100);
    assert (rv == 0);
    reply = mlm_client_recv (ui);
    part = zmsg_popstr (reply);
    assert (streq (part, "ERROR"));
    zstr_free (&part);
    part = zmsg_popstr (reply);
    assert (streq (part, "NOT_FOUND"));
    zstr_free (&part);
    zmsg_destroy (&reply);

    send = zmsg_new ();
    zmsg_addstr (send, "SimpleRule");
    zmsg_addstr (send, "ups");
    zmsg_addstr (send, "ignac!");
    rv = mlm_client_sendto (ui, "fty-alert-list", RFC_ALERTS_ACKNOWLEDGE_SUBJECT, NULL, 5000, &send);
    zclock_sleep (100);
    assert (rv == 0);
    reply = mlm_client_recv (ui);
    part = zmsg_popstr (reply);
    assert (streq (part, "ERROR"));
    zstr_free (&part);
    part = zmsg_popstr (reply);
    assert (streq (part, "BAD_STATE"));
    zstr_free (&part);
    zmsg_destroy (&reply);

    send = zmsg_new ();
    zmsg_addstr (send, "SimpleRule");
    zmsg_addstr (send, "ups");
    zmsg_addstr (send, "RESOLVED");
    rv = mlm_client_sendto (ui, "fty-alert-list", RFC_ALERTS_ACKNOWLEDGE_SUBJECT, NULL, 5000, &send);
    zclock_sleep (100);
    assert (rv == 0);
    reply = mlm_client_recv (ui);
    part = zmsg_popstr (reply);
    assert (streq (part, "ERROR"));
    zstr_free (&part);
    part = zmsg_popstr (reply);
    assert (streq (part, "BAD_STATE"));
    zstr_free (&part);
    zmsg_destroy (&reply);

    zlistx_destroy (&testAlerts);

    save_alerts ();
    zactor_destroy (&fty_al_server_mailbox);
    zactor_destroy (&fty_al_server_stream);
    mlm_client_destroy (&consumer);
    mlm_client_destroy (&producer);
    mlm_client_destroy (&ui);
    zactor_destroy (&server);
    destroy_alert ();

    if (NULL != actions1)
        zlist_destroy (&actions1);
    if (NULL != actions2)
        zlist_destroy (&actions2);
    if (NULL != actions3)
        zlist_destroy (&actions3);
    if (NULL != actions4)
        zlist_destroy (&actions4);
    if (NULL != actions5)
        zlist_destroy (&actions5);
    if (NULL != actions6)
        zlist_destroy (&actions6);
    if (NULL != actions7)
        zlist_destroy (&actions7);
    if (NULL != actions8)
        zlist_destroy (&actions8);
    if (NULL != actions9)
        zlist_destroy (&actions9);
    if (NULL != actions10)
        zlist_destroy (&actions10);
    if (NULL != actions11)
        zlist_destroy (&actions11);
    if (NULL != actions12)
        zlist_destroy (&actions12);

    printf ("OK\n");
}
