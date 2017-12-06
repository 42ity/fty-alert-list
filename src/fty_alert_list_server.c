/*  =========================================================================
    fty_alert_list_server - Providing information about active alerts

    Copyright (C) 2014 - 2017 Eaton

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
#include <string.h>
#include "fty_alert_list_classes.h"

#define RFC_ALERTS_LIST_SUBJECT "rfc-alerts-list"
#define RFC_ALERTS_ACKNOWLEDGE_SUBJECT  "rfc-alerts-acknowledge"

static const char *STATE_PATH = "/var/lib/fty/fty-alert-list";
static const char *STATE_FILE = "state_file";

static void
s_set_alert_lifetime (zhash_t *exp, fty_proto_t *msg)
{
    if (!exp || !msg) return;
    int64_t ttl = fty_proto_ttl (msg);
    if (!ttl) return;
    const char *rule = fty_proto_rule (msg);
    if (!rule) return;
    int64_t *time = (int64_t *) malloc (sizeof (int64_t));
    if (!time) return;
    *time = zclock_mono()/1000 + ttl;
    zhash_update (exp, rule, time);
    zsys_debug (" ##### rule %s with ttl %"PRIi64, rule, ttl);
    zhash_freefn (exp, rule, free);
}

static bool
s_alert_expired (zhash_t *exp, fty_proto_t *msg)
{
    if (!exp || !msg) return false;
    const char *rule = fty_proto_rule (msg);
    if (!rule) return false;
    int64_t *time = (int64_t *) zhash_lookup (exp, rule);
    if (!time) {
        return false;
    }
    return (*time < zclock_mono()/1000);
}

static void
s_clear_long_time_expired (zhash_t *exp) {
    if (!exp) return;

    zlist_t *keys = zhash_keys(exp);
    int64_t now = zclock_mono ()/1000;

    const char *rule = (char *)zlist_first (keys);
    while (rule) {
        int64_t *time = (int64_t *) zhash_lookup (exp, rule);
        if (*time < now - 3600) zhash_delete (exp, rule);
        rule = (char *)zlist_next (keys);
    }
    zlist_destroy (&keys);
}

static void
s_resolve_expired_alerts (zhash_t *exp, zlistx_t *alerts)
{
    if (!exp || !alerts) return;

    fty_proto_t *cursor = (fty_proto_t *) zlistx_first (alerts);

    while (cursor) {
        if (s_alert_expired (exp, cursor) && streq (fty_proto_state (cursor), "ACTIVE")) {
            fty_proto_set_state (cursor, "%s", "RESOLVED");
            zsys_info ("resolving alert:");
            fty_proto_print (cursor);
        }
        cursor = (fty_proto_t *) zlistx_next (alerts);
    }
    s_clear_long_time_expired (exp);
}

static void
s_handle_stream_deliver (mlm_client_t *client, zmsg_t** msg_p, zlistx_t *alerts, zhash_t *expirations) {
    assert (client);
    assert (msg_p);

    if (!is_fty_proto (*msg_p)) {
        zsys_error ("s_handle_stream_deliver (): Message not fty_proto");
        return;
    }

    fty_proto_t *alert = fty_proto_decode (msg_p);
    if (!alert || fty_proto_id (alert) != FTY_PROTO_ALERT) {
        fty_proto_destroy (&alert);
        zsys_warning ("s_handle_stream_deliver (): Message not FTY_PROTO_ALERT.");
        return;
    }
    if (!streq (fty_proto_state (alert), "ACTIVE") &&
        !streq (fty_proto_state (alert), "RESOLVED")) {
        fty_proto_destroy (&alert);
        zsys_warning ("s_handle_stream_deliver (): Message state not ACTIVE or RESOLVED. Not publishing any further.");
        return;
    }
    zsys_debug ("----> printing alert ");
    fty_proto_print (alert);
    fty_proto_t *cursor = (fty_proto_t *) zlistx_first (alerts);
    int found = 0;

    while (cursor) {
        if (alert_id_comparator (cursor, alert) == 0) {
            found = 1;
            break;
        }
        cursor = (fty_proto_t *) zlistx_next (alerts);
    }
    if (!found) {
        zlistx_add_end (alerts, alert);
        s_set_alert_lifetime (expirations, alert);
    }
    else {
        fty_proto_set_severity (cursor, "%s", fty_proto_severity (alert));
        fty_proto_set_description (cursor, "%s", fty_proto_description (alert));
        zlist_t *actions;
        if (NULL == fty_proto_action (alert)) {
            actions = zlist_new ();
            zlist_autofree (actions);
        } else {
            actions = zlist_dup (fty_proto_action (alert));
        }
        fty_proto_set_action (cursor, &actions);

        // Wasn't specified, but common sense applied, it should be:
        // RESOLVED comes from _ALERTS_SYS
        //  * if stored !RESOLVED -> update stored time/state, publish original
        //  * if stored RESOLVED -> don't update stored time, publish original
        //
        //  ACTIVE comes form _ALERTS_SYS
        //  * if stored ACTIVE -> don't update time, publish original
        //  * if stored RESOLVED -> update stored time/state, publish original
        //  * if stored ACK-XXX -> update original state, publish modified
        if (str_eq (fty_proto_state (alert), "RESOLVED")) {
            if (!str_eq (fty_proto_state (cursor), "RESOLVED")) {
                fty_proto_set_state (cursor, "%s", fty_proto_state (alert));
                fty_proto_set_time (cursor, fty_proto_time (alert));
            }
        }
        else { // state (alert) == ACTIVE
            s_set_alert_lifetime (expirations, alert);
            if (str_eq (fty_proto_state (cursor), "RESOLVED")) {
                fty_proto_set_state (cursor, "%s", fty_proto_state (alert));
                fty_proto_set_time (cursor, fty_proto_time (alert));
            }
            else if (!str_eq (fty_proto_state (cursor), "ACTIVE")) { // state (cursor) == ACK-XXX
                fty_proto_set_state (alert, "%s", fty_proto_state (cursor));
            }
        }
    }
    
    fty_proto_t *alert_dup = fty_proto_dup (alert);
    zmsg_t *encoded = fty_proto_encode (&alert_dup);
    assert (encoded);

    int rv = mlm_client_send (client, mlm_client_subject (client), &encoded);
    if (rv == -1) {
        zsys_error ("mlm_client_send (subject = '%s') failed",
                mlm_client_subject (client));
        zmsg_destroy (&encoded);
    }
    fty_proto_destroy (&alert);
}

static void
s_send_error_response (mlm_client_t *client, const char *subject, const char *reason) {
    assert (client);
    assert (subject);
    assert (reason);

    zmsg_t *reply  = zmsg_new ();
    assert (reply);

    zmsg_addstr (reply, "ERROR");
    zmsg_addstr (reply, reason);

    int rv = mlm_client_sendto (client, mlm_client_sender (client), subject, NULL, 5000, &reply);
    if (rv != 0) {
        zmsg_destroy (&reply);
        zsys_error (
                "mlm_client_sendto (sender = '%s', subject = '%s', timeout = '5000') failed.",
                mlm_client_sender (client), subject);
    }
}


static void
s_handle_rfc_alerts_list (mlm_client_t *client, zmsg_t **msg_p, zlistx_t *alerts) {
    assert (client);
    assert (msg_p && *msg_p);
    assert (alerts);

    zmsg_t *msg = *msg_p;
    char *command = zmsg_popstr (msg);
    if (!command || !str_eq (command, "LIST")) {
        free (command); command = NULL;
        zmsg_destroy (&msg);
        s_send_error_response (client, RFC_ALERTS_LIST_SUBJECT, "BAD_MESSAGE");
        return;
    }
    free (command); command = NULL;

    char *state = zmsg_popstr (msg);
    zmsg_destroy (msg_p);
    if (!state || !is_list_request_state (state)) {
        free (state); state = NULL;
        s_send_error_response (client, RFC_ALERTS_LIST_SUBJECT, "NOT_FOUND");
        return;
    }

    zmsg_t *reply = zmsg_new ();
    zmsg_addstr (reply, "LIST");
    zmsg_addstr (reply, state);
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
// FIXME: should we check and assert(nbytes>0) here, for both API versions,
// as we do in other similar cases?
#if CZMQ_VERSION_MAJOR == 3
            {
                byte *buffer = NULL;
                size_t nbytes = zmsg_encode (result, &buffer);
                frame = zframe_new ((void *) buffer, nbytes);
                free (buffer);
                buffer = NULL;
            }
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
    if (mlm_client_sendto (client, mlm_client_sender (client), RFC_ALERTS_LIST_SUBJECT, NULL, 5000, &reply) != 0) {
        zsys_error ("mlm_client_sendto (sender = '%s', subject = '%s', timeout = '5000') failed.",
                mlm_client_sender (client), RFC_ALERTS_LIST_SUBJECT);
    }
    free (state); state = NULL;
}


static void
s_handle_rfc_alerts_acknowledge (mlm_client_t *client, zmsg_t **msg_p, zlistx_t *alerts) {
    assert (client);
    assert (msg_p);
    assert (alerts);

    zmsg_t *msg = *msg_p;
    if (!msg)
        return;

    char *rule = zmsg_popstr (msg);
    if (!rule) {
        zmsg_destroy (&msg);
        s_send_error_response (client, RFC_ALERTS_ACKNOWLEDGE_SUBJECT, "BAD_MESSAGE");
        return;
    }
    char *element = zmsg_popstr (msg);
    if (!element) {
        zstr_free (&rule);
        zmsg_destroy (&msg);
        s_send_error_response (client, RFC_ALERTS_ACKNOWLEDGE_SUBJECT, "BAD_MESSAGE");
        return;
    }
    char *state = zmsg_popstr (msg);
    if (!state) {
        zstr_free (&rule);
        zstr_free (&element);
        zmsg_destroy (&msg);
        s_send_error_response (client, RFC_ALERTS_ACKNOWLEDGE_SUBJECT, "BAD_MESSAGE");
        return;
    }
    zmsg_destroy (&msg);
    // check 'state'
    if (!is_acknowledge_request_state (state)) {
        zsys_warning (
                "state '%s' is not an acknowledge request state according to protocol '%s'.",
                state, RFC_ALERTS_ACKNOWLEDGE_SUBJECT);
        zstr_free (&rule);
        zstr_free (&element);
        zstr_free (&state);
        s_send_error_response (client, RFC_ALERTS_ACKNOWLEDGE_SUBJECT, "BAD_STATE");
        return;
    }
    zsys_debug (
            "s_handle_rfc_alerts_acknowledge (): rule == '%s' element == '%s' state == '%s'",
            rule, element, state);
    // check ('rule', 'element') pair
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
        return;
    }
    if (str_eq (fty_proto_state (cursor), "RESOLVED")) {
        zstr_free (&rule);
        zstr_free (&element);
        zstr_free (&state);
        s_send_error_response (client, RFC_ALERTS_ACKNOWLEDGE_SUBJECT, "BAD_STATE");
        return;
    }
    // change stored alert state, don't change timestamp
    zsys_debug (
            "s_handle_rfc_alerts_acknowledge (): Changing state of (%s, %s) to %s",
            fty_proto_rule (cursor), fty_proto_name (cursor), state);
    fty_proto_set_state (cursor, "%s", state);

    zmsg_t *reply = zmsg_new ();
    zmsg_addstr (reply, "OK");
    zmsg_addstr (reply, rule);
    zmsg_addstr (reply, element);
    zmsg_addstr (reply, state);

    char *subject = zsys_sprintf (
            "%s/%s@%s",
            fty_proto_rule (cursor),
            fty_proto_severity (cursor),
            fty_proto_name (cursor));
    zstr_free (&rule);
    zstr_free (&element);
    zstr_free (&state);

    int rv = mlm_client_sendto (
            client, mlm_client_sender (client), RFC_ALERTS_ACKNOWLEDGE_SUBJECT, NULL, 5000, &reply);
    if (rv != 0) {
        zmsg_destroy (&reply);
        zsys_error (
                "mlm_client_sendto (sender = '%s', subject = '%s', timeout = '5000') failed.",
                mlm_client_sender (client), RFC_ALERTS_ACKNOWLEDGE_SUBJECT);
    }
    if (!subject) {
        zsys_error ("zsys_sprintf () failed");
        return;
    }
    uint64_t timestamp = (uint64_t) ((uint64_t) zclock_time () / 1000);
    fty_proto_t *copy = fty_proto_dup (cursor);
    if (!copy) {
        zsys_error ("fty_proto_dup () failed");
        zstr_free (&subject);
        return;
    }
    fty_proto_set_time (copy, timestamp);
    reply = fty_proto_encode (&copy);
    if (!reply) {
        zsys_error ("fty_proto_encode () failed");
        fty_proto_destroy (&copy);
        zstr_free (&subject);
        return;
    }
    rv = mlm_client_send (client, subject, &reply);
    if (rv != 0) {
        zmsg_destroy (&reply);
        zsys_error ("mlm_client_send (subject = '%s') failed", subject);
    }
    zstr_free (&subject);
}

static void
s_handle_mailbox_deliver (mlm_client_t *client, zmsg_t** msg_p, zlistx_t *alerts) {
    assert (client);
    assert (msg_p && *msg_p);
    assert (alerts);

    if (str_eq (mlm_client_subject (client), RFC_ALERTS_LIST_SUBJECT)) {
        s_handle_rfc_alerts_list (client, msg_p, alerts);
    }
    else
    if (str_eq (mlm_client_subject (client), RFC_ALERTS_ACKNOWLEDGE_SUBJECT)) {
        s_handle_rfc_alerts_acknowledge (client, msg_p, alerts);
    }
    else {
        s_send_error_response (client, mlm_client_subject (client), "UNKNOWN_PROTOCOL");
        zsys_error ("Unknown protocol. Subject: '%s', Sender: '%s'.",
            mlm_client_subject (client), mlm_client_sender (client));
        zmsg_destroy (msg_p);
    }
}

void
fty_alert_list_server (zsock_t *pipe, void *args)
{
    const char *endpoint = (const char *) args;
    zsys_debug ("endpoint = %s", endpoint);
    zlistx_t *alerts = zlistx_new ();
    zlistx_set_destructor (alerts, (czmq_destructor *) fty_proto_destroy);
    zlistx_set_duplicator (alerts, (czmq_duplicator *) fty_proto_dup);

    zhash_t *expirations = zhash_new ();

    mlm_client_t *client = mlm_client_new ();
    mlm_client_connect (client, endpoint, 1000, "fty-alert-list");
    mlm_client_set_consumer (client, "_ALERTS_SYS", ".*");
    mlm_client_set_producer (client, "ALERTS");

    int rv = alert_load_state (alerts, STATE_PATH, STATE_FILE);
    zsys_debug ("alert_load_state () == %d", rv);

    zpoller_t *poller = zpoller_new (pipe, mlm_client_msgpipe (client), NULL);
    zsock_signal (pipe, 0);

    while (!zsys_interrupted) {

        void *which = zpoller_wait (poller, -1);
        if (which == pipe) {
            zmsg_t *msg = zmsg_recv (pipe);
            char *cmd = zmsg_popstr (msg);
            if (streq (cmd, "$TERM")) {
                zstr_free (&cmd);
                zmsg_destroy (&msg);
                break;
            }
            else if (streq (cmd, "TTLCLEANUP")) {
                s_resolve_expired_alerts (expirations, alerts);
            }
            zstr_free (&cmd);
            zmsg_destroy (&msg);
        }
        else if (which == mlm_client_msgpipe (client)) {
            zmsg_t *msg = mlm_client_recv (client);
            if (!msg)
                break;
            if (str_eq (mlm_client_command (client), "MAILBOX DELIVER")) {
                s_handle_mailbox_deliver (client, &msg, alerts);
            }
            else if (str_eq (mlm_client_command (client), "STREAM DELIVER")) {
                s_handle_stream_deliver (client, &msg, alerts, expirations);
            }
            else {
                zsys_warning ("Unknown command '%s'. Subject: '%s', Sender: '%s'.",
                              mlm_client_command (client), mlm_client_subject (client), mlm_client_sender (client));
                zmsg_destroy (&msg);
            }
        }
    }

    rv = alert_save_state (alerts, STATE_PATH, STATE_FILE);
    zsys_debug ("alert_save_state () == %d", rv);

    mlm_client_destroy (&client);
    zpoller_destroy (&poller);
    zlistx_destroy (&alerts);
    zhash_destroy (&expirations);
}

//  --------------------------------------------------------------------------
//  Self test of this class.

// ---- Test Helper Functions

static void
test_print_zlistx (zlistx_t *list) {
    assert (list);
    fty_proto_t *cursor = (fty_proto_t *) zlistx_first (list);
    while (cursor) {
        zsys_debug ("| %-15s %-15s %-15s %-12s  %-12" PRIu64" count:%zu  %s  %s",
                fty_proto_rule (cursor),
                fty_proto_aux_string (cursor, FTY_PROTO_RULE_CLASS, ""),
                fty_proto_name (cursor),
                fty_proto_state (cursor),
                fty_proto_time (cursor),
                zlist_size (fty_proto_action (cursor)),
                fty_proto_severity (cursor),
                fty_proto_description (cursor));
        const char *actions = fty_proto_action_first(cursor);
        while (NULL != actions) {
            zsys_debug ("| %-15s %-15s %-15s %-12s  %-12" PRIu64" %s  %s  %s",
                    fty_proto_rule (cursor),
                    fty_proto_aux_string (cursor, FTY_PROTO_RULE_CLASS, ""),
                    fty_proto_name (cursor),
                    fty_proto_state (cursor),
                    fty_proto_time (cursor),
                    actions,
                    fty_proto_severity (cursor),
                    fty_proto_description (cursor));
            actions = fty_proto_action_next(cursor);
        }
        cursor = (fty_proto_t *) zlistx_next (list);
    }
}


static zmsg_t *
test_request_alerts_list (mlm_client_t *user_interface, const char *state) {
    assert (user_interface);
    assert (state);
    assert (is_list_request_state (state));

    zmsg_t *send = zmsg_new ();
    assert (send);
    zmsg_addstr (send, "LIST");
    zmsg_addstr (send, state);
    if (mlm_client_sendto (user_interface, "fty-alert-list", RFC_ALERTS_LIST_SUBJECT, NULL, 5000, &send) != 0) {
        zmsg_destroy (&send);
        zsys_error ("mlm_client_sendto (address = 'fty-alert-list', subject = '%s') failed.", RFC_ALERTS_LIST_SUBJECT);
        return NULL;
    }
    zmsg_t *reply = mlm_client_recv (user_interface);
    assert (str_eq (mlm_client_command (user_interface), "MAILBOX DELIVER"));
    assert (str_eq (mlm_client_sender (user_interface), "fty-alert-list"));
    assert (str_eq (mlm_client_subject (user_interface), RFC_ALERTS_LIST_SUBJECT));
    assert (reply);
    return reply;
}

static void
test_request_alerts_acknowledge (
        mlm_client_t *ui,
        mlm_client_t *consumer,
        const char *rule,
        const char *element,
        const char *state,
        zlistx_t *alerts,
        int expect_fail) {
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
        zsys_debug ("\t ALERTS published %s %s %s %" PRIu64" %s %s %s",
                fty_proto_rule (decoded),
                fty_proto_name (decoded),
                fty_proto_state (decoded),
                fty_proto_time (decoded),
                fty_proto_action (decoded),
                fty_proto_severity (decoded),
                fty_proto_description (decoded));
        assert (streq (rule, fty_proto_rule (decoded)));
        assert (utf8eq (element, fty_proto_name (decoded)) == 1 );
        assert (streq (state, fty_proto_state (decoded)));
        fty_proto_destroy (&decoded);
    }

    // Check protocol reply
    zmsg_t *reply = mlm_client_recv (ui);
    assert (str_eq (mlm_client_command (ui), "MAILBOX DELIVER"));
    assert (str_eq (mlm_client_sender (ui), "fty-alert-list"));
    assert (str_eq (mlm_client_subject (ui), RFC_ALERTS_ACKNOWLEDGE_SUBJECT));
    assert (reply);

    char *ok = zmsg_popstr (reply);
    if (expect_fail == 0) {
        char *rule_reply = zmsg_popstr (reply);
        char *element_reply = zmsg_popstr (reply);
        char *state_reply = zmsg_popstr (reply);
        assert (str_eq (ok, "OK"));
        assert (str_eq (rule_reply, rule));
        assert (utf8eq (element_reply, element));
        assert (str_eq (state_reply, state));
        zstr_free (&rule_reply);
        zstr_free (&element_reply);
        zstr_free (&state_reply);
        assert (found == 1);
    }
    else {
        assert (str_eq (ok, "ERROR"));
        char *reason = zmsg_popstr (reply);
        assert (str_eq (reason, "BAD_STATE") || str_eq (reason, "NOT_FOUND"));
        if (str_eq (reason, "BAD_STATE")) {
            assert (found == 1);
        }
        else if (str_eq (reason, "NOT_FOUND")) {
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
            if (!handle)
                return 0;
            zlistx_delete (received, handle);
        }
        cursor = (fty_proto_t *) zlistx_next (expected);
    }
    if (zlistx_size (received) != 0)
        return 0;
    return 1;
}

static void
test_check_result (const char *state, zlistx_t *expected, zmsg_t **reply_p, int fail) {
    assert (state);
    assert (expected);
    assert (reply_p);
    if (!*reply_p)
        return;
    zmsg_t *reply = *reply_p;
    // check leading protocol frames (strings)
    char *part = zmsg_popstr (reply);
    assert (str_eq (part, "LIST"));
    free (part); part = NULL;
    part = zmsg_popstr (reply);
    assert (str_eq (part, state));
    free (part); part = NULL;

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

    zsys_debug ("=====================================================");
    zsys_debug (" REQUESTED LIST STATE == '%s'    SHOULD FAIL == '%s'", state, fail == 0 ? "NO" : "YES");
    zsys_debug ("-----    EXPECTED    --------------------------------");
    test_print_zlistx (expected);
    zsys_debug ("-----    RECEIVED    --------------------------------");
    test_print_zlistx (received);
    zsys_debug ("");

    // compare the two by iterative substraction
    int rv = test_zlistx_same (state, expected, received);
    if (fail) {
        assert (rv == 0);
    }
    else {
        assert (rv == 1);
    }
    zlistx_destroy (&received);
    zmsg_destroy (reply_p);
}

static void
test_alert_publish (
        mlm_client_t *producer,
        mlm_client_t *consumer,
        zlistx_t *alerts,
        fty_proto_t **message)
{
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
        fty_proto_set_description (item,"%s",  fty_proto_description (*message));
        zlist_t *actions;
        if (NULL == fty_proto_action (*message)) {
            actions = zlist_new ();
            zlist_autofree (actions);
        } else {
            actions = zlist_dup (fty_proto_action (*message));
        }
        fty_proto_set_action (item, &actions);

        if (str_eq (fty_proto_state (*message), "RESOLVED")) {
            if (!str_eq (fty_proto_state (item), "RESOLVED")) {
                fty_proto_set_state (item, "%s", fty_proto_state (*message));
                fty_proto_set_time (item, fty_proto_time (*message));
            }
        }
        else {
            if (str_eq (fty_proto_state (item), "RESOLVED")) {
                fty_proto_set_state (item, "%s", fty_proto_state (*message));
                fty_proto_set_time (item, fty_proto_time (*message));
            }
            else if (!str_eq (fty_proto_state (item), "ACTIVE")) {
                fty_proto_set_state (*message, "%s", fty_proto_state (item));
            }
        }
    }
    else {
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
fty_alert_list_server_test (bool verbose)
{

    static const char* endpoint = "inproc://fty-lm-server-test";

    //  @selftest

    printf (" * fty_alerts_list_server: ");

    // Malamute
    zactor_t *server = zactor_new (mlm_server, "Malamute");
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

    // Alert List
    zactor_t *fty_al_server = zactor_new (fty_alert_list_server, (void *) endpoint);

    // maintain a list of active alerts (that serves as "expected results")
    zlistx_t *alerts = zlistx_new ();
    zlistx_set_destructor (alerts, (czmq_destructor *) fty_proto_destroy);
    zlistx_set_duplicator (alerts, (czmq_duplicator *) fty_proto_dup);
    zlistx_set_comparator (alerts, (czmq_comparator *) alert_id_comparator);

    zmsg_t *reply = test_request_alerts_list (ui, "ALL");
    assert (reply);
    test_check_result ("ALL", alerts, &reply, 0);

    reply = test_request_alerts_list (ui, "ACK-WIP");
    test_check_result ("ACK-WIP", alerts, &reply, 0);

    reply = test_request_alerts_list (ui, "ACK-IGNORE");
    test_check_result ("ACK-IGNORE", alerts, &reply, 0);

    reply = test_request_alerts_list (ui, "ALL-ACTIVE");
    test_check_result ("ALL-ACTIVE", alerts, &reply, 0);

    reply = test_request_alerts_list (ui, "RESOLVED");
    test_check_result ("RESOLVED", alerts, &reply, 0);

    // add new alert
    zlist_t *actions1 = zlist_new ();
    zlist_autofree (actions1);
    zlist_append(actions1, "EMAIL");
    zlist_append(actions1, "SMS");
    fty_proto_t *alert = alert_new ("Threshold", "ups", "ACTIVE", "high", "description", 1, &actions1, 0);
    test_alert_publish (producer, consumer, alerts, &alert);

    reply = test_request_alerts_list (ui, "ALL");
    test_check_result ("ALL", alerts, &reply, 0);

    reply = test_request_alerts_list (ui, "ACK-PAUSE");
    test_check_result ("ACK-PAUSE", alerts, &reply, 0);

    reply = test_request_alerts_list (ui, "ALL-ACTIVE");
    test_check_result ("ALL-ACTIVE", alerts, &reply, 0);

    reply = test_request_alerts_list (ui, "RESOLVED");
    test_check_result ("RESOLVED", alerts, &reply, 0);

    reply = test_request_alerts_list (ui, "ACTIVE");
    test_check_result ("ACTIVE", alerts, &reply, 0);

    // add new alert
    zlist_t *actions2 = zlist_new ();
    zlist_autofree (actions2);
    zlist_append(actions2, "EMAIL");
    zlist_append(actions2, "SMS");
    alert = alert_new ("Threshold", "epdu", "ACTIVE", "high", "description", 2, &actions2, 0);
    test_alert_publish (producer, consumer, alerts, &alert);

    reply = test_request_alerts_list (ui, "ALL");
    test_check_result ("ALL", alerts, &reply, 0);

    reply = test_request_alerts_list (ui, "ACTIVE");
    test_check_result ("ACTIVE", alerts, &reply, 0);

    // add new alert
    zlist_t *actions3 = zlist_new ();
    zlist_autofree (actions3);
    zlist_append(actions3, "EMAIL");
    zlist_append(actions3, "SMS");
    alert = alert_new ("SimpleRule", "ups", "ACTIVE", "high", "description", 3, &actions3, 0);
    test_alert_publish (producer, consumer, alerts, &alert);

    reply = test_request_alerts_list (ui, "ALL");
    test_check_result ("ALL", alerts, &reply, 0);

    reply = test_request_alerts_list (ui, "ACTIVE");
    test_check_result ("ACTIVE", alerts, &reply, 0);

    // add new alert
    zlist_t *actions4 = zlist_new ();
    zlist_autofree (actions4);
    zlist_append(actions4, "EMAIL");
    zlist_append(actions4, "SMS");
    alert = alert_new ("SimpleRule", "ŽlUťOUčKý kůň супер", "ACTIVE", "high", "description", 4, &actions4, 0);
    test_alert_publish (producer, consumer, alerts, &alert);

    reply = test_request_alerts_list (ui, "ALL");
    test_check_result ("ALL", alerts, &reply, 0);

    reply = test_request_alerts_list (ui, "ACTIVE");
    test_check_result ("ACTIVE", alerts, &reply, 0);

    reply = test_request_alerts_list (ui, "ALL-ACTIVE");
    test_check_result ("ALL-ACTIVE", alerts, &reply, 0);

    reply = test_request_alerts_list (ui, "RESOLVED");
    test_check_result ("RESOLVED", alerts, &reply, 0);

    // add new alert
    zlist_t *actions5 = zlist_new ();
    zlist_autofree (actions5);
    zlist_append(actions5, "EMAIL");
    zlist_append(actions5, "SMS");
    alert = alert_new ("Threshold", "ŽlUťOUčKý kůň супер", "RESOLVED", "high", "description", 4, &actions5, 0);
    test_alert_publish (producer, consumer, alerts, &alert);

    reply = test_request_alerts_list (ui, "ALL");
    test_check_result ("ALL", alerts, &reply, 0);

    reply = test_request_alerts_list (ui, "ALL-ACTIVE");
    test_check_result ("ALL-ACTIVE", alerts, &reply, 0);

    reply = test_request_alerts_list (ui, "RESOLVED");
    test_check_result ("RESOLVED", alerts, &reply, 0);

    reply = test_request_alerts_list (ui, "ACTIVE");
    test_check_result ("ACTIVE", alerts, &reply, 0);

    reply = test_request_alerts_list (ui, "ACK-SILENCE");
    test_check_result ("ACK-SILENCE", alerts, &reply, 0);

    // change state (rfc-alerts-acknowledge)
    test_request_alerts_acknowledge (ui, consumer, "Threshold", "epdu", "ACK-WIP", alerts, 0);

    reply = test_request_alerts_list (ui, "ALL");
    test_check_result ("ALL", alerts, &reply, 0);

    reply = test_request_alerts_list (ui, "ALL-ACTIVE");
    test_check_result ("ALL-ACTIVE", alerts, &reply, 0);

    reply = test_request_alerts_list (ui, "RESOLVED");
    test_check_result ("RESOLVED", alerts, &reply, 0);

    reply = test_request_alerts_list (ui, "ACK-WIP");
    test_check_result ("ACK-WIP", alerts, &reply, 0);

    // change state back
    test_request_alerts_acknowledge (ui, consumer, "Threshold", "epdu", "ACTIVE", alerts, 0);

    reply = test_request_alerts_list (ui, "ALL");
    test_check_result ("ALL", alerts, &reply, 0);

    reply = test_request_alerts_list (ui, "ALL-ACTIVE");
    test_check_result ("ALL-ACTIVE", alerts, &reply, 0);

    reply = test_request_alerts_list (ui, "RESOLVED");
    test_check_result ("RESOLVED", alerts, &reply, 0);

    reply = test_request_alerts_list (ui, "ACTIVE");
    test_check_result ("ACTIVE", alerts, &reply, 0);

    // change state of two alerts
    test_request_alerts_acknowledge (ui, consumer, "Threshold", "ups", "ACK-PAUSE", alerts, 0);
    test_request_alerts_acknowledge (ui, consumer, "SimpleRule", "ups", "ACK-PAUSE", alerts, 0);

    reply = test_request_alerts_list (ui, "ALL");
    test_check_result ("ALL", alerts, &reply, 0);

    reply = test_request_alerts_list (ui, "ALL-ACTIVE");
    test_check_result ("ALL-ACTIVE", alerts, &reply, 0);

    reply = test_request_alerts_list (ui, "RESOLVED");
    test_check_result ("RESOLVED", alerts, &reply, 0);

    reply = test_request_alerts_list (ui, "ACK-PAUSE");
    test_check_result ("ACK-PAUSE", alerts, &reply, 0);

    reply = test_request_alerts_list (ui, "ACK-SILENCE");
    test_check_result ("ACK-SILENCE", alerts, &reply, 0);

    // some more state changes
    test_request_alerts_acknowledge (ui, consumer, "SimpleRule", "ups", "ACK-WIP", alerts, 0);
    test_request_alerts_acknowledge (ui, consumer, "Threshold", "ups", "ACK-SILENCE", alerts, 0);
    test_request_alerts_acknowledge (ui, consumer, "SimpleRule", "ŽlUťOučKý Kůň супер", "ACK-SILENCE", alerts, 0);
    test_request_alerts_acknowledge (ui, consumer, "Threshold", "epdu", "ACK-PAUSE", alerts, 0);
    // alerts/ack RESOLVED->anything must fail
    test_request_alerts_acknowledge (ui, consumer, "Threshold", "ŽlUťOUčKý Kůň супер", "ACTIVE", alerts, 1);
    test_request_alerts_acknowledge (ui, consumer, "Threshold", "ŽlUťOUčKý kůň супер", "ACK-WIP", alerts, 1);
    test_request_alerts_acknowledge (ui, consumer, "Threshold", "ŽLuťOUčKý kůň супер", "ACK-IGNORE", alerts, 1);
    test_request_alerts_acknowledge (ui, consumer, "Threshold", "ŽlUťOUčKý kůň супер", "ACK-SILENCE", alerts, 1);
    test_request_alerts_acknowledge (ui, consumer, "Threshold", "ŽlUťOUčKý kůň супер", "ACK-PAUSE", alerts, 1);

    reply = test_request_alerts_list (ui, "ALL");
    test_check_result ("ALL", alerts, &reply, 0);

    reply = test_request_alerts_list (ui, "ALL-ACTIVE");
    test_check_result ("ALL-ACTIVE", alerts, &reply, 0);

    reply = test_request_alerts_list (ui, "ACTIVE");
    test_check_result ("ACTIVE", alerts, &reply, 0);

    reply = test_request_alerts_list (ui, "ACK-WIP");
    test_check_result ("ACK-WIP", alerts, &reply, 0);

    reply = test_request_alerts_list (ui, "ACK-IGNORE");
    test_check_result ("ACK-IGNORE", alerts, &reply, 0);

    reply = test_request_alerts_list (ui, "ACK-PAUSE");
    test_check_result ("ACK-PAUSE", alerts, &reply, 0);

    reply = test_request_alerts_list (ui, "ACK-SILENCE");
    test_check_result ("ACK-SILENCE", alerts, &reply, 0);

    reply = test_request_alerts_list (ui, "RESOLVED");
    test_check_result ("RESOLVED", alerts, &reply, 0);

    // resolve alert
    zlist_t *actions6 = zlist_new ();
    zlist_autofree (actions6);
    zlist_append(actions6, "EMAIL");
    zlist_append(actions6, "SMS");
    alert = alert_new ("SimpleRule", "Žluťoučký kůň супер", "RESOLVED", "high", "description", 13, &actions6, 0);
    test_alert_publish (producer, consumer, alerts, &alert);

    reply = test_request_alerts_list (ui, "ALL");
    test_check_result ("ALL", alerts, &reply, 0);

    reply = test_request_alerts_list (ui, "ALL-ACTIVE");
    test_check_result ("ALL-ACTIVE", alerts, &reply, 0);

    reply = test_request_alerts_list (ui, "RESOLVED");
    test_check_result ("RESOLVED", alerts, &reply, 0);

    // test: For non-RESOLVED alerts timestamp of when first published is stored
    zlist_t *actions7 = zlist_new ();
    zlist_autofree (actions7);
    zlist_append(actions7, "EMAIL");
    zlist_append(actions7, "SMS");
    alert = alert_new ("#1549", "epdu", "ACTIVE", "high", "description", time (NULL), &actions7, 0);
    test_alert_publish (producer, consumer, alerts, &alert);

    reply = test_request_alerts_list (ui, "ALL");
    test_check_result ("ALL", alerts, &reply, 0);

    test_request_alerts_acknowledge (ui, consumer, "#1549", "epdu", "ACTIVE", alerts, 0);

    reply = test_request_alerts_list (ui, "ALL");
    test_check_result ("ALL", alerts, &reply, 0);

    test_request_alerts_acknowledge (ui, consumer, "#1549", "epdu", "ACTIVE", alerts, 0);

    reply = test_request_alerts_list (ui, "ALL");
    test_check_result ("ALL", alerts, &reply, 0);

    test_request_alerts_acknowledge (ui, consumer, "#1549", "epdu", "ACK-WIP", alerts, 0);

    reply = test_request_alerts_list (ui, "ALL");
    test_check_result ("ALL", alerts, &reply, 0);

    test_request_alerts_acknowledge (ui, consumer, "#1549", "epdu", "ACK-IGNORE", alerts, 0);

    reply = test_request_alerts_list (ui, "ALL");
    test_check_result ("ALL", alerts, &reply, 0);

    test_request_alerts_acknowledge (ui, consumer, "#1549", "epdu", "ACK-PAUSE", alerts, 0);

    reply = test_request_alerts_list (ui, "ALL");
    test_check_result ("ALL", alerts, &reply, 0);

    test_request_alerts_acknowledge (ui, consumer, "#1549", "epdu", "ACK-SILENCE", alerts, 0);

    reply = test_request_alerts_list (ui, "ALL");
    test_check_result ("ALL", alerts, &reply, 0);

    test_request_alerts_acknowledge (ui, consumer, "#1549", "epdu", "ACTIVE", alerts, 0);

    reply = test_request_alerts_list (ui, "ALL");
    test_check_result ("ALL", alerts, &reply, 0);

    reply = test_request_alerts_list (ui, "ACTIVE");
    test_check_result ("ACTIVE", alerts, &reply, 0);

    zlist_t *actions8 = zlist_new ();
    zlist_autofree (actions8);
    zlist_append(actions8, "EMAIL");
    zlist_append(actions8, "SMS");
    alert = alert_new ("#1549", "epdu", "RESOLVED", "high", "description", time (NULL) + 8, &actions8, 0);
    test_alert_publish (producer, consumer, alerts, &alert);

    reply = test_request_alerts_list (ui, "ALL");
    test_check_result ("ALL", alerts, &reply, 0);

    reply = test_request_alerts_list (ui, "ACTIVE");
    test_check_result ("ACTIVE", alerts, &reply, 0);

    reply = test_request_alerts_list (ui, "RESOLVED");
    test_check_result ("RESOLVED", alerts, &reply, 0);

    reply = test_request_alerts_list (ui, "ALL-ACTIVE");
    test_check_result ("ALL-ACTIVE", alerts, &reply, 0);

    zlist_t *actions9 = zlist_new ();
    zlist_autofree (actions9);
    zlist_append(actions9, "EMAIL");
    zlist_append(actions9, "SMS");
    alert = alert_new ("#1549", "epdu", "ACTIVE", "high", "description", time (NULL) + 9, &actions9, 0);
    test_alert_publish (producer, consumer, alerts, &alert);

    reply = test_request_alerts_list (ui, "ALL");
    test_check_result ("ALL", alerts, &reply, 0);

    reply = test_request_alerts_list (ui, "ACTIVE");
    test_check_result ("ACTIVE", alerts, &reply, 0);

    reply = test_request_alerts_list (ui, "RESOLVED");
    test_check_result ("RESOLVED", alerts, &reply, 0);

    reply = test_request_alerts_list (ui, "ALL-ACTIVE");
    test_check_result ("ALL-ACTIVE", alerts, &reply, 0);

    test_request_alerts_acknowledge (ui, consumer, "#1549", "epdu", "ACK-IGNORE", alerts, 0);

    reply = test_request_alerts_list (ui, "ALL");
    test_check_result ("ALL", alerts, &reply, 0);

    // Now, let's publish an alert as-a-byspass (i.e. we don't add it to expected)
    // and EXPECT A FAILURE (i.e. expected list != received list)
    zlist_t *actions10 = zlist_new ();
    zlist_autofree (actions10);
    zlist_append(actions10, "EMAIL");
    zlist_append(actions10, "SMS");
    zmsg_t *alert_bypass = fty_proto_encode_alert (NULL, 14, 0, "Pattern", "rack", "ACTIVE", "high", "description", actions10);
    rv = mlm_client_send (producer, "Nobody cares", &alert_bypass);
    assert (rv == 0);
    zclock_sleep (200);
    alert_bypass = mlm_client_recv (consumer);
    assert (alert_bypass);
    zmsg_destroy (&alert_bypass);

    reply = test_request_alerts_list (ui, "ALL");
    test_check_result ("ALL", alerts, &reply, 1);

    reply = test_request_alerts_list (ui, "ACTIVE");
    test_check_result ("ACTIVE", alerts, &reply, 1);

    reply = test_request_alerts_list (ui, "RESOLVED");
    test_check_result ("RESOLVED", alerts, &reply, 0);

    reply = test_request_alerts_list (ui, "ACK-WIP");
    test_check_result ("ACK-WIP", alerts, &reply, 0);

    reply = test_request_alerts_list (ui, "ALL-ACTIVE");
    test_check_result ("ALL-ACTIVE", alerts, &reply, 1);

    zlist_t *actions11 = zlist_new ();
    zlist_autofree (actions11);
    zlist_append(actions11, "EMAIL");
    zlist_append(actions11, "SMS");
    alert_bypass = fty_proto_encode_alert (NULL, 15, 0, "Pattern", "rack", "RESOLVED", "high", "description", actions11);
    mlm_client_send (producer, "Nobody cares", &alert_bypass);
    assert (rv == 0);
    zclock_sleep (100);
    alert_bypass = mlm_client_recv (consumer);
    assert (alert_bypass);
    zmsg_destroy (&alert_bypass);

    reply = test_request_alerts_list (ui, "ALL");
    test_check_result ("ALL", alerts, &reply, 1);

    reply = test_request_alerts_list (ui, "ACTIVE");
    test_check_result ("ACTIVE", alerts, &reply, 0);

    reply = test_request_alerts_list (ui, "RESOLVED");
    test_check_result ("RESOLVED", alerts, &reply, 1);

    reply = test_request_alerts_list (ui, "ACK-WIP");
    test_check_result ("ACK-WIP", alerts, &reply, 0);

    reply = test_request_alerts_list (ui, "ALL-ACTIVE");
    test_check_result ("ALL-ACTIVE", alerts, &reply, 0);

    zlist_t *actions12 = zlist_new ();
    zlist_autofree (actions12);
    zlist_append(actions12, "EMAIL");
    zlist_append(actions12, "SMS");
    alert = alert_new ("BlackBooks", "store", "ACTIVE", "high", "description", 16, &actions12, 2);
    test_alert_publish (producer, consumer, alerts, &alert);

    reply = test_request_alerts_list (ui, "ACTIVE");
    test_check_result ("ACTIVE", alerts, &reply, 0);

    // early cleanup should not change the alert
    zstr_send (fty_al_server, "TTLCLEANUP");
    reply = test_request_alerts_list (ui, "ACTIVE");
    test_check_result ("ACTIVE", alerts, &reply, 0);

    zclock_sleep (3000);

    // cleanup should resolv alert
    zstr_send (fty_al_server, "TTLCLEANUP");
    reply = test_request_alerts_list (ui, "RESOLVED");
    test_check_result ("RESOLVED", alerts, &reply, 1);


    // RESOLVED used to be an error response, but it's no more true
    zmsg_t *send = zmsg_new ();
    zmsg_addstr (send, "LIST");
    zmsg_addstr (send, "RESOLVED");
    rv = mlm_client_sendto (ui, "fty-alert-list", RFC_ALERTS_LIST_SUBJECT, NULL, 5000, &send);
    assert (rv == 0);
    reply = mlm_client_recv (ui);
    assert (str_eq (mlm_client_command (ui), "MAILBOX DELIVER"));
    assert (str_eq (mlm_client_sender (ui), "fty-alert-list"));
    assert (str_eq (mlm_client_subject (ui), RFC_ALERTS_LIST_SUBJECT));
    char *part = zmsg_popstr (reply);
    assert (str_eq (part, "LIST"));
    zstr_free (&part);
    part = zmsg_popstr (reply);
    assert (str_eq (part, "RESOLVED"));
    zstr_free (&part);
    zmsg_destroy (&reply);

    // Now, let's test an error response of rfc-alerts-list
    send = zmsg_new ();
    zmsg_addstr (send, "LIST");
    zmsg_addstr (send, "ACTIVE-ALL");
    rv = mlm_client_sendto (ui, "fty-alert-list", RFC_ALERTS_LIST_SUBJECT, NULL, 5000, &send);
    assert (rv == 0);
    reply = mlm_client_recv (ui);
    assert (str_eq (mlm_client_command (ui), "MAILBOX DELIVER"));
    assert (str_eq (mlm_client_sender (ui), "fty-alert-list"));
    assert (str_eq (mlm_client_subject (ui), RFC_ALERTS_LIST_SUBJECT));
    part = zmsg_popstr (reply);
    assert (str_eq (part, "ERROR"));
    zstr_free (&part);
    part = zmsg_popstr (reply);
    assert (str_eq (part, "NOT_FOUND"));
    zstr_free (&part);
    zmsg_destroy (&reply);

    send = zmsg_new ();
    zmsg_addstr (send, "LIST");
    zmsg_addstr (send, "Karolino");
    rv = mlm_client_sendto (ui, "fty-alert-list", RFC_ALERTS_LIST_SUBJECT, NULL, 5000, &send);
    assert (rv == 0);
    reply = mlm_client_recv (ui);
    assert (str_eq (mlm_client_command (ui), "MAILBOX DELIVER"));
    assert (str_eq (mlm_client_sender (ui), "fty-alert-list"));
    assert (str_eq (mlm_client_subject (ui), RFC_ALERTS_LIST_SUBJECT));
    part = zmsg_popstr (reply);
    assert (str_eq (part, "ERROR"));
    zstr_free (&part);
    part = zmsg_popstr (reply);
    assert (str_eq (part, "NOT_FOUND"));
    zstr_free (&part);
    zmsg_destroy (&reply);

    send = zmsg_new ();
    zmsg_addstr (send, "Hatatitla");
    zmsg_addstr (send, "Karolino");
    rv = mlm_client_sendto (ui, "fty-alert-list", RFC_ALERTS_LIST_SUBJECT, NULL, 5000, &send);
    zclock_sleep (100);
    assert (rv == 0);
    reply = mlm_client_recv (ui);
    assert (str_eq (mlm_client_command (ui), "MAILBOX DELIVER"));
    assert (str_eq (mlm_client_sender (ui), "fty-alert-list"));
    assert (str_eq (mlm_client_subject (ui), RFC_ALERTS_LIST_SUBJECT));
    part = zmsg_popstr (reply);
    assert (str_eq (part, "ERROR"));
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
    assert (str_eq (part, "ERROR"));
    zstr_free (&part);
    part = zmsg_popstr (reply);
    assert (str_eq (part, "UNKNOWN_PROTOCOL"));
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
    assert (str_eq (part, "ERROR"));
    zstr_free (&part);
    part = zmsg_popstr (reply);
    assert (str_eq (part, "BAD_MESSAGE"));
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
    assert (str_eq (part, "ERROR"));
    zstr_free (&part);
    part = zmsg_popstr (reply);
    assert (str_eq (part, "NOT_FOUND"));
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
    assert (str_eq (part, "ERROR"));
    zstr_free (&part);
    part = zmsg_popstr (reply);
    assert (str_eq (part, "BAD_STATE"));
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
    assert (str_eq (part, "ERROR"));
    zstr_free (&part);
    part = zmsg_popstr (reply);
    assert (str_eq (part, "BAD_STATE"));
    zstr_free (&part);
    zmsg_destroy (&reply);

    zlistx_destroy (&alerts);

    mlm_client_destroy (&ui);
    mlm_client_destroy (&producer);
    mlm_client_destroy (&consumer);

    zactor_destroy (&fty_al_server);
    zactor_destroy (&server);


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
