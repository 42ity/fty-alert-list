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

/// fty_alert_list_server - Providing information about active alerts

#include "fty_alert_list_server.h"
#include <map>
#include <mutex>
#include <string.h>
#include <fty_proto.h>
#include <fty_log.h>
#include <fty_common.h>
#include <malamute.h>
#include "alerts_utils.h"

#define RFC_ALERTS_LIST_SUBJECT        "rfc-alerts-list"
#define RFC_ALERTS_ACKNOWLEDGE_SUBJECT "rfc-alerts-acknowledge"

static const char* STATE_PATH = "/var/lib/fty/fty-alert-list";
static const char* STATE_FILE = "state_file";

static zlistx_t*                      alerts = nullptr;
static std::map<fty_proto_t*, time_t> alertsLastSent;
static std::mutex                     alertMtx;
static bool                           verbose = false;

static void s_set_alert_lifetime(zhash_t* exp, fty_proto_t* msg)
{
    if (!exp || !msg)
        return;

    int64_t ttl = fty_proto_ttl(msg);
    if (!ttl)
        return;
    const char* rule = fty_proto_rule(msg);
    if (!rule)
        return;
    int64_t* time = reinterpret_cast<int64_t*>(malloc(sizeof(int64_t)));
    if (!time)
        return;

    *time = zclock_mono() / 1000 + ttl;
    zhash_update(exp, rule, time);
    log_debug(" ##### rule %s with ttl %" PRIi64, rule, ttl);
    zhash_freefn(exp, rule, free);
}

static bool s_alert_expired(zhash_t* exp, fty_proto_t* msg)
{
    if (!exp || !msg)
        return false;

    const char* rule = fty_proto_rule(msg);
    if (!rule)
        return false;

    int64_t* time = reinterpret_cast<int64_t*>(zhash_lookup(exp, rule));
    if (!time) {
        return false;
    }
    return (*time < zclock_mono() / 1000);
}

static void s_clear_long_time_expired(zhash_t* exp)
{
    if (!exp)
        return;

    zlist_t* keys = zhash_keys(exp);
    int64_t  now  = zclock_mono() / 1000;

    const char* rule = reinterpret_cast<char*>(zlist_first(keys));
    while (rule) {
        int64_t* time = reinterpret_cast<int64_t*>(zhash_lookup(exp, rule));
        if (*time < now - 3600)
            zhash_delete(exp, rule);
        rule = reinterpret_cast<char*>(zlist_next(keys));
    }
    zlist_destroy(&keys);
}

static void s_resolve_expired_alerts(zhash_t* exp)
{
    if (!exp || !alerts)
        return;

    alertMtx.lock();
    fty_proto_t* cursor = reinterpret_cast<fty_proto_t*>(zlistx_first(alerts));
    while (cursor) {
        if (s_alert_expired(exp, cursor) && streq(fty_proto_state(cursor), "ACTIVE")) {
            fty_proto_set_state(cursor, "%s", "RESOLVED");
            std::string new_desc = JSONIFY("%s - %s", fty_proto_description(cursor), "TTLCLEANUP");
            fty_proto_set_description(cursor, "%s", new_desc.c_str());

            if (verbose) {
                log_debug("s_resolve_expired_alerts: resolving alert");
                fty_proto_print(cursor);
            }
        }
        cursor = reinterpret_cast<fty_proto_t*>(zlistx_next(alerts));
    }
    alertMtx.unlock();

    s_clear_long_time_expired(exp);
}

static void s_handle_stream_deliver(mlm_client_t* client, zmsg_t** msg_p, zhash_t* expirations)
{
    assert(client);
    assert(msg_p);

    if (!fty_proto_is(*msg_p)) {
        log_error("s_handle_stream_deliver (): Message not fty_proto");
        return;
    }

    fty_proto_t* newAlert = fty_proto_decode(msg_p);
    if (!newAlert || fty_proto_id(newAlert) != FTY_PROTO_ALERT) {
        fty_proto_destroy(&newAlert);
        log_warning("s_handle_stream_deliver (): Message not FTY_PROTO_ALERT.");
        return;
    }

    // handle *only* ACTIVE or RESOLVED alerts
    if (!streq(fty_proto_state(newAlert), "ACTIVE") && !streq(fty_proto_state(newAlert), "RESOLVED")) {
        fty_proto_destroy(&newAlert);
        log_warning("s_handle_stream_deliver (): Message state not ACTIVE or RESOLVED. Not publishing any further.");
        return;
    }

    if (verbose) {
        log_debug("----> printing alert ");
        fty_proto_print(newAlert);
    }

    alertMtx.lock();

    fty_proto_t* cursor = reinterpret_cast<fty_proto_t*>(zlistx_first(alerts));
    bool         found  = false;
    while (cursor) {
        if (alert_id_comparator(cursor, newAlert) == 0) {
            found = true;
            break;
        }
        cursor = reinterpret_cast<fty_proto_t*>(zlistx_next(alerts));
    }

    bool send = true; // default, publish

    if (!found) {
        // Record creation time
        fty_proto_aux_insert(newAlert, "ctime", "%" PRIu64, fty_proto_time(newAlert));

        zlistx_add_end(alerts, newAlert);
        cursor                 = reinterpret_cast<fty_proto_t*>(zlistx_last(alerts));
        alertsLastSent[cursor] = 0;
        s_set_alert_lifetime(expirations, newAlert);
    } else {
        // Append creation time to new alert
        fty_proto_aux_insert(newAlert, "ctime", "%" PRIu64, fty_proto_aux_number(cursor, "ctime", 0));

        bool sameSeverity = streq(fty_proto_severity(newAlert), fty_proto_severity(cursor));
        fty_proto_set_severity(cursor, "%s", fty_proto_severity(newAlert));

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

        if (streq(fty_proto_state(newAlert), "RESOLVED")) {
            if (!streq(fty_proto_state(cursor), "RESOLVED")) {
                // Record resolved time
                fty_proto_aux_insert(cursor, "ctime", "%" PRIu64, fty_proto_time(newAlert));
                fty_proto_aux_insert(newAlert, "ctime", "%" PRIu64, fty_proto_time(newAlert));

                fty_proto_set_state(cursor, "%s", fty_proto_state(newAlert));
                fty_proto_set_time(cursor, fty_proto_time(newAlert));
                fty_proto_set_metadata(cursor, "%s", fty_proto_metadata(newAlert));
            } else {
                send = false;
            }
        } else { // state (newAlert) == ACTIVE
            s_set_alert_lifetime(expirations, newAlert);

            // copy the description only if the alert is active
            fty_proto_set_description(cursor, "%s", fty_proto_description(newAlert));

            if (streq(fty_proto_state(cursor), "RESOLVED")) {
                // Record reactivation time
                fty_proto_aux_insert(cursor, "ctime", "%" PRIu64, fty_proto_time(newAlert));
                fty_proto_aux_insert(newAlert, "ctime", "%" PRIu64, fty_proto_time(newAlert));

                fty_proto_set_time(cursor, fty_proto_time(newAlert));
                fty_proto_set_state(cursor, "%s", fty_proto_state(newAlert));
                fty_proto_set_metadata(cursor, "%s", fty_proto_metadata(newAlert));
            } else if (!streq(fty_proto_state(cursor), "ACTIVE")) {
                // fty_proto_state (cursor) ==  ACK-XXXX
                if (sameSeverity) {
                    send = false;
                }
            } else { // state (cursor) == ACTIVE
                fty_proto_set_time(cursor, fty_proto_time(newAlert));

                // Always active and same severity => don't publish...
                if (sameSeverity) {
                    // ... if we're not at risk of timing out
                    time_t lastSent = alertsLastSent[cursor];
                    if ((zclock_mono() / 1000) < (lastSent + fty_proto_ttl(cursor) / 2)) {
                        send = false;
                    }
                }
                // Severity changed => update creation time
                else {
                    fty_proto_aux_insert(cursor, "ctime", "%" PRIu64, fty_proto_time(newAlert));
                    fty_proto_aux_insert(newAlert, "ctime", "%" PRIu64, fty_proto_time(newAlert));
                }
            }
        }

        // let's do the action at the end of the processing
        zlist_t* actions;
        if (nullptr == fty_proto_action(newAlert)) {
            actions = zlist_new();
            zlist_autofree(actions);
        } else {
            actions = zlist_dup(fty_proto_action(newAlert));
        }
        fty_proto_set_action(cursor, &actions);
    }

    alertMtx.unlock();

    if (send) {
        log_info("send %s (%s/%s)", fty_proto_rule(newAlert), fty_proto_severity(newAlert), fty_proto_state(newAlert));

        fty_proto_t* alert_dup = fty_proto_dup(newAlert);
        zmsg_t*      encoded   = fty_proto_encode(&alert_dup);
        fty_proto_destroy(&alert_dup);
        assert(encoded);

        int rv = mlm_client_send(client, mlm_client_subject(client), &encoded);
        zmsg_destroy(&encoded);

        if (rv == -1) {
            log_error("mlm_client_send (subject = '%s') failed", mlm_client_subject(client));
        } else { // Update last sent time
            alertsLastSent[cursor] = zclock_mono() / 1000;
        }
    }

    fty_proto_destroy(&newAlert);
}

static void s_send_error_response(mlm_client_t* client, const char* subject, const char* reason)
{
    assert(client);
    assert(subject);
    assert(reason);

    zmsg_t* reply = zmsg_new();
    assert(reply);

    zmsg_addstr(reply, "ERROR");
    zmsg_addstr(reply, reason);

    int rv = mlm_client_sendto(client, mlm_client_sender(client), subject, nullptr, 5000, &reply);
    if (rv != 0) {
        zmsg_destroy(&reply);
        log_error("mlm_client_sendto (sender = '%s', subject = '%s', timeout = '5000') failed.",
            mlm_client_sender(client), subject);
    }
}

static void s_handle_rfc_alerts_list(mlm_client_t* client, zmsg_t** msg_p)
{
    assert(client);
    assert(msg_p && *msg_p);
    assert(alerts);

    zmsg_t* msg     = *msg_p;
    char*   command = zmsg_popstr(msg);
    if (!command || (!streq(command, "LIST") && !streq(command, "LIST_EX"))) {
        free(command);
        command = nullptr;
        zmsg_destroy(&msg);
        std::string err = TRANSLATE_ME("BAD_MESSAGE");
        s_send_error_response(client, RFC_ALERTS_LIST_SUBJECT, err.c_str());
        return;
    }

    char* correlation_id = nullptr;
    if (streq(command, "LIST_EX")) {
        correlation_id = zmsg_popstr(msg);
        if (!correlation_id) {
            free(command);
            command = nullptr;
            free(correlation_id);
            correlation_id = nullptr;
            zmsg_destroy(&msg);
            std::string err = TRANSLATE_ME("BAD_MESSAGE");
            s_send_error_response(client, RFC_ALERTS_LIST_SUBJECT, err.c_str());
            return;
        }
    }

    free(command);
    command = nullptr;

    char* state = zmsg_popstr(msg);
    zmsg_destroy(msg_p);
    if (!state || !is_list_request_state(state)) {
        free(correlation_id);
        correlation_id = nullptr;
        free(state);
        state = nullptr;
        s_send_error_response(client, RFC_ALERTS_LIST_SUBJECT, "NOT_FOUND");
        return;
    }

    zmsg_t* reply = zmsg_new();
    if (correlation_id) {
        zmsg_addstr(reply, "LIST_EX");
        zmsg_addstr(reply, correlation_id);
    } else {
        zmsg_addstr(reply, "LIST");
    }
    zmsg_addstr(reply, state);
    alertMtx.lock();
    fty_proto_t* cursor = reinterpret_cast<fty_proto_t*>(zlistx_first(alerts));
    while (cursor) {
        if (is_state_included(state, fty_proto_state(cursor))) {
            fty_proto_t* duplicate = fty_proto_dup(cursor);
            zmsg_t*      result    = fty_proto_encode(&duplicate);

            /* Note: the CZMQ_VERSION_MAJOR comparison below actually assumes versions
             * we know and care about - v3.0.2 (our legacy default, already obsoleted
             * by upstream), and v4.x that is in current upstream master. If the API
             * evolves later (incompatibly), these macros will need to be amended.
             */
            zframe_t* frame = nullptr;
            // FIXME: should we check and assert (nbytes>0) here, for both API versions,
            // as we do in other similar cases?
#if CZMQ_VERSION_MAJOR == 3
            byte*  buffer = nullptr;
            size_t nbytes = zmsg_encode(result, &buffer);
            frame         = zframe_new(buffer, nbytes);
            free(buffer);
            buffer = nullptr;
#else
            frame = zmsg_encode(result);
#endif
            assert(frame);
            zmsg_destroy(&result);
            zmsg_append(reply, &frame);
            // FIXME: Should we zframe_destroy (&frame) here as we do in other similar cases?
        }
        cursor = reinterpret_cast<fty_proto_t*>(zlistx_next(alerts));
    }
    alertMtx.unlock();

    if (mlm_client_sendto(client, mlm_client_sender(client), RFC_ALERTS_LIST_SUBJECT, nullptr, 5000, &reply) != 0) {
        log_error("mlm_client_sendto (sender = '%s', subject = '%s', timeout = '5000') failed.",
            mlm_client_sender(client), RFC_ALERTS_LIST_SUBJECT);
    }
    free(correlation_id);
    correlation_id = nullptr;
    free(state);
    state = nullptr;
}

static void s_handle_rfc_alerts_acknowledge(mlm_client_t* client, zmsg_t** msg_p)
{
    assert(client);
    assert(msg_p);
    assert(alerts);

    zmsg_t* msg = *msg_p;
    if (!msg) {
        return;
    }

    char* rule = zmsg_popstr(msg);
    if (!rule) {
        zmsg_destroy(&msg);
        std::string err = TRANSLATE_ME("BAD_MESSAGE");
        s_send_error_response(client, RFC_ALERTS_ACKNOWLEDGE_SUBJECT, err.c_str());
        return;
    }
    char* element = zmsg_popstr(msg);
    if (!element) {
        zstr_free(&rule);
        zmsg_destroy(&msg);
        std::string err = TRANSLATE_ME("BAD_MESSAGE");
        s_send_error_response(client, RFC_ALERTS_ACKNOWLEDGE_SUBJECT, err.c_str());
        return;
    }
    char* state = zmsg_popstr(msg);
    if (!state) {
        zstr_free(&rule);
        zstr_free(&element);
        zmsg_destroy(&msg);
        std::string err = TRANSLATE_ME("BAD_MESSAGE");
        s_send_error_response(client, RFC_ALERTS_ACKNOWLEDGE_SUBJECT, err.c_str());
        return;
    }
    zmsg_destroy(&msg);
    // check 'state'
    if (!is_acknowledge_request_state(state)) {
        log_warning("state '%s' is not an acknowledge request state according to protocol '%s'.", state,
            RFC_ALERTS_ACKNOWLEDGE_SUBJECT);
        zstr_free(&rule);
        zstr_free(&element);
        zstr_free(&state);
        s_send_error_response(client, RFC_ALERTS_ACKNOWLEDGE_SUBJECT, "BAD_STATE");
        return;
    }
    log_debug("s_handle_rfc_alerts_acknowledge (): rule == '%s' element == '%s' state == '%s'", rule, element, state);
    // check ('rule', 'element') pair
    alertMtx.lock();
    fty_proto_t* cursor = reinterpret_cast<fty_proto_t*>(zlistx_first(alerts));
    int          found  = 0;
    while (cursor) {
        if (is_alert_identified(cursor, rule, element)) {
            found = 1;
            break;
        }
        cursor = reinterpret_cast<fty_proto_t*>(zlistx_next(alerts));
    }
    if (found == 0) {
        zstr_free(&rule);
        zstr_free(&element);
        zstr_free(&state);
        s_send_error_response(client, RFC_ALERTS_ACKNOWLEDGE_SUBJECT, "NOT_FOUND");
        alertMtx.unlock();
        return;
    }
    if (streq(fty_proto_state(cursor), "RESOLVED")) {
        zstr_free(&rule);
        zstr_free(&element);
        zstr_free(&state);
        s_send_error_response(client, RFC_ALERTS_ACKNOWLEDGE_SUBJECT, "BAD_STATE");
        alertMtx.unlock();
        return;
    }
    // change stored alert state, don't change timestamp
    log_debug("s_handle_rfc_alerts_acknowledge (): Changing state of (%s, %s) to %s", fty_proto_rule(cursor),
        fty_proto_name(cursor), state);
    fty_proto_set_state(cursor, "%s", state);

    zmsg_t* reply = zmsg_new();
    zmsg_addstr(reply, "OK");
    zmsg_addstr(reply, rule);
    zmsg_addstr(reply, element);
    zmsg_addstr(reply, state);

    char* subject =
        zsys_sprintf("%s/%s@%s", fty_proto_rule(cursor), fty_proto_severity(cursor), fty_proto_name(cursor));
    zstr_free(&rule);
    zstr_free(&element);
    zstr_free(&state);

    int rv = mlm_client_sendto(client, mlm_client_sender(client), RFC_ALERTS_ACKNOWLEDGE_SUBJECT, nullptr, 5000, &reply);
    if (rv != 0) {
        zmsg_destroy(&reply);
        log_error("mlm_client_sendto (sender = '%s', subject = '%s', timeout = '5000') failed.",
            mlm_client_sender(client), RFC_ALERTS_ACKNOWLEDGE_SUBJECT);
    }
    if (!subject) {
        log_error("zsys_sprintf () failed");
        alertMtx.unlock();
        return;
    }
    uint64_t     timestamp = uint64_t(zclock_time() / 1000);
    fty_proto_t* copy      = fty_proto_dup(cursor);
    if (!copy) {
        log_error("fty_proto_dup () failed");
        zstr_free(&subject);
        alertMtx.unlock();
        return;
    }
    alertMtx.unlock();

    fty_proto_set_time(copy, timestamp);
    reply = fty_proto_encode(&copy);
    if (!reply) {
        log_error("fty_proto_encode () failed");
        fty_proto_destroy(&copy);
        zstr_free(&subject);
        return;
    }
    rv = mlm_client_send(client, subject, &reply);
    if (rv != 0) {
        zmsg_destroy(&reply);
        log_error("mlm_client_send (subject = '%s') failed", subject);
    }
    zstr_free(&subject);
}

static void s_handle_mailbox_deliver(mlm_client_t* client, zmsg_t** msg_p)
{
    assert(client);
    assert(msg_p && *msg_p);
    assert(alerts);

    if (streq(mlm_client_subject(client), RFC_ALERTS_LIST_SUBJECT)) {
        s_handle_rfc_alerts_list(client, msg_p);
    } else if (streq(mlm_client_subject(client), RFC_ALERTS_ACKNOWLEDGE_SUBJECT)) {
        s_handle_rfc_alerts_acknowledge(client, msg_p);
    } else {
        std::string err = TRANSLATE_ME("UNKNOWN_PROTOCOL");
        s_send_error_response(client, mlm_client_subject(client), err.c_str());
        log_error(
            "Unknown protocol. Subject: '%s', Sender: '%s'.", mlm_client_subject(client), mlm_client_sender(client));
        zmsg_destroy(msg_p);
    }
}

void fty_alert_list_server_stream(zsock_t* pipe, void* args)
{
    log_info("Started");

    const char* endpoint = reinterpret_cast<const char*>(args);
    log_debug("Stream endpoint = %s", endpoint);

    zhash_t*      expirations = zhash_new();
    mlm_client_t* client      = mlm_client_new();
    mlm_client_connect(client, endpoint, 1000, "fty-alert-list-stream");
    mlm_client_set_consumer(client, "_ALERTS_SYS", ".*");
    mlm_client_set_producer(client, "ALERTS");

    zpoller_t* poller = zpoller_new(pipe, mlm_client_msgpipe(client), nullptr);
    zsock_signal(pipe, 0);

    while (!zsys_interrupted) {

        void* which = zpoller_wait(poller, 1000);

        if (which == pipe) {
            zmsg_t* msg = zmsg_recv(pipe);
            char*   cmd = zmsg_popstr(msg);
            if (streq(cmd, "$TERM")) {
                zstr_free(&cmd);
                zmsg_destroy(&msg);
                break;
            } else if (streq(cmd, "TTLCLEANUP")) {
                s_resolve_expired_alerts(expirations);
            }
            zstr_free(&cmd);
            zmsg_destroy(&msg);
        } else if (which == mlm_client_msgpipe(client)) {
            zmsg_t* msg = mlm_client_recv(client);
            if (!msg) {
                break;
            } else if (streq(mlm_client_command(client), "STREAM DELIVER")) {
                s_handle_stream_deliver(client, &msg, expirations);
            } else {
                log_warning("Unknown command '%s'. Subject: '%s', Sender: '%s'.", mlm_client_command(client),
                    mlm_client_subject(client), mlm_client_sender(client));
                zmsg_destroy(&msg);
            }
        }
    }

    mlm_client_destroy(&client);
    zpoller_destroy(&poller);
    zhash_destroy(&expirations);

    log_info("Ended");
}

void fty_alert_list_server_mailbox(zsock_t* pipe, void* args)
{
    const char* endpoint = reinterpret_cast<const char*>(args);
    log_debug("Mailbox endpoint = %s", endpoint);

    mlm_client_t* client = mlm_client_new();
    mlm_client_connect(client, endpoint, 1000, "fty-alert-list");
    mlm_client_set_producer(client, "ALERTS");

    zpoller_t* poller = zpoller_new(pipe, mlm_client_msgpipe(client), nullptr);
    zsock_signal(pipe, 0);

    while (!zsys_interrupted) {

        void* which = zpoller_wait(poller, 1000);
        if (which == pipe) {
            zmsg_t* msg = zmsg_recv(pipe);
            char*   cmd = zmsg_popstr(msg);
            if (streq(cmd, "$TERM")) {
                zstr_free(&cmd);
                zmsg_destroy(&msg);
                break;
            }
            zstr_free(&cmd);
            zmsg_destroy(&msg);
        } else if (which == mlm_client_msgpipe(client)) {
            zmsg_t* msg = mlm_client_recv(client);
            if (!msg) {
                break;
            } else if (streq(mlm_client_command(client), "MAILBOX DELIVER")) {
                s_handle_mailbox_deliver(client, &msg);
            } else {
                log_warning("Unknown command '%s'. Subject: '%s', Sender: '%s'.", mlm_client_command(client),
                    mlm_client_subject(client), mlm_client_sender(client));
                zmsg_destroy(&msg);
            }
        }
    }

    mlm_client_destroy(&client);
    zpoller_destroy(&poller);
}

void save_alerts()
{
    int rv = alert_save_state(alerts, STATE_PATH, STATE_FILE, verbose);
    log_debug("alert_save_state () == %d", rv);
}

void init_alert_private(const char* path, const char* filename, bool verb)
{
    alerts = zlistx_new();
    assert(alerts);
    zlistx_set_destructor(alerts, reinterpret_cast<czmq_destructor*>(fty_proto_destroy));
    zlistx_set_duplicator(alerts, reinterpret_cast<czmq_duplicator*>(fty_proto_dup));

    int rv = alert_load_state(alerts, path, filename);
    log_debug("alert_load_state () == %d", rv);

    verbose = verb;
}

void init_alert(bool verb)
{
    init_alert_private(STATE_PATH, STATE_FILE, verb);
}

void destroy_alert()
{
    zlistx_destroy(&alerts);
}
