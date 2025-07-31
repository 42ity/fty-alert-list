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
#include "alerts_utils.h"

#include <fty_proto.h>
#include <fty_log.h>
#include <fty_common.h>
#include <malamute.h>
#include <map>
#include <mutex>
#include <string.h>

#define RFC_ALERTS_LIST_SUBJECT        "rfc-alerts-list"
#define RFC_ALERTS_ACKNOWLEDGE_SUBJECT "rfc-alerts-acknowledge"

static const char* STATE_PATH = "/var/lib/fty/fty-alert-list";
static const char* STATE_FILE = "state_file";

static zlistx_t* alerts{nullptr};
static std::mutex alertMtx;
static std::map<fty_proto_t*, time_t> alertsLastSent;
static bool verbose{false};

static void s_set_alert_lifetime(zhash_t* exp, fty_proto_t* alert)
{
    if (!(exp && alert)) {
        return;
    }

    int64_t ttl = fty_proto_ttl(alert);
    const char* rule = fty_proto_rule(alert);
    if (!(ttl && rule)) {
        return;
    }

    int64_t* time = reinterpret_cast<int64_t*>(malloc(sizeof(*time)));
    if (time) {
        log_debug("# rule %s with ttl %" PRIi64, rule, ttl);
        *time = (zclock_mono() / 1000) + ttl; // expiry time (sec)
        zhash_update(exp, rule, time);
        zhash_freefn(exp, rule, free);
    }
    else {
        log_error("time malloc() failed");
    }
}

static bool s_alert_expired(zhash_t* exp, fty_proto_t* alert)
{
    if (exp && alert) {
        const char* rule = fty_proto_rule(alert);
        int64_t* time = rule ? reinterpret_cast<int64_t*>(zhash_lookup(exp, rule)) : nullptr;
        if (time) {
            return (zclock_mono() / 1000) > (*time);
        }
    }
    return false;
}

static void s_clear_long_time_expired(zhash_t* exp)
{
    if (!exp) {
        return;
    }

    int64_t now = zclock_mono() / 1000;

    zlist_t* keys = zhash_keys(exp);
    for (void* it = zlist_first(keys); it; it = zlist_next(keys)) {
        const char* rule = reinterpret_cast<char*>(it);
        int64_t* p = reinterpret_cast<int64_t*>(zhash_lookup(exp, rule));
        int64_t time = p ? (*p) : 0;
        if (now > (time + 3600)) { // expired an hour ago (sec)
            zhash_delete(exp, rule);
        }
    }
    zlist_destroy(&keys);
}

static void s_resolve_expired_alerts(zhash_t* exp)
{
    if (!(exp && alerts)) {
        return;
    }

    alertMtx.lock();

    for (void* it = zlistx_first(alerts); it; it = zlistx_next(alerts)) {
        fty_proto_t* cursor = reinterpret_cast<fty_proto_t*>(it);

        if (streq(fty_proto_state(cursor), "ACTIVE")
            && s_alert_expired(exp, cursor)
        ) {
            const std::string newDesc{JSONIFY("%s - %s", fty_proto_description(cursor), "TTLCLEANUP")};

            fty_proto_set_description(cursor, "%s", newDesc.c_str());
            fty_proto_set_state(cursor, "%s", "RESOLVED");

            if (verbose) {
                log_debug("s_resolve_expired_alerts: resolving alert '%s'", fty_proto_rule(cursor));
                fty_proto_print(cursor);
            }
        }
    }

    alertMtx.unlock();

    s_clear_long_time_expired(exp);
}

static void s_handle_stream_deliver(mlm_client_t* client, zmsg_t** msg_p, zhash_t* expirations)
{
    if (!(client && msg_p && expirations)) {
        if (msg_p) zmsg_destroy(msg_p);
        log_debug("bad args");
        return;
    }

    fty_proto_t* newAlert = (*msg_p) ? fty_proto_decode(msg_p) : NULL;
    zmsg_destroy(msg_p); // secure

    if (!(newAlert && (fty_proto_id(newAlert) == FTY_PROTO_ALERT))) {
        fty_proto_destroy(&newAlert);
        log_warning("Message not FTY_PROTO_ALERT.");
        return;
    }

    // handle ACTIVE/RESOLVED alerts *only*
    if (!(streq(fty_proto_state(newAlert), "ACTIVE")
          || streq(fty_proto_state(newAlert), "RESOLVED"))
    ) {
        fty_proto_destroy(&newAlert);
        log_warning("Message state not ACTIVE or RESOLVED. Not publishing any further.");
        return;
    }

    if (verbose) {
        log_debug("== alert:");
        fty_proto_print(newAlert);
    }

    alertMtx.lock();

    fty_proto_t* cursor = NULL;
    for (void* it = zlistx_first(alerts); it; it = zlistx_next(alerts)) {
        fty_proto_t* cursor_ = reinterpret_cast<fty_proto_t*>(it);

        if (alert_id_comparator(cursor_, newAlert) == 0) {
            cursor = cursor_;
            break; // found (cursor)
        }
    }

    // work with 'cursor'

    int64_t now = zclock_mono() / 1000; // sec
    bool send{true}; // default, publish

    if (!cursor) { // 1st time alert
        // Record creation time
        fty_proto_aux_insert(newAlert, "ctime", "%" PRIu64, fty_proto_time(newAlert));

        zlistx_add_end(alerts, newAlert);
        cursor = reinterpret_cast<fty_proto_t*>(zlistx_last(alerts));

        s_set_alert_lifetime(expirations, cursor);
        alertsLastSent[cursor] = 0; // first time (not sent yet)
    }
    else {
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
            }
            else {
                send = false;
            }
        }
        else { // state (newAlert) == ACTIVE
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
            }
            else if (streq(fty_proto_state(cursor), "ACTIVE")) {
                fty_proto_set_time(cursor, fty_proto_time(newAlert));

                // Always active and same severity...
                if (sameSeverity) {
                    // don't publish if we're not at risk of timing out
                    // but resend at least every 120s (warranty ttl is >1 day!)
                    time_t lastSent = alertsLastSent[cursor];
                    uint32_t ttl = MIN(fty_proto_ttl(newAlert), (2 * 120));
                    if ((lastSent + (ttl / 2)) > now) {
                        send = false;
                    }
                }
                // Severity changed => update creation time
                else {
                    fty_proto_aux_insert(cursor, "ctime", "%" PRIu64, fty_proto_time(newAlert));
                    fty_proto_aux_insert(newAlert, "ctime", "%" PRIu64, fty_proto_time(newAlert));
                }
            }
            else { // state (cursor) == ACK-XXXX
                if (sameSeverity) {
                    send = false;
                }
            }
        }

        // let's do the action at the end of the processing
        zlist_t* actions = NULL;
        if (!fty_proto_action(newAlert)) {
            actions = zlist_new();
            zlist_autofree(actions);
        }
        else {
            actions = zlist_dup(fty_proto_action(newAlert));
        }
        fty_proto_set_action(cursor, &actions); // actions owned by cursor
    }

    if (send) { // NOTICE: use 'cursor'
        log_info("send %s (%s/%s)", fty_proto_rule(newAlert), fty_proto_severity(newAlert), fty_proto_state(newAlert));

        fty_proto_t* alert_dup = fty_proto_dup(newAlert);
        zmsg_t* encoded = fty_proto_encode(&alert_dup);
        fty_proto_destroy(&alert_dup);
        if (!encoded) {
            log_error("fty_proto_encode() failed");
        }

        int r = encoded ? mlm_client_send(client, mlm_client_subject(client), &encoded) : -42;
        zmsg_destroy(&encoded);

        if (r != 0) {
            log_error("mlm_client_send (subject = '%s', r: %d) failed", mlm_client_subject(client), r);
            const auto& it = alertsLastSent.find(cursor);
            if (it == alertsLastSent.cend()) {
                alertsLastSent[cursor] = 0; // first time
            }
        }
        else { // Update last sent time
            alertsLastSent[cursor] = now;
        }
    }

    alertMtx.unlock();

    fty_proto_destroy(&newAlert);
}

static void s_send_error_response(mlm_client_t* client, const char* subject, const char* reason)
{
    if (!(client && subject)) {
        log_error("client/subject is NULL");
        return;
    }

    const char* sender = mlm_client_sender(client);

    zmsg_t* reply = zmsg_new();
    if (!reply) {
        log_error("zmsg_new() failed (sender: '%s', subject: '%s')",
            sender, subject);
        return;
    }
    zmsg_addstr(reply, "ERROR");
    zmsg_addstr(reply, reason ? reason : "");

    int r = mlm_client_sendto(client, sender, subject, nullptr, 5000, &reply);
    zmsg_destroy(&reply);
    if (r != 0) {
        log_error("mlm_client_sendto failed (sender: '%s', subject: '%s', timeout = '5000')",
            sender, subject);
    }
}

static void s_handle_rfc_alerts_list(mlm_client_t* client, zmsg_t** msg_p)
{
    if (!(client && msg_p && alerts)) {
        if (msg_p) zmsg_destroy(msg_p);
        log_error("bad args");
        return;
    }

    const char* subject = RFC_ALERTS_LIST_SUBJECT;

    zmsg_t* msg = *msg_p;
    *msg_p = NULL; // take ownership

    char* command = NULL;
    char* correlation_id = NULL;
    char* state = NULL;

    #define CLEANUP { zstr_free(&state); zstr_free(&correlation_id); zstr_free(&command); }

    command = zmsg_popstr(msg);
    if (!command || (!(streq(command, "LIST") || streq(command, "LIST_EX")))) {
        CLEANUP;
        zmsg_destroy(&msg);
        const std::string err{TRANSLATE_ME("BAD_MESSAGE")};
        s_send_error_response(client, subject, err.c_str());
        return;
    }

    if (streq(command, "LIST_EX")) {
        correlation_id = zmsg_popstr(msg);
        if (!correlation_id) {
            CLEANUP;
            zmsg_destroy(&msg);
            const std::string err{TRANSLATE_ME("BAD_MESSAGE")};
            s_send_error_response(client, subject, err.c_str());
            return;
        }
    }

    state = zmsg_popstr(msg);
    if (!(state && is_list_request_state(state))) {
        CLEANUP;
        zmsg_destroy(&msg);
        s_send_error_response(client, subject, "NOT_FOUND");
        return;
    }

    zmsg_destroy(&msg); // useless

    zmsg_t* reply = zmsg_new();
    zmsg_addstr(reply, command);
    if (correlation_id) { zmsg_addstr(reply, correlation_id); } // LIST_EX
    zmsg_addstr(reply, state);

    alertMtx.lock();

    for (void* it = zlistx_first(alerts); it; it = zlistx_next(alerts)) {
        fty_proto_t* cursor = reinterpret_cast<fty_proto_t*>(it);

        if (is_state_included(state, fty_proto_state(cursor))) {
            fty_proto_t* duplicate = fty_proto_dup(cursor);
            zmsg_t* result = fty_proto_encode(&duplicate);
            fty_proto_destroy(&duplicate);

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
            if (!frame) {
                log_error("frame is NULL");
            }
            else {
                zmsg_append(reply, &frame);
            }

            zframe_destroy(&frame);
            zmsg_destroy(&result);
        }
    }

    alertMtx.unlock();

    const char* sender = mlm_client_sender(client);
    int r = mlm_client_sendto(client, sender, subject, nullptr, 5000, &reply);
    zmsg_destroy(&reply);
    if (r != 0) {
        log_error("mlm_client_sendto (sender = '%s', subject = '%s', timeout = '5000') failed.",
            sender, subject);
    }

    CLEANUP; // useless
    #undef CLEANUP
}

static void s_handle_rfc_alerts_acknowledge(mlm_client_t* client, zmsg_t** msg_p)
{
    if (!(client && msg_p && alerts)) {
        if (msg_p) zmsg_destroy(msg_p);
        log_error("bad args");
        return;
    }

    const char* subject = RFC_ALERTS_ACKNOWLEDGE_SUBJECT;
    const char* sender = mlm_client_sender(client);

    zmsg_t* msg = *msg_p;
    *msg_p = NULL; // take ownership

    #define CLEANUP { zstr_free(&state); zstr_free(&element); zstr_free(&rule); }

    char* rule = zmsg_popstr(msg);
    char* element = zmsg_popstr(msg);
    char* state = zmsg_popstr(msg);

    zmsg_destroy(&msg); // useless

    if (!(rule && element && state)) {
        CLEANUP;
        const std::string err{TRANSLATE_ME("BAD_MESSAGE")};
        s_send_error_response(client, subject, err.c_str());
        return;
    }

    // check 'state'
    if (!is_acknowledge_request_state(state)) {
        log_warning("state '%s' is not an acknowledge request state according to protocol '%s'.",
            state, subject);
        CLEANUP;
        s_send_error_response(client, subject, "BAD_STATE");
        return;
    }

    log_debug("s_handle_rfc_alerts_acknowledge (): rule == '%s' element == '%s' state == '%s'", rule, element, state);
    // check ('rule', 'element') pair

    fty_proto_t* copy = NULL; // of alert
    {
        alertMtx.lock();

        fty_proto_t* cursor = NULL;
        for (void* it = zlistx_first(alerts); it; it = zlistx_next(alerts)) {
            fty_proto_t* cursor_ = reinterpret_cast<fty_proto_t*>(it);

            if (is_alert_identified(cursor_, rule, element)) {
                cursor = cursor_;
                break; // found (cursor)
            }
        }

        if (!cursor) { // not found
            alertMtx.unlock();
            CLEANUP;
            s_send_error_response(client, subject, "NOT_FOUND");
            return;
        }

        if (streq(fty_proto_state(cursor), "RESOLVED")) {
            alertMtx.unlock();
            CLEANUP;
            s_send_error_response(client, subject, "BAD_STATE");
            return;
        }

        // change stored alert state, don't change timestamp
        log_debug("s_handle_rfc_alerts_acknowledge (): Changing state of (%s, %s) to %s",
            fty_proto_rule(cursor), fty_proto_name(cursor), state);

        // change state
        fty_proto_set_state(cursor, "%s", state);

        // alert to notify state changed
        copy = fty_proto_dup(cursor);
        if (!copy) {
            log_error("fty_proto_dup failed");
        }

        alertMtx.unlock();
    }

    // send reply
    zmsg_t* reply = zmsg_new();
    zmsg_addstr(reply, "OK");
    zmsg_addstr(reply, rule);
    zmsg_addstr(reply, element);
    zmsg_addstr(reply, state);

    CLEANUP; // useless
    #undef CLEANUP

    int r = mlm_client_sendto(client, sender, subject, nullptr, 5000, &reply);
    zmsg_destroy(&reply);
    if (r != 0) {
        log_error("mlm_client_sendto (sender = '%s', subject = '%s', timeout = '5000') failed.",
            sender, subject);
    }

    // notify state changed
    if (copy) {
        char send_subject[255] = "";
        snprintf(send_subject, sizeof(send_subject), "%s/%s@%s", fty_proto_rule(copy), fty_proto_severity(copy), fty_proto_name(copy));
        fty_proto_set_time(copy, uint64_t(zclock_time() / 1000)); // timestamp changed
        reply = fty_proto_encode(&copy);
        if (!reply) {
            log_error("fty_proto_encode failed");
        }
        else {
            r = mlm_client_send(client, send_subject, &reply);
            if (r != 0) {
                log_error("mlm_client_send (subject = '%s') failed", send_subject);
            }
        }
        zmsg_destroy(&reply);
    }
    fty_proto_destroy(&copy);
}

static void s_handle_mailbox_deliver(mlm_client_t* client, zmsg_t** msg_p)
{
    if (!(client && msg_p && alerts)) {
        if (msg_p) zmsg_destroy(msg_p);
        log_error("bad args");
        return;
    }

    const char* subject = mlm_client_subject(client);
    const char* sender = mlm_client_sender(client);

    if (streq(subject, RFC_ALERTS_LIST_SUBJECT)) {
        s_handle_rfc_alerts_list(client, msg_p);
    }
    else if (streq(subject, RFC_ALERTS_ACKNOWLEDGE_SUBJECT)) {
        s_handle_rfc_alerts_acknowledge(client, msg_p);
    }
    else {
        log_error("Unexpetd subject '%s' (sender: '%s')", subject, sender);
        const std::string err{TRANSLATE_ME("UNKNOWN_PROTOCOL")};
        s_send_error_response(client, subject, err.c_str());
    }
    zmsg_destroy(msg_p);
}

void fty_alert_list_server_stream(zsock_t* pipe, void* args)
{
    const char* endpoint = reinterpret_cast<const char*>(args);
    log_debug("Stream endpoint = %s", endpoint);

    mlm_client_t* client = mlm_client_new();
    if (!client) {
        log_error("mlm_client_new failed");
        return;
    }

    int r = mlm_client_connect(client, endpoint, 1000, "fty-alert-list-stream");
    if (r != 0) {
        log_error("mlm_client_connect() failed");
    }
    r = mlm_client_set_consumer(client, "_ALERTS_SYS", ".*");
    if (r != 0) {
        log_error("mlm_client_set_consumer() _ALERTS_SYS failed");
    }
    r = mlm_client_set_producer(client, "ALERTS");
    if (r != 0) {
        log_error("mlm_client_set_producer() ALERTS failed");
    }

    zpoller_t* poller = zpoller_new(pipe, mlm_client_msgpipe(client), nullptr);
    if (!poller) {
        log_error("zpoller_new failed");
        mlm_client_destroy(&client);
        return;
    }

    zhash_t* expirations = zhash_new();
    if (!expirations) {
        zpoller_destroy(&poller);
        mlm_client_destroy(&client);
        log_error("expirations zhash_new failed");
        return;
    }

    zsock_signal(pipe, 0);
    log_info("client stream started");

    const int POLL_TIMEOUT_MS = 30000; //ms

    while (!zsys_interrupted) {

        void* which = zpoller_wait(poller, POLL_TIMEOUT_MS);

        if (which == NULL) {
            if (zpoller_terminated(poller) || zsys_interrupted) {
                break;
            }
        }
        else if (which == pipe) {
            zmsg_t* msg = zmsg_recv(pipe);
            char* cmd = zmsg_popstr(msg);
            bool term{cmd && streq(cmd, "$TERM")};
            if (cmd && streq(cmd, "TTLCLEANUP")) {
                s_resolve_expired_alerts(expirations);
            }
            zstr_free(&cmd);
            zmsg_destroy(&msg);
            if (term) {
                break;
            }
        }
        else if (which == mlm_client_msgpipe(client)) {
            zmsg_t* msg = mlm_client_recv(client);
            const char* command = mlm_client_command(client);
            const char* subject = mlm_client_subject(client);
            const char* sender = mlm_client_sender(client);

            if (streq(command, "STREAM DELIVER")) {
                s_handle_stream_deliver(client, &msg, expirations);
            }
            else {
                log_debug("Unexpected command '%s' (subject: '%s', sender: '%s')",
                    command, subject, sender);
            }
            zmsg_destroy(&msg);
        }
    }

    zhash_destroy(&expirations);
    zpoller_destroy(&poller);
    mlm_client_destroy(&client);

    log_info("client stream ended");
}

void fty_alert_list_server_mailbox(zsock_t* pipe, void* args)
{
    const char* endpoint = reinterpret_cast<const char*>(args);
    log_debug("Mailbox endpoint = %s", endpoint);

    mlm_client_t* client = mlm_client_new();
    if (!client) {
        log_error("mlm_client_new failed");
        return;
    }

    int r = mlm_client_connect(client, endpoint, 1000, "fty-alert-list");
    if (r != 0) {
        log_error("mlm_client_connect() failed");
    }
    r = mlm_client_set_producer(client, "ALERTS");
    if (r != 0) {
        log_error("mlm_client_set_producer() ALERTS failed");
    }

    zpoller_t* poller = zpoller_new(pipe, mlm_client_msgpipe(client), nullptr);
    if (!poller) {
        log_error("zpoller_new failed");
        mlm_client_destroy(&client);
        return;
    }

    zsock_signal(pipe, 0);
    log_info("client mailbox started");

    const int POLL_TIMEOUT_MS = 30000; //ms

    while (!zsys_interrupted) {

        void* which = zpoller_wait(poller, POLL_TIMEOUT_MS);

        if (which == NULL) {
            if (zpoller_terminated(poller) || zsys_interrupted) {
                break;
            }
        }
        else if (which == pipe) {
            zmsg_t* msg = zmsg_recv(pipe);
            char* cmd = zmsg_popstr(msg);
            bool term{cmd && streq(cmd, "$TERM")};
            zstr_free(&cmd);
            zmsg_destroy(&msg);
            if (term) {
                break;
            }
        }
        else if (which == mlm_client_msgpipe(client)) {
            zmsg_t* msg = mlm_client_recv(client);
            const char* command = mlm_client_command(client);
            const char* subject = mlm_client_subject(client);
            const char* sender = mlm_client_sender(client);

            if (streq(command, "MAILBOX DELIVER")) {
                s_handle_mailbox_deliver(client, &msg);
            }
            else {
                log_debug("Unexpected command '%s' (subject: '%s', sender: '%s')",
                    command, subject ,sender);
            }
            zmsg_destroy(&msg);
        }
    }

    zpoller_destroy(&poller);
    mlm_client_destroy(&client);

    log_info("client mailbox ended");
}

void save_alerts()
{
    int r = alert_save_state(alerts, STATE_PATH, STATE_FILE, verbose);
    log_debug("alert_save_state () == %d", r);
}

void init_alert_private(const char* path, const char* filename, bool verbose_)
{
    if (alerts) {
        log_warning("alerts is in use. Destroying...");
        destroy_alert();
    }

    alerts = zlistx_new();
    if (!alerts) {
        log_error("zlistx_new() alerts failed");
        return;
    }
    zlistx_set_destructor(alerts, reinterpret_cast<czmq_destructor*>(fty_proto_destroy));
    zlistx_set_duplicator(alerts, reinterpret_cast<czmq_duplicator*>(fty_proto_dup));

    int r = alert_load_state(alerts, path, filename);
    log_debug("alert_load_state () == %d", r);

    verbose = verbose_;
}

int init_alert(bool verbose_)
{
    init_alert_private(STATE_PATH, STATE_FILE, verbose_);
    return alerts ? 0 : -1;
}

void destroy_alert()
{
    zlistx_destroy(&alerts);
}
