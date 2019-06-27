/*  ==========================================================================
    alert_list - Actor to serve REST API requests about alerts

    Copyright (C) 2014 - 2019 Eaton

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
    alert_list - Actor to serve REST API requests about alerts
@discuss
@end
*/

#include "fty_alert_list_classes.h"

#define RFC_ALERTS_LIST_SUBJECT "rfc-alerts-list"
#define RFC_ALERTS_ACKNOWLEDGE_SUBJECT  "rfc-alerts-acknowledge"

void
AlertList::alert_cache_clean ()
{
    log_trace ("cleaning up cache..");
    uint64_t now = zclock_mono ()/1000;
    for (auto alert_pair : m_Alert_cache) {
        std::shared_ptr<Alert> alert = alert_pair.second;
        if ((alert->mtime () + alert->ttl () < now) && (alert->state() != "RESOLVED")) {
            log_debug ("cleaning up alert %s", alert->id().c_str ());
            alert->cleanup ();

            zmsg_t *fty_alert = alert->StaleToFtyProto ();
            int rv = mlm_client_send (m_Stream_client, alert->id().c_str (), &fty_alert);
            if (rv == -1) {
                log_error ("mlm_client_send (subject = '%s') failed", alert->id ().c_str ());
                zmsg_destroy (&fty_alert);
            }
        }
    }
}

void
AlertList::filter_alerts_for_publishing
    (std::vector<Alert> alerts,
     std::function<bool(Alert alert)> filter,
     zmsg_t *msg)
{
    std::vector<Alert> filtered_alerts;
    std::copy_if (
            alerts.begin(),
            alerts.end(),
            std::back_inserter (filtered_alerts),
            filter
            );

    for (auto alert : filtered_alerts) {
        int sep = alert.id().find ('@');
        std::string name = alert.id().substr (sep+1);
        try {
            std::string logical_asset_name, logical_asset_ename, normal_state, port;
            std::shared_ptr<FullAsset> asset = FullAssetDatabase::getInstance ().getAsset (name);
            std::string ename = asset->getName ();
            if (asset->getTypeString () == "device" && asset->getSubtypeString () == "sensorgpio") {
                logical_asset_name = asset->getAuxItem ("logical_asset");
                if (logical_asset_name.empty ())
                    logical_asset_name = asset->getParentId ();
                std::shared_ptr<FullAsset> logical_asset = FullAssetDatabase::getInstance ().getAsset (logical_asset_name);
                logical_asset_ename = logical_asset->getName ();
                normal_state = asset->getExtItem ("normal_state");
                port = asset->getExtItem ("port");
            }

            zmsg_t *fty_alert = alert.toFtyProto (
                    ename,
                    logical_asset_name,
                    logical_asset_ename,
                    normal_state,
                    port
                    );
            zmsg_addmsg (msg, &fty_alert);
        } catch (std::exception &e) {
            log_error ("Unable to get asset data due to :", e.what ());
        } catch (...) {
            log_error ("Unable to get asset data due to : unknown error");
        }
    }
}

std::string
AlertList::handle_rule (std::string rule)
{
    GenericRule deserialized_rule (rule);
    std::string id = deserialized_rule.getName ();
    auto pos = m_Alert_cache.find (id);
    // new rule
    if (pos == m_Alert_cache.end ()) {
        for (auto asset : deserialized_rule.getAssets ()) {
            try {
                std::shared_ptr<FullAsset> full_asset = FullAssetDatabase::getInstance ().getAsset (asset);
            }
            catch (element_not_found &eerror) {
                // ask FTY_ASSET_AGENT for ASSET_DETAILS
                zuuid_t *uuid = zuuid_new ();
                zpoller_t *asset_helper = zpoller_new (mlm_client_msgpipe (m_Mailbox_client), NULL);
                mlm_client_sendtox (m_Mailbox_client, AGENT_FTY_ASSET, "ASSET_DETAIL", "GET",
                        zuuid_str_canonical (uuid), asset.c_str (), NULL);
                void *which = zpoller_wait (asset_helper, 5);
                if (which == NULL) {
                    log_warning("no response from ASSET AGENT, ignoring this alert.");
                } else {
                    zmsg_t *reply_msg = mlm_client_recv (m_Mailbox_client);
                    ZstrGuard rcv_uuid (zmsg_popstr (reply_msg));
                    if ((rcv_uuid == zuuid_str_canonical (uuid)) && fty_proto_is (reply_msg)) {
                        fty_proto_t *reply_proto_msg = fty_proto_decode (&reply_msg);
                        if (fty_proto_id (reply_proto_msg) != FTY_PROTO_ASSET) {
                            log_warning("unexpected response from ASSET AGENT, ignoring this alert.");
                        }
                        log_debug("received alert for %s, asked for it and was successful", asset.c_str ());
                        Alert rule_alert (id, deserialized_rule.getResults());
                        std::shared_ptr<Alert> rule_alert_ptr = std::make_shared<Alert> (rule_alert);
                        m_Alert_cache.insert (std::pair<std::string, std::shared_ptr<Alert>> (id, rule_alert_ptr));
                        m_Asset_alerts[asset].push_back (rule_alert_ptr);
                    }
                    else {
                        log_warning("received alert for unknown asset, ignoring.");
                        if (reply_msg) {
                            zmsg_destroy(&reply_msg);
                        }
                        // msg will be destroyed by caller
                    }
                }
                zuuid_destroy (&uuid);
            }
            Alert rule_alert (id, deserialized_rule.getResults());
            std::shared_ptr<Alert> rule_alert_ptr = std::make_shared<Alert> (rule_alert);
            m_Alert_cache.insert (std::pair<std::string, std::shared_ptr<Alert>> (id, rule_alert_ptr));
            m_Asset_alerts[asset].push_back (rule_alert_ptr);
        }
    }
    // update of old rule
    else {
        pos->second->overwrite (deserialized_rule);
    }
    return id;
}

// This function receives alerts from FTY_PROTO_STREAM_ALERTS_SYS.
// In case of success, its result is publishing of new alert on FTY_PROTO_STREAM_ALERTS
void
AlertList::handle_alert (fty_proto_t *fty_new_alert, std::string subject)
{
    bool should_send = false;
    bool should_overwrite = false;

    // check if alert is in the cache
    std::string new_alert_id = std::string (fty_proto_rule (fty_new_alert));
    auto old_alert = m_Alert_cache.find (new_alert_id);
    if (old_alert == m_Alert_cache.end ()) {
         log_error ("Alert for non-existing rule %s", new_alert_id.c_str ());
    }
    else {
        std::string old_state_str = old_alert->second->state();
        uint64_t old_last_sent = m_Last_send [new_alert_id];
        std::string old_outcome = old_alert->second->outcome ();
        std::string new_outcome = fty_proto_aux_string (fty_new_alert, "outcome", "ok");
        bool same_outcome = (old_outcome == new_outcome);

        old_alert->second->update (fty_new_alert);
        const char *old_state = old_state_str.c_str ();
        // check if it has changed
        // RESOLVED comes from _ALERTS_SYS
        // * if stored !RESOLVED -> update stored time/state, publish original
        // * if stored RESOLVED -> don't update stored time, don't publish original
        if (streq (fty_proto_state (fty_new_alert), "RESOLVED")) {
            if (!streq (old_state, "RESOLVED")) {
                should_overwrite = true;
                should_send = true;
            }
        }

        //  ACTIVE comes form _ALERTS_SYS
        //  * if stored RESOLVED -> update stored time/state, publish modified, send ACT
        //  * if stored ACTIVE -> update time
        //      if severity change => publish else don't publish
        //  * if stored ACK-XXX -> Don't change state or time, don't publish

        if (streq (fty_proto_state (fty_new_alert), "ACTIVE")) {
            if (streq (old_state, "RESOLVED")) {
                should_overwrite = true;
                should_send = true;
            }
            else if (streq (old_state, "ACTIVE")) {
                if (!same_outcome) {
                    should_overwrite = true;
                    should_send = true;
                }
                // if still active and same severity, publish only when we are at risk of timing out
                if (static_cast<uint64_t>(zclock_mono ()/1000) >= (old_last_sent + fty_proto_ttl (fty_new_alert)/2)) {
                    should_send = true;
                }
                // always update the time - for the old alert directly in the cache
                old_alert->second->setMtime (fty_proto_time (fty_new_alert));
            }
            else { // some ACK-XXX state stored
                if (!same_outcome) {
                    should_send = true;
                }
            }
        }

        if (should_overwrite) {
            fty_proto_aux_insert (fty_new_alert, "ctime", "%" PRIu64, fty_proto_time (fty_new_alert));
            old_alert->second->overwrite (fty_new_alert);
        }

        if (should_send) {
            fty_proto_t *alert_dup = fty_proto_dup (fty_new_alert);
            zmsg_t *encoded = fty_proto_encode (&alert_dup);
            assert (encoded);

            int rv = mlm_client_send (m_Stream_client, subject.c_str (), &encoded);
            if (rv == -1) {
                log_error ("mlm_client_send (subject = '%s') failed", subject.c_str ());
                zmsg_destroy (&encoded);
            }
            else {
                m_Last_send [new_alert_id] = zclock_mono ()/1000;
            }
        }
    }
    fty_proto_destroy (&fty_new_alert);
}


void
AlertList::process_stream (zmsg_t *msg)
{
    if (!is_fty_proto (msg)) {
        log_error ("Message not fty_proto");
        zmsg_destroy (&msg);
        return;
    }

    fty_proto_t *fty_msg = fty_proto_decode (&msg);
    if (!fty_msg) {
        log_error ("Failed to unpack fty_proto");
        zmsg_destroy (&msg);
        return;
    }
    if (fty_proto_id (fty_msg) == FTY_PROTO_ALERT) {
        std::string subject = mlm_client_subject (m_Stream_client);
        handle_alert (fty_msg, subject);
    }
    else if (fty_proto_id (fty_msg) == FTY_PROTO_ASSET) {
        fty_proto_print (fty_msg);
        if (streq (fty_proto_operation (fty_msg), FTY_PROTO_ASSET_OP_CREATE) || streq (fty_proto_operation (fty_msg), FTY_PROTO_ASSET_OP_UPDATE)) {
            try {
                FullAsset asset(fty_msg);
                FullAssetDatabase::getInstance ().insertOrUpdateAsset (asset);
            } catch (std::exception &e) {
                log_error ("Unable to create/update asset due to :", e.what ());
            } catch (...) {
                log_error ("Unable to create/update asset due to : unknown error");
            }
            fty_proto_destroy (&fty_msg);
        }
        else if (streq (fty_proto_operation (fty_msg),  FTY_PROTO_ASSET_OP_DELETE)){
            try {
                FullAssetDatabase::getInstance ().deleteAsset (fty_proto_name (fty_msg));
            } catch (std::exception &e) {
                log_error ("Unable to delete asset due to :", e.what ());
            } catch (...) {
                log_error ("Unable to delete asset due to : unknown error");
            }
            fty_proto_destroy (&fty_msg);
        }
    }
    else {
        log_warning ("Message neither FTY_PROTO_ASSET nor FTY_PROTO_ALERT.");
        fty_proto_destroy (&fty_msg);
    }
}

zmsg_t *
AlertList::process_LIST (zmsg_t *msg, std::string subject, char *cmd, char *correlation_id)
{
    zmsg_t *reply = zmsg_new ();

    if (subject != RFC_ALERTS_LIST_SUBJECT) {
        log_error ("Expected subject %s,  got %s", RFC_ALERTS_LIST_SUBJECT, subject.c_str ());
        zmsg_addstr (reply, correlation_id);
        zmsg_addstr (reply, "ERROR");
        zmsg_addstr (reply, "WRONG_SUBJECT");
        return reply;
    }

    const std::set<std::string> alert_filters =
        { "RESOLVED", "ACTIVE", "ACK-IGNORE", "ACK-PAUSE", "ACK-SILENCE", "ACK-WIP", "ALL-ACTIVE", "ALL" };
    char *filter = zmsg_popstr (msg);

    if (alert_filters.find (filter) != alert_filters.end ()) {
        std::function<bool(Alert alert)> filter_fn;
        if (streq (filter, "ALL")) {
            // pass trivial lambda
            filter_fn = [](Alert alert) -> bool { return true; } ;
        }
        else if (streq (filter, "ALL-ACTIVE")) {
            // select everything except RESOLVED
            filter_fn = [](Alert alert) -> bool { return alert.state () != "RESOLVED"; } ;
        }
        else {
            // select by state
            filter_fn = [=](Alert alert) -> bool { return streq (alert.state ().c_str (), filter); } ;
        }

        if (streq (cmd, "LISTALL")) {
            zmsg_addstr (reply, correlation_id);
            zmsg_addstr (reply, "LISTALL");
            zmsg_addstr (reply, filter);

            std::vector<Alert> values;
            values.reserve (m_Alert_cache.size ());
            std::transform (m_Alert_cache.begin (), m_Alert_cache.end (), std::back_inserter (values),
                    [](const std::pair<std::string, std::shared_ptr<Alert>> p) { return *(p.second); });
            filter_alerts_for_publishing (values, filter_fn, reply);
        }

        if (streq (cmd, "LIST")) {
            zmsg_addstr (reply, correlation_id);
            zmsg_addstr (reply, "LIST");
            zmsg_addstr (reply, filter);

            char *name = zmsg_popstr (msg);
            while (name) {
                std::vector<std::shared_ptr<Alert>> asset_alerts = m_Asset_alerts [name];

                std::vector<Alert> values;
                values.reserve (asset_alerts.size ());
                std::transform (asset_alerts.begin (), asset_alerts.end (), std::back_inserter (values),
                        [](const std::shared_ptr<Alert> p) { return *p; });
                filter_alerts_for_publishing (values, filter_fn, reply);
                zstr_free (&name);
                name = zmsg_popstr (msg);
            }
        }
    }
    else {
        log_error ("Filter %s not allowed for alerts", filter);
        zmsg_addstr (reply, correlation_id);
        zmsg_addstr (reply, "ERROR");
        zmsg_addstr (reply, "NOT_FOUND");
    }
    zstr_free (&filter);
    return reply;
}

zmsg_t *
AlertList::process_CHANGESTATE (zmsg_t *msg, std::string subject, char *correlation_id)
{
    zmsg_t *reply =  zmsg_new ();

    if (subject != RFC_ALERTS_ACKNOWLEDGE_SUBJECT) {
        log_error ("Expected subject %s,  got %s", RFC_ALERTS_ACKNOWLEDGE_SUBJECT, subject.c_str ());
        zmsg_addstr (reply, correlation_id);
        zmsg_addstr (reply, "ERROR");
        zmsg_addstr (reply, "WRONG_SUBJECT");
        return reply;
    }

    ZstrGuard alert_id (zmsg_popstr (msg));
    auto pos = m_Alert_cache.find (alert_id.get ());
    if (pos == m_Alert_cache.end ()) {
        zmsg_addstr (reply, correlation_id);
        zmsg_addstr (reply, "ERROR");
        zmsg_addstr (reply, "NOT_FOUND");
        return reply;
    }
    ZstrGuard new_state (zmsg_popstr (msg));
    std::shared_ptr<Alert> alert = pos->second;
    int rv = alert->switchState (new_state.get ());
    if (rv) {
        zmsg_addstr (reply, correlation_id);
        zmsg_addstr (reply, "ERROR");
        zmsg_addstr (reply, "BAD_STATE");
        return reply;
    }
    else {
        zmsg_addstr (reply, correlation_id);
        zmsg_addstr (reply, "CHANGESTATE");
        zmsg_addstr (reply, alert_id.get ());
        return reply;
    }

    return reply;
}

void
AlertList::process_mailbox (zmsg_t *msg)
{
    zmsg_t *reply;
    zmsg_print (msg);
    std::string subject = mlm_client_subject (m_Mailbox_client);
    std::string address = mlm_client_sender (m_Mailbox_client);
    ZstrGuard correlation_id (zmsg_popstr (msg));
    ZstrGuard cmd (zmsg_popstr (msg));
    if (streq (cmd, "LISTALL") || streq (cmd, "LIST")) {
        reply = process_LIST (msg, subject, cmd.get (), correlation_id.get ());
    }
    else if (streq (cmd, "ADD")) {
        reply = zmsg_new ();
        ZstrGuard rule (zmsg_popstr (msg));
        std::string rule_id = handle_rule (rule.get ());

        log_debug ("Rule '%s' was successfully added", rule_id.c_str ());
        zmsg_addstr (reply, correlation_id);
        zmsg_addstr (reply, "OK");
        zmsg_addstr (reply, rule_id.c_str ());
    }
    else if (streq (cmd, "CHANGESTATE")) {
        reply = process_CHANGESTATE (msg, subject, correlation_id.get ());
    }
    else {
        reply = zmsg_new ();
        zmsg_addstr (reply, correlation_id);
        zmsg_addstr (reply, "ERROR");
        zmsg_addstr (reply, "BAD_COMMAND");
    }

    int rv = mlm_client_sendto (m_Mailbox_client, address.c_str (), subject.c_str (), NULL, 1000, &reply);
    if (rv == -1) {
        log_error ("mlm_client_sendto to '%s' failed", address.c_str ());
        zmsg_destroy (&reply);
    }
}

void
AlertList::alert_list_run (zsock_t *pipe)
{
    zpoller_t *poller = zpoller_new (pipe, mlm_client_msgpipe (m_Mailbox_client), mlm_client_msgpipe (m_Stream_client), NULL);
    zsock_signal (pipe, 0);

    while (!zsys_interrupted) {
        void *which = zpoller_wait (poller, -1);
        if (which == pipe) {
            zmsg_t *msg = zmsg_recv (pipe);
            ZstrGuard cmd (zmsg_popstr (msg));
            if (streq (cmd, "$TERM")) {
                zmsg_destroy (&msg);
                break;
            }
            else if (streq (cmd, "CONNECT")) {
                ZstrGuard endpoint (zmsg_popstr (msg));
                ZstrGuard name (zmsg_popstr (msg));
                std::string stream_name = name.get () + std::string ("-stream");
                mlm_client_connect (m_Mailbox_client, endpoint, 1000, name);
                mlm_client_connect (m_Stream_client, endpoint, 1000, stream_name.c_str ());
            }
            else if (streq (cmd, "PRODUCER")) {
                ZstrGuard stream (zmsg_popstr (msg));
                mlm_client_set_producer (m_Stream_client, stream);
            }
            else if (streq (cmd, "CONSUMER")) {
                ZstrGuard stream (zmsg_popstr (msg));
                ZstrGuard pattern (zmsg_popstr (msg));
                mlm_client_set_consumer (m_Stream_client, stream, pattern);
            }
            else if (streq (cmd , "TTLCLEANUP")) {
                alert_cache_clean ();
            }
            else {
                log_warning ("Unknown command '%s' on pipe", cmd.get ());
            }
            zmsg_destroy (&msg);
        } else if (which == mlm_client_msgpipe (m_Mailbox_client)) {
            zmsg_t *msg = mlm_client_recv (m_Mailbox_client);
            if (!msg) {
                break;
            }
            process_mailbox (msg);
            zmsg_destroy (&msg);
        } else if (which == mlm_client_msgpipe (m_Stream_client)) {
            zmsg_t *msg = mlm_client_recv (m_Stream_client);
            if (!msg) {
                break;
            }
            process_stream (msg);
        } else {
             log_warning ("Unexpected message");
        }
    }
    zpoller_destroy (&poller);
}

void
alert_list_actor (zsock_t *pipe, void *args)
{
    AlertList alert_list_server;
    alert_list_server.alert_list_run (pipe);
}


//  --------------------------------------------------------------------------
//  Self test of this class

// If your selftest reads SCMed fixture data, please keep it in
// src/selftest-ro; if your test creates filesystem objects, please
// do so under src/selftest-rw.
// The following pattern is suggested for C selftest code:
//    char *filename = NULL;
//    filename = zsys_sprintf ("%s/%s", SELFTEST_DIR_RO, "mytemplate.file");
//    assert (filename);
//    ... use the "filename" for I/O ...
//    zstr_free (&filename);
// This way the same "filename" variable can be reused for many subtests.
#define SELFTEST_DIR_RO "src/selftest-ro"
#define SELFTEST_DIR_RW "src/selftest-rw"

void
alert_list_test (bool verbose)
{
    printf (" * fty_alert_list_server: ");

    //  @selftest
    //  Simple create/destroy test
    {
        AlertList alert_list_server_tmp();
    }

    static const char* endpoint = "inproc://fty-alert-list-test";
    static const char* alert_list_test_address = "fty-alert-list-test";

    zactor_t *server = zactor_new (mlm_server, (void *) "Malamute");
    zstr_sendx (server, "BIND", endpoint, NULL);
    if (verbose)
        zstr_send (server, "VERBOSE");

    zactor_t *alert_list_server = zactor_new (alert_list_actor, (void *) alert_list_test_address);
    zstr_sendx (alert_list_server, "CONNECT", endpoint, alert_list_test_address, NULL);
    zstr_sendx (alert_list_server, "CONSUMER", FTY_PROTO_STREAM_ALERTS_SYS, ".*", NULL);
    zstr_sendx (alert_list_server, "CONSUMER", FTY_PROTO_STREAM_ASSETS, ".*", NULL);
    zstr_sendx (alert_list_server, "PRODUCER", FTY_PROTO_STREAM_ALERTS, NULL);

    mlm_client_t *asset_producer = mlm_client_new ();
    int rv = mlm_client_connect (asset_producer, endpoint, 1000, "ASSETPRODUCER");
    assert (rv == 0);
    rv = mlm_client_set_producer (asset_producer, "ASSETS");
    assert (rv == 0);

    mlm_client_t *alert_producer = mlm_client_new ();
    rv = mlm_client_connect (alert_producer, endpoint, 1000, "ALERTPRODUCER");
    assert (rv == 0);
    rv = mlm_client_set_producer (alert_producer, "_ALERTS_SYS");
    assert (rv == 0);

    mlm_client_t *ui = mlm_client_new ();
    rv = mlm_client_connect (ui, endpoint, 1000, "UI");
    assert (rv == 0);

    zclock_sleep (1000);
    {
    uint64_t now = zclock_mono () / 1000;

    // send asset - DC
    // fill in ename, type, subtype
    zhash_t *asset_aux = zhash_new ();
    zhash_autofree (asset_aux);
    zhash_insert (asset_aux, "type", (void *) "datacenter");
    zhash_insert (asset_aux, "subtype", (void *) "N_A");
    zhash_t *ext = zhash_new ();
    zhash_autofree (ext);
    zhash_insert (ext, "name", (void *) "DC-Roztoky");
    zmsg_t *dc = fty_proto_encode_asset (asset_aux, "testdatacenter", FTY_PROTO_ASSET_OP_CREATE, ext);
    rv = mlm_client_send (asset_producer, "CREATE", &dc);
    assert (rv == 0);
    zhash_destroy (&ext);
    zhash_destroy (&asset_aux);

    zclock_sleep (1000);

    // add rule
    zmsg_t *rule_msg = zmsg_new ();
    zuuid_t *uuid = zuuid_new ();
    zmsg_addstr (rule_msg, zuuid_str_canonical (uuid));
    zmsg_addstr (rule_msg, "ADD");
    std::string rule_json ("{\"test\":{\"name\":\"average.mana@testdatacenter\",\"categories\":[\"CAT_ALL\"],\"metrics\":[\"");
    rule_json += "average.mana1\"],\"results\":[{\"ok\":{\"action\":[],\"severity\":\"CRITICAL\",\"description\":\"";
    rule_json += "ok_description for __ename__\",\"threshold_name\":\"\"}}, {\"high_critical\":{\"action\":[\"EMAIL\"],\"severity\":\"";
    rule_json += "CRITICAL\",\"description\":\"critical_high_description for __ename__\",\"threshold_name\":\"\"}}],\"assets\":[\"";
    rule_json += "testdatacenter\"],\"values\":[{\"var1\":\"val1\"},{\"var2\":\"val2\"}]}}";
    zmsg_addstr (rule_msg, rule_json.c_str ());
    rv = mlm_client_sendto (ui, alert_list_test_address, "rule-handling", NULL, 5000, &rule_msg);
    assert (rv == 0);

    zmsg_t *reply = mlm_client_recv (ui);
    assert (reply != NULL);
    char *str = zmsg_popstr (reply);
    assert (streq (str, zuuid_str_canonical (uuid)));
    zstr_free (&str);
    str = zmsg_popstr (reply);
    assert (streq (str, "OK"));
    zstr_free (&str);
    zuuid_destroy (&uuid);
    str = zmsg_popstr (reply);
    assert (streq (str, "average.mana@testdatacenter"));
    zstr_free (&str);
    zmsg_destroy (&reply);

    // send ACTIVE alert
    zhash_t *alert_aux = zhash_new ();
    zhash_autofree (alert_aux);
    zhash_insert (alert_aux, "outcome", (void *) "high_critical");
    zlist_t *fty_actions = zlist_new ();

    uint64_t mtime = now;
    uint64_t ttl = 300;

    zmsg_t *active_alert = fty_proto_encode_alert (
            alert_aux,
            mtime,
            ttl,
            "average.mana@testdatacenter",
            "testdatacenter",
            "ACTIVE",
            "",
            "",
            fty_actions
            );
    rv = mlm_client_send (alert_producer, "CREATE", &active_alert);
    assert (rv == 0);
    zlist_destroy (&fty_actions);
    zhash_destroy (&alert_aux);

    zclock_sleep (1000);

    // LISTALL
    zmsg_t *listall_msg = zmsg_new ();
    uuid = zuuid_new ();
    zmsg_addstr (listall_msg, zuuid_str_canonical (uuid));
    zmsg_addstr (listall_msg, "LISTALL");
    zmsg_addstr (listall_msg, "ALL");
    rv = mlm_client_sendto (ui, alert_list_test_address, RFC_ALERTS_LIST_SUBJECT, NULL, 5000, &listall_msg);
    assert (rv == 0);

    zmsg_t *listall_reply = mlm_client_recv (ui);
    str = zmsg_popstr (listall_reply);
    assert (streq (str, zuuid_str_canonical (uuid)));
    zstr_free (&str);
    str = zmsg_popstr (listall_reply);
    assert (streq (str, "LISTALL"));
    zstr_free (&str);
    zuuid_destroy (&uuid);
    str = zmsg_popstr (listall_reply);
    assert (streq (str, "ALL"));
    zstr_free (&str);

    zmsg_t *tmp = zmsg_popmsg (listall_reply);
    fty_proto_t *fty_tmp = fty_proto_decode (&tmp);
    assert (fty_proto_id (fty_tmp) == FTY_PROTO_ALERT);
    assert (fty_proto_aux_number (fty_tmp, "ctime", 0) == now);
    assert (fty_proto_time (fty_tmp) == now);
    assert (streq (fty_proto_rule (fty_tmp), "average.mana"));
    assert (streq (fty_proto_name (fty_tmp), "testdatacenter"));
    assert (fty_proto_ttl (fty_tmp) == ttl);
    assert (streq (fty_proto_severity (fty_tmp), "CRITICAL"));
    assert (streq (fty_proto_state (fty_tmp), "ACTIVE"));
    assert (streq (fty_proto_description (fty_tmp), "critical_high_description for DC-Roztoky"));
    zlist_t *fty_alert_msg_actions = fty_proto_action (fty_tmp);
    assert (streq ((const char *) zlist_first (fty_alert_msg_actions), "EMAIL"));
    fty_proto_destroy (&fty_tmp);

    tmp = zmsg_popmsg (listall_reply);
    assert (tmp == NULL);
    zmsg_destroy (&listall_reply);

    // LIST/testdatacenter
    zmsg_t *list_msg = zmsg_new ();
    uuid = zuuid_new ();
    zmsg_addstr (list_msg, zuuid_str_canonical (uuid));
    zmsg_addstr (list_msg, "LIST");
    zmsg_addstr (list_msg, "ALL");
    zmsg_addstr (list_msg, "testdatacenter");
    rv = mlm_client_sendto (ui, alert_list_test_address, RFC_ALERTS_LIST_SUBJECT, NULL, 5000, &list_msg);
    assert (rv == 0);

    zmsg_t *list_reply = mlm_client_recv (ui);
    str = zmsg_popstr (list_reply);
    assert (streq (str, zuuid_str_canonical (uuid)));
    zstr_free (&str);
    str = zmsg_popstr (list_reply);
    assert (streq (str, "LIST"));
    zstr_free (&str);
    zuuid_destroy (&uuid);
    str = zmsg_popstr (list_reply);
    assert (streq (str, "ALL"));
    zstr_free (&str);

    tmp = zmsg_popmsg (list_reply);
    fty_tmp = fty_proto_decode (&tmp);
    assert (fty_proto_id (fty_tmp) == FTY_PROTO_ALERT);
    assert (fty_proto_aux_number (fty_tmp, "ctime", 0) == now);
    assert (fty_proto_time (fty_tmp) == now);
    assert (streq (fty_proto_rule (fty_tmp), "average.mana"));
    assert (streq (fty_proto_name (fty_tmp), "testdatacenter"));
    assert (fty_proto_ttl (fty_tmp) == ttl);
    assert (streq (fty_proto_severity (fty_tmp), "CRITICAL"));
    assert (streq (fty_proto_state (fty_tmp), "ACTIVE"));
    assert (streq (fty_proto_description (fty_tmp), "critical_high_description for DC-Roztoky"));
    fty_alert_msg_actions = fty_proto_action (fty_tmp);
    assert (streq ((const char *) zlist_first (fty_alert_msg_actions), "EMAIL"));
    fty_proto_destroy (&fty_tmp);

    tmp = zmsg_popmsg (list_reply);
    assert (tmp == NULL);
    zmsg_destroy (&list_reply);
    }

    {
    // send RESOLVED alert
    uint64_t now = zclock_mono () / 1000;

    zhash_t *aux = zhash_new ();
    zhash_autofree (aux);
    zhash_insert (aux, "outcome", (void *) "ok");
    zlist_t *fty_actions = zlist_new ();

    uint64_t mtime = now;
    uint64_t ttl = 5;

    zmsg_t *resolved_alert = fty_proto_encode_alert (
            aux,
            mtime,
            ttl,
            "average.mana@testdatacenter",
            "testdatacenter",
            "RESOLVED",
            "",
            "",
            fty_actions
            );
    zlist_destroy (&fty_actions);
    zhash_destroy (&aux);
    rv = mlm_client_send (alert_producer, "CREATE", &resolved_alert);
    assert (rv == 0);

    zclock_sleep (1000);
    // LISTALL
    zmsg_t *listall_msg = zmsg_new ();
    zuuid_t *uuid = zuuid_new ();
    zmsg_addstr (listall_msg, zuuid_str_canonical (uuid));
    zmsg_addstr (listall_msg, "LISTALL");
    zmsg_addstr (listall_msg, "ALL");
    rv = mlm_client_sendto (ui, alert_list_test_address, RFC_ALERTS_LIST_SUBJECT, NULL, 5000, &listall_msg);
    assert (rv == 0);

    zmsg_t *reply = mlm_client_recv (ui);
    char *str = zmsg_popstr (reply);
    assert (streq (str, zuuid_str_canonical (uuid)));
    zstr_free (&str);
    str = zmsg_popstr (reply);
    assert (streq (str, "LISTALL"));
    zstr_free (&str);
    zuuid_destroy (&uuid);
    str = zmsg_popstr (reply);
    assert (streq (str, "ALL"));
    zstr_free (&str);

    zmsg_t *tmp = zmsg_popmsg (reply);
    fty_proto_t *fty_tmp = fty_proto_decode (&tmp);
    assert (fty_proto_id (fty_tmp) == FTY_PROTO_ALERT);
    log_error ("%d = %d", fty_proto_aux_number (fty_tmp, "ctime", 0), mtime);
    assert (fty_proto_aux_number (fty_tmp, "ctime", 0) == mtime);
    assert (fty_proto_time (fty_tmp) == mtime);
    assert (streq (fty_proto_rule (fty_tmp), "average.mana"));
    assert (streq (fty_proto_name (fty_tmp), "testdatacenter"));
    assert (fty_proto_ttl (fty_tmp) == ttl);
    assert (streq (fty_proto_severity (fty_tmp), "CRITICAL"));
    assert (streq (fty_proto_state (fty_tmp), "RESOLVED"));
    assert (streq (fty_proto_description (fty_tmp), "ok_description for DC-Roztoky"));
    zlist_t *fty_alert_msg_actions = fty_proto_action (fty_tmp);
    assert (zlist_first (fty_alert_msg_actions) == NULL);
    fty_proto_destroy (&fty_tmp);

    tmp = zmsg_popmsg (reply);
    assert (tmp == NULL);
    zmsg_destroy (&reply);
    }

    {
    // send ACTIVE alert
    uint64_t now = zclock_mono () / 1000;

    zhash_t *aux = zhash_new ();
    zhash_autofree (aux);
    zhash_insert (aux, "outcome", (void *) "high_critical");
    zlist_t *fty_actions = zlist_new ();

    uint64_t mtime = now;
    uint64_t ttl = 5;

    zmsg_t *active_alert = fty_proto_encode_alert (
            aux,
            mtime,
            ttl,
            "average.mana@testdatacenter",
            "testdatacenter",
            "ACTIVE",
            "",
            "",
            fty_actions
            );
    zlist_destroy (&fty_actions);
    zhash_destroy (&aux);
    rv = mlm_client_send (alert_producer, "CREATE", &active_alert);
    assert (rv == 0);

    // wait for TTL to time out
    zclock_sleep (6000);
    zstr_sendx (alert_list_server, "TTLCLEANUP", NULL);

    // LIST ALL
    zmsg_t *listall_msg = zmsg_new ();
    zuuid_t *uuid = zuuid_new ();
    zmsg_addstr (listall_msg, zuuid_str_canonical (uuid));
    zmsg_addstr (listall_msg, "LISTALL");
    zmsg_addstr (listall_msg, "ALL");
    rv = mlm_client_sendto (ui, alert_list_test_address, RFC_ALERTS_LIST_SUBJECT, NULL, 5000, &listall_msg);

    zmsg_t *reply = mlm_client_recv (ui);
    char *str = zmsg_popstr (reply);
    assert (streq (str, zuuid_str_canonical (uuid)));
    zstr_free (&str);
    str = zmsg_popstr (reply);
    assert (streq (str, "LISTALL"));
    zstr_free (&str);
    zuuid_destroy (&uuid);
    str = zmsg_popstr (reply);
    assert (streq (str, "ALL"));
    zstr_free (&str);

    zmsg_t *tmp = zmsg_popmsg (reply);
    fty_proto_t *fty_tmp = fty_proto_decode (&tmp);
    assert (fty_proto_id (fty_tmp) == FTY_PROTO_ALERT);
    assert (fty_proto_aux_number (fty_tmp, "ctime", 0) >= mtime);
    assert (fty_proto_time (fty_tmp) >= mtime );
    assert (streq (fty_proto_rule (fty_tmp), "average.mana"));
    assert (streq (fty_proto_name (fty_tmp), "testdatacenter"));
    assert (fty_proto_ttl (fty_tmp) == ttl);
    assert (streq (fty_proto_severity (fty_tmp), ""));
    assert (streq (fty_proto_state (fty_tmp), "RESOLVED"));
    assert (streq (fty_proto_description (fty_tmp), ""));
    zlist_t *fty_alert_msg_actions = fty_proto_action (fty_tmp);
    assert (zlist_first (fty_alert_msg_actions) == NULL);
    fty_proto_destroy (&fty_tmp);

    tmp = zmsg_popmsg (reply);
    assert (tmp == NULL);
    zmsg_destroy (&reply);
    }

    mlm_client_destroy (&ui);
    mlm_client_destroy (&alert_producer);
    mlm_client_destroy (&asset_producer);
    zactor_destroy (&alert_list_server);
    zactor_destroy (&server);
    //  @end
    printf ("OK\n");
}
