/*  =========================================================================
    bios_alerts_list_server - Providing information about active and resolved alerts

    Copyright (C) 2014 - 2015 Eaton                                        
                                                                           
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
    bios_alerts_list_server - Providing information about active and resolved alerts
@discuss
@end
*/
#include "../include/alert_list.h"

#define RFC_ALERTS_LIST_SUBJECT "rfc-alerts-list"

static int
is_alertstate (const char *state) {
    assert (state);
    if (streq (state, "ALL") ||
        streq (state, "ACTIVE") ||
        streq (state, "ACK-WIP") ||
        streq (state, "ACK-IGNORE") ||
        streq (state, "ACK-PAUSE") ||
        streq (state, "ACK-SILENCE")) {
        return 1;
    }
    return 0;
}

static int
alerteq (bios_proto_t *alert1, bios_proto_t *alert2) {
    assert (alert1);
    assert (alert2);
    assert (bios_proto_id (alert1) == BIOS_PROTO_ALERT);
    assert (bios_proto_id (alert2) == BIOS_PROTO_ALERT);

    if (streq (bios_proto_rule (alert1), bios_proto_rule (alert2)) &&
        streq (bios_proto_element_src (alert1), bios_proto_element_src (alert2)))
        return 1;
    else
        return 0;
}

static void
s_handle_stream_deliver (zmsg_t** msg_p, zlistx_t *alerts) {
    zsys_debug ("s_handle_stream_deliver ():");
    assert (msg_p);
    zmsg_t *msg = *msg_p;
    bios_proto_t *alert = bios_proto_decode (&msg);
    if (!alert || bios_proto_id (alert) != BIOS_PROTO_ALERT) {
        zsys_warning ("s_handle_stream_deliver (): Message not BIOS_PROTO_ALERT.");
        return;
    }

    zsys_debug ("s_handle_stream_deliver (): Message debug print");
    bios_proto_print (alert);

    bios_proto_t *cursor = (bios_proto_t *) zlistx_first (alerts);
    if (cursor) {
        int found = 0;
        while (cursor) {
            if (alerteq (cursor, alert)) {
                if (streq (bios_proto_state (alert), "RESOLVED")) {
                    zlistx_delete (alerts, zlistx_cursor (alerts));
                    zsys_debug ("s_handle_stream_deliver (): alert deleted from list.");
                }
                else {
                    bios_proto_set_state (cursor, "%s", bios_proto_state (alert));
                    zsys_debug ("s_handle_stream_deliver (): alert state updated.");
                }
                found = 1;
                break;
            }
            cursor = (bios_proto_t *) zlistx_next (alerts);
        }
        if (!found) {        
            zlistx_add_end (alerts, alert);
            zsys_debug ("s_handle_stream_deliver (): alert added to list");
        }
    }
    else if (!streq (bios_proto_state (alert), "RESOLVED")) {
        zlistx_add_end (alerts, alert);
        zsys_debug ("s_handle_stream_deliver (): alert added to list");
    }
    else
        zsys_debug ("s_handle_stream_deliver (): nothing done");

    bios_proto_destroy (&alert);
    zmsg_destroy (&msg);
}

static void
s_handle_mailbox_deliver (mlm_client_t *client, zmsg_t** msg_p, zlistx_t *alerts) {
    zsys_debug ("s_handle_mailbox_deliver () start.");
    assert (msg_p);
    zmsg_t *msg = *msg_p;
    if (!msg)
        return;
    char *part = zmsg_popstr (msg);
    if (!streq (part, "LIST")) {
        zmsg_destroy (&msg);
        return;
    }
    free (part); part = NULL;
    part = zmsg_popstr (msg);
    if (!is_alertstate (part)) {
        free (part); part = NULL;
        zmsg_destroy (&msg);
        zmsg_t *reply  = zmsg_new ();
        zmsg_addstr (reply, "ERROR");
        zmsg_addstrf (reply, "NOT_FOUND");
        mlm_client_sendto (client, mlm_client_sender (client), "rfc-alerts-list", NULL, 5000, &reply);
        return;
    }    

    zmsg_t *reply = zmsg_new ();
    zmsg_addstr (reply, "LIST");
    zmsg_addstr (reply, part);
    bios_proto_t *cursor = (bios_proto_t *) zlistx_first (alerts);
    while (cursor) {
        if (streq (part, "ALL") || streq (part, bios_proto_state (cursor))) {
            byte *buffer = NULL;
            bios_proto_t *duplicate = bios_proto_dup (cursor);
            zmsg_t *result = bios_proto_encode (&duplicate);
            assert (result);
            size_t nbytes = zmsg_encode (result, &buffer);
            zframe_t *frame = zframe_new ((void *) buffer, nbytes);
            assert (frame);
            zmsg_destroy (&result);
            free (buffer); buffer = NULL;
            zmsg_append (reply, &frame);
        }

        cursor = (bios_proto_t *) zlistx_next (alerts);
    }
    mlm_client_sendto (client, mlm_client_sender (client), "rfc-alerts-list", NULL, 5000, &reply);
    free (part); part = NULL;
    zmsg_destroy (&msg);
    zsys_debug ("s_handle_mailbox_deliver () end.");
}

void
bios_alerts_list_server (zsock_t *pipe, void *args)
{
    static const char* endpoint = "inproc://bios-lm-server-test";
    zlistx_t *alerts = zlistx_new ();
    zlistx_set_destructor (alerts, (czmq_destructor *) bios_proto_destroy);
    zlistx_set_duplicator (alerts, (czmq_duplicator *) bios_proto_dup);

    mlm_client_t *client = mlm_client_new ();
    mlm_client_connect (client, endpoint, 1000, "ALERTS-LIST");
    mlm_client_set_consumer (client, "ALERTS", ".*");

    zpoller_t *poller = zpoller_new (pipe, mlm_client_msgpipe (client), NULL);
    zsock_signal (pipe, 0);

    while (!zsys_interrupted) {

        void *which = zpoller_wait (poller, -1);
        if (which == pipe) {
            break;
        }

        zmsg_t *msg = mlm_client_recv (client);
        if (!msg)
            break;
        if (streq (mlm_client_command (client), "MAILBOX DELIVER")) {
            if (streq (mlm_client_subject (client), "rfc-alerts-list")) {
                s_handle_mailbox_deliver (client, &msg, alerts);
            }
            else {
                zsys_warning ("Unknown protocol. Subject: '%s', Sender: '%s'.",
                    mlm_client_subject (client), mlm_client_sender (client));
            }
        }
        else if (streq (mlm_client_command (client), "STREAM DELIVER")) {
            s_handle_stream_deliver (&msg, alerts);
        }
        else {
            zsys_warning ("Unknown command '%s'. Subject: '%s', Sender: '%s'.",
                    mlm_client_command (client), mlm_client_subject (client), mlm_client_sender (client));
            zmsg_destroy (&msg);
        }
    }

    zpoller_destroy (&poller);
    mlm_client_destroy (&client);
    zlistx_destroy (&alerts);
}

//  --------------------------------------------------------------------------
//  Self test of this class.

// ---- Test Helper Functions

// request
static zmsg_t *
test_request_alerts_list (mlm_client_t *user_interface) {
    assert (user_interface);
    zmsg_t *send = zmsg_new ();
    zmsg_addstr (send, "LIST");
    zmsg_addstr (send, "ALL");
    if (mlm_client_sendto (user_interface, "ALERTS-LIST", "rfc-alerts-list", NULL, 5000, &send) != 0) {
        zmsg_destroy (&send);
        zsys_error ("mlm_client_sendto (address = 'ALERTS-LIST', subject = 'rfc-alerts-list') failed.");
        return NULL;
    }
    zmsg_t *reply = mlm_client_recv (user_interface);
    assert (streq (mlm_client_command (user_interface), "MAILBOX DELIVER"));
    assert (streq (mlm_client_sender (user_interface), "ALERTS-LIST"));
    return reply;
}

/*
typedef struct {
    char *rule, *element, *state, *severity, *description, *actions;
    uint64_t timestamp;
} alert_data;

alert_data
*/

void
bios_alerts_list_server_test (bool verbose)
{
    static const char* endpoint = "inproc://bios-lm-server-test";

    printf (" * bios_alerts_list_server:\n");

    // Malamute
    zactor_t *server = zactor_new (mlm_server, "Malamute");
    zstr_sendx (server, "BIND", endpoint, NULL);
    if (verbose)
        zstr_send (server, "VERBOSE");

    // User Interface
    mlm_client_t *ui_client = mlm_client_new ();
    mlm_client_connect (ui_client, endpoint, 1000, "UI");

    // Alert Producer
    mlm_client_t *ap_client = mlm_client_new ();
    mlm_client_connect (ap_client, endpoint, 1000, "ALERTS-PUB");
    mlm_client_set_producer (ap_client, "ALERTS");

    //  @selftest
    //  Simple create/destroy test
    zactor_t *bios_al_server = zactor_new (bios_alerts_list_server, NULL);

    zmsg_t *reply = test_request_alerts_list (ui_client);
    assert (reply);
    // Now the list should be empty
    char *part = zmsg_popstr (reply);
    assert (streq (part, "LIST"));
    free (part);
    part = zmsg_popstr (reply);
    assert (streq (part, "ALL"));
    free (part);
    part = zmsg_popstr (reply);
    assert (!part);
    zmsg_destroy (&reply);

    zmsg_t *alert = bios_proto_encode_alert (NULL, "Threshold_1", "ups-9", "ACTIVE", "high", "description", 1, "EMAIL|SMS");
    assert (alert);
    mlm_client_send (ap_client, "Threshold_1@ups-9", &alert);
    zclock_sleep (500);

    zmsg_t *foo = zmsg_new ();
    zmsg_addstr (foo, "LIST");
    zmsg_addstr (foo, "ALL");
    mlm_client_sendto (ui_client, "ALERTS-LIST", "rfc-alerts-list", NULL, 5000, &foo);
    // Now there is one alert
    reply = mlm_client_recv (ui_client);
    part = zmsg_popstr (reply);
    assert (streq (part, "LIST"));
    free (part);
    part = zmsg_popstr (reply);
    assert (streq (part, "ALL"));
    free (part);
    zframe_t *frame = zmsg_pop (reply);
    zmsg_t *decoded_zmsg = zmsg_decode (zframe_data (frame), zframe_size (frame));
zframe_destroy (&frame);
    assert (decoded_zmsg);
    bios_proto_t *decoded = bios_proto_decode (&decoded_zmsg);
    assert (decoded);
    assert (streq (bios_proto_rule (decoded), "Threshold_1"));
    assert (streq (bios_proto_element_src (decoded), "ups-9"));

    zmsg_destroy (&reply);
 
    mlm_client_destroy (&ui_client);
    mlm_client_destroy (&ap_client);
   
    zactor_destroy (&bios_al_server);
    zactor_destroy (&server);
    printf ("OK\n");
}
