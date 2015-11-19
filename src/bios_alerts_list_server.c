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

static void
s_handle_stream_deliver (zmsg_t** msg_p, zlistx_t *alerts) {
    zmsg_t *msg = *msg_p;
    bios_proto_t *alert = bios_proto_decode (&msg);
    if (!alert)
        return;

    zlistx_add_end (alerts, alert);

    bios_proto_print (alert);
    bios_proto_destroy (&alert);
    zmsg_destroy (&msg);
}

static void
s_handle_mailbox_deliver (mlm_client_t *client, zmsg_t** msg_p, zlistx_t *alerts) {
    assert (msg_p && *msg_p);
    zmsg_t *msg = *msg_p;

    zmsg_t *reply = zmsg_new ();
    zmsg_addstrf (reply, "%zu", zlistx_size (alerts));

    mlm_client_sendto (client, mlm_client_sender (client), "ALERTS-LIST-OK", NULL, 5000, &reply);

    zmsg_destroy (&msg);
}

void
bios_alerts_list_server (zsock_t *pipe, void *args)
{
    static const char* endpoint = "inproc://bios-lm-server-test";
    zlistx_t *alerts = zlistx_new ();

    mlm_client_t *client = mlm_client_new ();
    mlm_client_connect (client, endpoint, 1000, "ALERTS-LIST");
    mlm_client_set_consumer (client, "ALERTS", ".*");

    zpoller_t *poller = zpoller_new (pipe, mlm_client_msgpipe (client), NULL);

    zsock_signal (pipe, 0);

    while (!zsys_interrupted) {

        void *which = zpoller_wait (poller, -1);
        if (which == pipe)
            break;

        zmsg_t *msg = mlm_client_recv (client);

        if (streq (mlm_client_command (client), "MAILBOX DELIVER")) {
            s_handle_mailbox_deliver (client, &msg, alerts);
        }
        else
        if (streq (mlm_client_command (client), "STREAM DELIVER")) {
            s_handle_stream_deliver (&msg, alerts);
        }
        else {
            zmsg_destroy (&msg);
        }
    }

    zpoller_destroy (&poller);
    mlm_client_destroy (&client);
    zlistx_destroy (&alerts);
}

//  --------------------------------------------------------------------------
//  Self test of this class.

void
bios_alerts_list_server_test (bool verbose)
{
    static const char* endpoint = "inproc://bios-lm-server-test";

    printf (" * bios_alerts_list_server: ");
    if (verbose)
        printf ("\n");

    zactor_t *server = zactor_new (mlm_server, "Malamute");
    zstr_sendx (server, "BIND", endpoint, NULL);
    if (verbose)
        zstr_send (server, "VERBOSE");

    mlm_client_t *ui_client = mlm_client_new ();
    mlm_client_connect (ui_client, endpoint, 1000, "UI");

    mlm_client_t *ap_client = mlm_client_new ();
    mlm_client_connect (ap_client, endpoint, 1000, "ALERTS-PUB");
    mlm_client_set_producer (ap_client, "ALERTS");

    //  @selftest
    //  Simple create/destroy test
    zactor_t *bios_al_server = zactor_new (bios_alerts_list_server, NULL);

    zmsg_t *foo = zmsg_new ();
    zmsg_addstrf (foo, "ALERTS-%s", "LIST");
    mlm_client_sendto (ui_client, "ALERTS-LIST", "ALERTS-LIST", NULL, 5000, &foo);
    zmsg_t *reply = mlm_client_recv (ui_client);
    char *size = zmsg_popstr (reply);

    assert (streq (size, "0"));

    zmsg_destroy (&reply);
    zstr_free (&size);

    zmsg_t *alert = bios_proto_encode_alert (NULL, "rule", "element_src", "state", "severity", "desription", 1024, "action");
    assert (alert);
    mlm_client_send (ap_client, "rule@element_src", &alert);
    zclock_sleep (500);

    foo = zmsg_new ();
    zmsg_addstrf (foo, "ALERTS-%s", "LIST");
    mlm_client_sendto (ui_client, "ALERTS-LIST", "ALERTS-LIST", NULL, 5000, &foo);
    reply = mlm_client_recv (ui_client);
    size = zmsg_popstr (reply);

    assert (streq (size, "1"));
    zmsg_destroy (&reply);
    zstr_free (&size);

    mlm_client_destroy (&ui_client);
    mlm_client_destroy (&ap_client);
    zactor_destroy (&bios_al_server);
    zactor_destroy (&server);
    printf ("OK\n");
}
