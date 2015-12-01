/*  =========================================================================
    agent_mockup - Providing information about active and resolved alerts

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

#include <czmq.h>
#include "../include/alerts-list.h"

int main (int argc, char **argv) {
    zsys_info ("alerts-list MOCKUP starting");
    char *endpoint = NULL;
    if (argc > 1)
        endpoint = strdup (argv[1]);
    else
        endpoint = strdup ("ipc://@/malamute");

    zactor_t *bios_al_server = zactor_new (alerts_list_server, (void *) endpoint);
    
    // Push some message on ALERTS stream in here
    mlm_client_t *ap_client = mlm_client_new ();
    mlm_client_connect (ap_client, endpoint, 1000, "agent-alerts-list-mockup");
    mlm_client_set_producer (ap_client, "ALERTS");

    bios_proto_t *alert = bios_proto_new (BIOS_PROTO_ALERT);
    assert (alert);
    bios_proto_set_rule (alert, "Threshold");
    bios_proto_set_element_src (alert, "ups");
    bios_proto_set_state (alert, "ACTIVE");
    bios_proto_set_severity (alert, "high");
    bios_proto_set_description (alert, "description");
    bios_proto_set_action (alert, "EMAIL");
    bios_proto_set_time (alert, 1);

    zmsg_t *zmessage = bios_proto_encode (&alert);
    assert (zmessage);
    int rv = mlm_client_send (ap_client, "Nobody here cares about this.", &zmessage);
    assert (rv == 0);
    zclock_sleep (500);

    alert = bios_proto_new (BIOS_PROTO_ALERT);
    assert (alert);
    bios_proto_set_rule (alert, "Pattern");
    bios_proto_set_element_src (alert, "epdu");
    bios_proto_set_state (alert, "ACTIVE");
    bios_proto_set_severity (alert, "high");
    bios_proto_set_description (alert, "description");
    bios_proto_set_action (alert, "EMAIL|SMS");
    bios_proto_set_time (alert, 2);

    zmessage = bios_proto_encode (&alert);
    assert (zmessage);
    rv = mlm_client_send (ap_client, "Nobody here cares about this.", &zmessage);
    assert (rv == 0);
    zclock_sleep (500);

    alert = bios_proto_new (BIOS_PROTO_ALERT);
    assert (alert);
    bios_proto_set_rule (alert, "Single");
    bios_proto_set_element_src (alert,  "ups");
    bios_proto_set_state (alert, "ACTIVE");
    bios_proto_set_severity (alert, "high");
    bios_proto_set_description (alert, "description");
    bios_proto_set_action (alert, "EMAIL|SMS");
    bios_proto_set_time (alert, 3);

    zmessage = bios_proto_encode (&alert);
    assert (zmessage);
    rv = mlm_client_send (ap_client, "Nobody here cares about this.", &zmessage);
    assert (rv == 0);
    zclock_sleep (500);

    while (!zsys_interrupted) {
        sleep (5000);
    }
    zactor_destroy (&bios_al_server);
    free (endpoint); endpoint = NULL;
    return EXIT_SUCCESS;
}
