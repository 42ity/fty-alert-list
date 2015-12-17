/*  =========================================================================
    generate_alert - Testing tool for publishing alerts on ALERTS stream

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
#include "../include/alerts_list.h"

int main (int argc, char **argv) {
    char *endpoint = NULL;
    
    if (argc < 7) {
        fprintf (stderr, "USAGE:\n\tgenerate_alert <rule_name> <element_name> <state> <severity> <description> <unixtime> <action[|action2[|...]]> [endpoint]\n");
        fprintf (stderr, "\nOPTIONAL ARGUMENTS:\n\tendpoint\tMalamute endpoint. Default: ipc://@/malamute.\n");
        return EXIT_FAILURE;
    }

    // check unixtime
    char **endptr = NULL;
    errno = 0;
    unsigned long int unixtime = strtoul (argv[6], endptr, 10);
    if (endptr != NULL || errno != 0) {
        zsys_error ("<unixtime> parameter = '%s' is not a valid unix time", argv[6]);
        return EXIT_FAILURE;
    }

    if (argc > 8)
        endpoint = strdup (argv[8]);
    else
        endpoint = strdup ("ipc://@/malamute");

    mlm_client_t *client = mlm_client_new ();
    srand ((unsigned) time (NULL));
    char *strtemp = NULL;
    int rv = asprintf (&strtemp, "generate_alert.%d%d", rand () % 10, rand () % 10);
    if (rv == -1) {
        zsys_error ("asprintf() failed");
        free (endpoint); endpoint = NULL;
        mlm_client_destroy (&client);
        return EXIT_FAILURE;
    }
    mlm_client_connect (client, endpoint, 1000, strtemp);
    free (strtemp); strtemp = NULL;
    mlm_client_set_producer (client, "ALERTS");

    zmsg_t *alert_message = bios_proto_encode_alert (
            NULL,
            argv[1],
            argv[2],
            argv[3],
            argv[4],
            argv[5],
            unixtime,
            argv[7]);
    if (!alert_message) {
        zsys_error ("bios_proto_encode_alert() failed");
        free (endpoint); endpoint = NULL;
        mlm_client_destroy (&client);
        return EXIT_FAILURE;
    }

    // rule_name/severity@element_name
    rv = asprintf (&strtemp, "%s/%s@%s", argv[1], argv[4], argv[2]);
    if (rv == -1) {
        zsys_error ("asprintf() failed");
        free (endpoint); endpoint = NULL;
        mlm_client_destroy (&client);
        return EXIT_FAILURE;
    }   
    rv = mlm_client_send (client, strtemp, &alert_message);
    free (strtemp); strtemp = NULL;
    if (rv != 0) {
        zsys_error ("mlm_client_send () failed");
        free (endpoint); endpoint = NULL;
        mlm_client_destroy (&client);
        return EXIT_FAILURE;
    }
    free (endpoint); endpoint = NULL;
    mlm_client_destroy (&client);
    return EXIT_SUCCESS;
}
