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
    //
    // Push some message on ALERTS stream in here
    // 
    while (!zsys_interrupted) {
        sleep (5000);
    }
    zactor_destroy (&bios_al_server);
    free (endpoint); endpoint = NULL;
    return EXIT_SUCCESS;
}
