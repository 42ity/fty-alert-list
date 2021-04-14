/*  =========================================================================
    fty_alert_list - description

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
    fty_alert_list -
@discuss
@end
 */

#include <czmq.h>
#include <fty_log.h>

#include "fty_alert_list_library.h"

static int
s_ttl_cleanup_timer(zloop_t *loop, int timer_id, void *output) {
    zstr_send(output, "TTLCLEANUP");
    return 0;
}

int main(int argc, char *argv []) {

    ManageFtyLog::setInstanceFtylog ("fty-alert-list", FTY_COMMON_LOGGING_DEFAULT_CFG);

    bool verbose = false;

    int argn;
    for (argn = 1; argn < argc; argn++) {
        if (streq(argv [argn], "--help") ||
                streq(argv [argn], "-h")) {
            puts("fty-alert-list [options] ...");
            puts("  --verbose / -v         verbose test output");
            puts("  --help / -h            this information");
            return EXIT_SUCCESS;
        }
        else if (streq(argv [argn], "--verbose") ||
                streq(argv [argn], "-v")) {
            verbose = true;
        }
        else {
            printf("Unknown option: %s\n", argv [argn]);
            return EXIT_FAILURE;
        }
    }

    if (verbose) ManageFtyLog::getInstanceFtylog()->setVerboseMode();

    log_info("fty-alert-list starting...");

    //  Insert main code here
    log_debug("fty-alert-list - Agent providing information about active alerts"); // TODO: rewrite alerts_list_server to accept VERBOSE

    //init the alert list (common with stream and mailbox treatment)
    init_alert(verbose); // read alerts state_file

    //initialize actors and timer for stream

    const char *endpoint = "ipc://@/malamute";
    zactor_t *alert_list_server_mailbox = zactor_new(fty_alert_list_server_mailbox, (void *) endpoint);
    if (!alert_list_server_mailbox) {
        log_fatal("alert_list_server_mailbox creation failed");
        return EXIT_FAILURE;
    }

    zactor_t *alert_list_server_stream = zactor_new(fty_alert_list_server_stream, (void *) endpoint);
    if (!alert_list_server_stream) {
        log_fatal("alert_list_server_stream creation failed");
        zactor_destroy(&alert_list_server_mailbox);
        return EXIT_FAILURE;
    }

    zloop_t *ttlcleanup_stream = zloop_new();
    if (!ttlcleanup_stream) {
        log_fatal("ttlcleanup_stream creation failed");
        zactor_destroy(&alert_list_server_stream);
        zactor_destroy(&alert_list_server_mailbox);
        return EXIT_FAILURE;
    }
    zloop_timer(ttlcleanup_stream, 60 * 1000, 0, s_ttl_cleanup_timer, alert_list_server_stream);
    zloop_start(ttlcleanup_stream);

    log_info("fty-alert-list started");
    while (!zsys_interrupted) {
        sleep(1000);
    }

    save_alerts();

    zloop_destroy(&ttlcleanup_stream);
    zactor_destroy(&alert_list_server_stream);
    zactor_destroy(&alert_list_server_mailbox);
    destroy_alert();

    log_info("fty-alert-list ended");
    return EXIT_SUCCESS;
}
