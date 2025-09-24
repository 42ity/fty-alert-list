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

#include "alerts_utils.h"
#include "fty_alert_list_server.h"

#include <fty_log.h>
#include <malamute.h>

static int s_ttl_cleanup_timer(zloop_t* /*loop*/, int /*timer_id*/, void* output)
{
    if (output) {
        zstr_send(output, "TTLCLEANUP");
    }
    return 0;
}

int main(int argc, char* argv[])
{
    const char* AGENT_NAME = "fty-alert-list";
    const char* MLM_ENDPOINT = "ipc://@/malamute";

    bool verbose = false;

    for (int i = 1; i < argc; i++) {
        const std::string arg{argv[i]};

        if ((arg == "-h") || (arg == "--help")) {
            printf("%s [options] ...\n", argv[0]);
            printf("  -v/--verbose  verbose output\n");
            printf("  -h/--help     this information\n");
            return EXIT_SUCCESS;
        }
        else if ((arg =="-v") || (arg == "--verbose")) {
            verbose = true;
        }
        else {
            fprintf(stderr, "Unknown option (%s)\n", arg.c_str());
            return EXIT_FAILURE;
        }
    }

    ManageFtyLog::setInstanceFtylog(AGENT_NAME, FTY_COMMON_LOGGING_DEFAULT_CFG);

    if (verbose) {
        ManageFtyLog::getInstanceFtylog()->setVerboseMode();
    }

    log_info("%s starting...", AGENT_NAME);

    // init/read the alerts list (common with stream and mailbox treatment)
    int r = init_alert(verbose);
    if (r != 0) {
        log_fatal("init_alert() failed");
        return EXIT_FAILURE;
    }

    // initialize actors and timer for stream

    zactor_t* alert_list_server_mailbox = zactor_new(fty_alert_list_server_mailbox, const_cast<char*>(MLM_ENDPOINT));
    if (!alert_list_server_mailbox) {
        log_fatal("alert_list_server_mailbox creation failed");
        destroy_alert();
        return EXIT_FAILURE;
    }

    zactor_t* alert_list_server_stream = zactor_new(fty_alert_list_server_stream, const_cast<char*>(MLM_ENDPOINT));
    if (!alert_list_server_stream) {
        log_fatal("alert_list_server_stream creation failed");
        zactor_destroy(&alert_list_server_mailbox);
        destroy_alert();
        return EXIT_FAILURE;
    }

    zloop_t* ttlcleanup_stream = zloop_new();
    if (!ttlcleanup_stream) {
        log_fatal("ttlcleanup_stream creation failed");
        zactor_destroy(&alert_list_server_stream);
        zactor_destroy(&alert_list_server_mailbox);
        destroy_alert();
        return EXIT_FAILURE;
    }

    r = zloop_timer(ttlcleanup_stream, 60 * 1000, 0, s_ttl_cleanup_timer, alert_list_server_stream);
    if (r < 0) {
        log_error("ttlcleanup timer registration failed");
    }
    zloop_start(ttlcleanup_stream);

    log_info("%s started", AGENT_NAME);

    // main loop, accept any message back from server
    // copy from src/malamute.c under MPL license
    while (!zsys_interrupted) {
        char* msg = zstr_recv(alert_list_server_mailbox);
        if (!msg) {
            break;
        }

        log_debug("%s: recv msg '%s'", AGENT_NAME, msg);
        zstr_free(&msg);
    }

    save_alerts();

    zloop_destroy(&ttlcleanup_stream);
    zactor_destroy(&alert_list_server_stream);
    zactor_destroy(&alert_list_server_mailbox);

    destroy_alert();

    log_info("%s ended", AGENT_NAME);

    return EXIT_SUCCESS;
}
