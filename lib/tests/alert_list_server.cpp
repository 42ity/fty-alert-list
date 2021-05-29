#include <catch2/catch.hpp>
#include "src/fty_alert_list_server.h"
#include "src/alerts_utils.h"
#include <fty_proto.h>
#include <malamute.h>
#include <fty_common_utf8.h>
#include <fty_common_macros.h>

#define RFC_ALERTS_LIST_SUBJECT        "rfc-alerts-list"
#define RFC_ALERTS_ACKNOWLEDGE_SUBJECT "rfc-alerts-acknowledge"

static zmsg_t* test_request_alerts_list(mlm_client_t* user_interface, const char* state, bool ex = false)
{
    REQUIRE(user_interface);
    REQUIRE(state);
    REQUIRE(is_list_request_state(state));

    zmsg_t* send = zmsg_new();
    REQUIRE(send);
    if (ex) {
        zmsg_addstr(send, "LIST_EX");
        zmsg_addstr(send, "1234");
    } else {
        zmsg_addstr(send, "LIST");
    }
    zmsg_addstr(send, state);
    if (mlm_client_sendto(user_interface, "fty-alert-list", RFC_ALERTS_LIST_SUBJECT, nullptr, 5000, &send) != 0) {
        zmsg_destroy(&send);
        return nullptr;
    }
    zmsg_t* reply = mlm_client_recv(user_interface);
    CHECK(streq(mlm_client_command(user_interface), "MAILBOX DELIVER"));
    CHECK(streq(mlm_client_sender(user_interface), "fty-alert-list"));
    CHECK(streq(mlm_client_subject(user_interface), RFC_ALERTS_LIST_SUBJECT));
    CHECK(reply);
    return reply;
}

static void test_request_alerts_acknowledge(mlm_client_t* ui, mlm_client_t* consumer, const char* rule,
    const char* element, const char* state, zlistx_t* alerts, int expect_fail)
{
    REQUIRE(ui);
    REQUIRE(consumer);
    REQUIRE(rule);
    REQUIRE(element);
    REQUIRE(state);
    REQUIRE(alerts);

    // Update 'state' for ('rule', 'element') in EXPECTED structure
    fty_proto_t* cursor = reinterpret_cast<fty_proto_t*>(zlistx_first(alerts));
    int          found  = 0;
    while (cursor) {
        if (is_alert_identified(cursor, rule, element)) {
            if (expect_fail == 0) {
                fty_proto_set_state(cursor, "%s", state);
            }
            found = 1;
            break;
        }
        cursor = reinterpret_cast<fty_proto_t*>(zlistx_next(alerts));
    }

    // Send the request
    zmsg_t* send = zmsg_new();
    REQUIRE(send);
    zmsg_addstr(send, rule);
    zmsg_addstr(send, element);
    zmsg_addstr(send, state);
    int rv = mlm_client_sendto(ui, "fty-alert-list", RFC_ALERTS_ACKNOWLEDGE_SUBJECT, nullptr, 5000, &send);
    REQUIRE(rv == 0);

    if (expect_fail == 0) {
        // Suck the message off stream
        zmsg_t* published = mlm_client_recv(consumer);
        REQUIRE(published);
        fty_proto_t* decoded = fty_proto_decode(&published);
        REQUIRE(decoded);
        CHECK(streq(rule, fty_proto_rule(decoded)));
        CHECK(UTF8::utf8eq(element, fty_proto_name(decoded)) == 1);
        CHECK(streq(state, fty_proto_state(decoded)));
        fty_proto_destroy(&decoded);
    }

    // Check protocol reply
    zmsg_t* reply = mlm_client_recv(ui);
    REQUIRE(reply);
    CHECK(streq(mlm_client_command(ui), "MAILBOX DELIVER"));
    CHECK(streq(mlm_client_sender(ui), "fty-alert-list"));
    CHECK(streq(mlm_client_subject(ui), RFC_ALERTS_ACKNOWLEDGE_SUBJECT));

    char* ok = zmsg_popstr(reply);
    if (expect_fail == 0) {
        char* rule_reply    = zmsg_popstr(reply);
        char* element_reply = zmsg_popstr(reply);
        char* state_reply   = zmsg_popstr(reply);
        CHECK(streq(ok, "OK"));
        CHECK(streq(rule_reply, rule));
        CHECK(UTF8::utf8eq(element_reply, element));
        CHECK(streq(state_reply, state));
        zstr_free(&rule_reply);
        zstr_free(&element_reply);
        zstr_free(&state_reply);
        CHECK(found == 1);
    } else {
        CHECK(streq(ok, "ERROR"));
        char* reason = zmsg_popstr(reply);
        CHECK((streq(reason, "BAD_STATE") || streq(reason, "NOT_FOUND")));
        if (streq(reason, "BAD_STATE")) {
            CHECK(found == 1);
        } else if (streq(reason, "NOT_FOUND")) {
            CHECK(found == 0);
        }
        zstr_free(&reason);
    }
    zstr_free(&ok);
    zmsg_destroy(&reply);
}

static int test_zlistx_same(const char* state, zlistx_t* expected, zlistx_t* received)
{
    REQUIRE(state);
    REQUIRE(expected);
    REQUIRE(received);
    fty_proto_t* cursor = reinterpret_cast<fty_proto_t*>(zlistx_first(expected));
    while (cursor) {
        if (is_state_included(state, fty_proto_state(cursor))) {
            void* handle = zlistx_find(received, cursor);
            if (!handle) {
                return 0;
            }
            zlistx_delete(received, handle);
        }
        cursor = reinterpret_cast<fty_proto_t*>(zlistx_next(expected));
    }
    if (zlistx_size(received) != 0) {
        return 0;
    }
    return 1;
}

static void test_check_result(const char* state, zlistx_t* expected, zmsg_t** reply_p, int fail)
{
    CHECK(state);
    CHECK(expected);
    CHECK(reply_p);
    if (!*reply_p) {
        return;
    }
    zmsg_t* reply = *reply_p;
    // check leading protocol frames (strings)
    char* part = zmsg_popstr(reply);
    CHECK((streq(part, "LIST") || streq(part, "LIST_EX")));
    if (streq(part, "LIST_EX")) {
        char* correlation_id = zmsg_popstr(reply);
        CHECK(streq(correlation_id, "1234"));
        free(correlation_id);
    }
    free(part);
    part = nullptr;
    part = zmsg_popstr(reply);
    CHECK(streq(part, state));
    free(part);
    part = nullptr;

    zlistx_t* received = zlistx_new();
    zlistx_set_destructor(received, reinterpret_cast<czmq_destructor*>(fty_proto_destroy));
    zlistx_set_duplicator(received, reinterpret_cast<czmq_duplicator*>(fty_proto_dup));
    zlistx_set_comparator(received, reinterpret_cast<czmq_comparator*>(alert_comparator));
    zframe_t* frame = zmsg_pop(reply);
    while (frame) {
        zmsg_t* decoded_zmsg = nullptr;
        /* Note: the CZMQ_VERSION_MAJOR comparison below actually assumes versions
         * we know and care about - v3.0.2 (our legacy default, already obsoleted
         * by upstream), and v4.x that is in current upstream master. If the API
         * evolves later (incompatibly), these macros will need to be amended.
         */
#if CZMQ_VERSION_MAJOR == 3
        decoded_zmsg = zmsg_decode(zframe_data(frame), zframe_size(frame));
#else
        decoded_zmsg = zmsg_decode(frame);
#endif
        zframe_destroy(&frame);
        REQUIRE(decoded_zmsg);
        fty_proto_t* decoded = fty_proto_decode(&decoded_zmsg);
        REQUIRE(decoded);
        CHECK(fty_proto_id(decoded) == FTY_PROTO_ALERT);
        zlistx_add_end(received, decoded);
        fty_proto_destroy(&decoded);
        frame = zmsg_pop(reply);
    }

    // compare the two by iterative substraction
    int rv = test_zlistx_same(state, expected, received);
    if (fail) {
        CHECK(rv == 0);
    } else {
        CHECK(rv == 1);
    }
    zlistx_destroy(&received);
    zmsg_destroy(reply_p);
}

static void test_alert_publish(mlm_client_t* producer, mlm_client_t* consumer, zlistx_t* alerts, fty_proto_t** message)
{
    REQUIRE(message);
    REQUIRE(*message);
    REQUIRE(alerts);
    REQUIRE(producer);
    REQUIRE(consumer);

    void* handle = zlistx_find(alerts, *message);
    if (handle) {
        fty_proto_t* item = reinterpret_cast<fty_proto_t*>(zlistx_handle_item(handle));

        fty_proto_set_rule(item, "%s", fty_proto_rule(*message));
        fty_proto_set_name(item, "%s", fty_proto_name(*message));
        fty_proto_set_severity(item, "%s", fty_proto_severity(*message));
        fty_proto_set_description(item, "%s", fty_proto_description(*message));
        zlist_t* actions;
        if (nullptr == fty_proto_action(*message)) {
            actions = zlist_new();
            zlist_autofree(actions);
        } else {
            actions = zlist_dup(fty_proto_action(*message));
        }
        fty_proto_set_action(item, &actions);

        if (streq(fty_proto_state(*message), "RESOLVED")) {
            if (!streq(fty_proto_state(item), "RESOLVED")) {
                fty_proto_set_state(item, "%s", fty_proto_state(*message));
                fty_proto_set_time(item, fty_proto_time(*message));
            }
        } else {
            if (streq(fty_proto_state(item), "RESOLVED")) {
                fty_proto_set_state(item, "%s", fty_proto_state(*message));
                fty_proto_set_time(item, fty_proto_time(*message));
            } else if (!streq(fty_proto_state(item), "ACTIVE")) {
                fty_proto_set_state(*message, "%s", fty_proto_state(item));
            }
        }
    } else {
        zlistx_add_end(alerts, *message);
    }

    fty_proto_t* copy = fty_proto_dup(*message);
    REQUIRE(copy);
    zmsg_t* zmessage = fty_proto_encode(&copy);
    REQUIRE(zmessage);
    int rv = mlm_client_send(producer, "Nobody here cares about this.", &zmessage);
    REQUIRE(rv == 0);
    zclock_sleep(100);
    zmessage = mlm_client_recv(consumer);
    REQUIRE(zmessage);
    fty_proto_t* received = fty_proto_decode(&zmessage);

    CHECK(alert_comparator(*message, received) == 0);
    fty_proto_destroy(&received);
    fty_proto_destroy(message);
}

TEST_CASE("alert list server test")
{
    #define SELFTEST_RO "tests/selftest-ro"

    static const char* endpoint = "inproc://fty-lm-server-test";

    // Malamute
    zactor_t* server = zactor_new(mlm_server, const_cast<char*>("Malamute"));
    zstr_sendx(server, "BIND", endpoint, nullptr);

    // User Interface
    mlm_client_t* ui = mlm_client_new();
    int           rv = mlm_client_connect(ui, endpoint, 1000, "UI");
    REQUIRE(rv == 0);

    // Alert Producer
    mlm_client_t* producer = mlm_client_new();
    rv                     = mlm_client_connect(producer, endpoint, 1000, "PRODUCER");
    REQUIRE(rv == 0);
    rv = mlm_client_set_producer(producer, "_ALERTS_SYS");
    REQUIRE(rv == 0);

    // Arbitrary Alert Consumer
    mlm_client_t* consumer = mlm_client_new();
    rv                     = mlm_client_connect(consumer, endpoint, 1000, "CONSUMER");
    REQUIRE(rv == 0);
    rv = mlm_client_set_consumer(consumer, "ALERTS", ".*");
    REQUIRE(rv == 0);

    // Alert Lists (assume empty)
    init_alert_private(SELFTEST_RO, "_faked_empty_alerts_", false);
    zactor_t* fty_al_server_stream  = zactor_new(fty_alert_list_server_stream, const_cast<char*>(endpoint));
    zactor_t* fty_al_server_mailbox = zactor_new(fty_alert_list_server_mailbox, const_cast<char*>(endpoint));

    // maintain a list of active alerts (that serves as "expected results")
    zlistx_t* testAlerts = zlistx_new();
    zlistx_set_destructor(testAlerts, reinterpret_cast<czmq_destructor*>(fty_proto_destroy));
    zlistx_set_duplicator(testAlerts, reinterpret_cast<czmq_duplicator*>(fty_proto_dup));
    zlistx_set_comparator(testAlerts, reinterpret_cast<czmq_comparator*>(alert_id_comparator));

    zmsg_t* reply = test_request_alerts_list(ui, "ALL");
    REQUIRE(reply);
    test_check_result("ALL", testAlerts, &reply, 0);

    reply = test_request_alerts_list(ui, "ACK-WIP");
    test_check_result("ACK-WIP", testAlerts, &reply, 0);

    reply = test_request_alerts_list(ui, "ACK-IGNORE");
    test_check_result("ACK-IGNORE", testAlerts, &reply, 0);

    reply = test_request_alerts_list(ui, "ALL-ACTIVE");
    test_check_result("ALL-ACTIVE", testAlerts, &reply, 0);

    reply = test_request_alerts_list(ui, "RESOLVED");
    test_check_result("RESOLVED", testAlerts, &reply, 0);

    // add new alert
    zlist_t* actions1 = zlist_new();
    zlist_autofree(actions1);
    zlist_append(actions1, const_cast<char*>("EMAIL"));
    zlist_append(actions1, const_cast<char*>("SMS"));
    fty_proto_t* alert = alert_new("Threshold", "ups", "ACTIVE", "high", "description", 1, &actions1, 0);
    test_alert_publish(producer, consumer, testAlerts, &alert);

    reply = test_request_alerts_list(ui, "ALL");
    test_check_result("ALL", testAlerts, &reply, 0);

    reply = test_request_alerts_list(ui, "ACK-PAUSE");
    test_check_result("ACK-PAUSE", testAlerts, &reply, 0);

    reply = test_request_alerts_list(ui, "ALL-ACTIVE");
    test_check_result("ALL-ACTIVE", testAlerts, &reply, 0);

    reply = test_request_alerts_list(ui, "RESOLVED");
    test_check_result("RESOLVED", testAlerts, &reply, 0);

    reply = test_request_alerts_list(ui, "ACTIVE");
    test_check_result("ACTIVE", testAlerts, &reply, 0);

    // add new alert
    zlist_t* actions2 = zlist_new();
    zlist_autofree(actions2);
    zlist_append(actions2, const_cast<char*>("EMAIL"));
    zlist_append(actions2, const_cast<char*>("SMS"));
    alert = alert_new("Threshold", "epdu", "ACTIVE", "high", "description", 2, &actions2, 0);
    test_alert_publish(producer, consumer, testAlerts, &alert);

    reply = test_request_alerts_list(ui, "ALL");
    test_check_result("ALL", testAlerts, &reply, 0);

    reply = test_request_alerts_list(ui, "ACTIVE");
    test_check_result("ACTIVE", testAlerts, &reply, 0);

    // add new alert
    zlist_t* actions3 = zlist_new();
    zlist_autofree(actions3);
    zlist_append(actions3, const_cast<char*>("EMAIL"));
    zlist_append(actions3, const_cast<char*>("SMS"));
    alert = alert_new("SimpleRule", "ups", "ACTIVE", "high", "description", 3, &actions3, 0);
    test_alert_publish(producer, consumer, testAlerts, &alert);

    reply = test_request_alerts_list(ui, "ALL");
    test_check_result("ALL", testAlerts, &reply, 0);

    reply = test_request_alerts_list(ui, "ACTIVE");
    test_check_result("ACTIVE", testAlerts, &reply, 0);

    // add new alert
    zlist_t* actions4 = zlist_new();
    zlist_autofree(actions4);
    zlist_append(actions4, const_cast<char*>("EMAIL"));
    zlist_append(actions4, const_cast<char*>("SMS"));
    alert = alert_new("SimpleRule", "ŽlUťOUčKý kůň супер", "ACTIVE", "high", "description", 4, &actions4, 0);
    test_alert_publish(producer, consumer, testAlerts, &alert);

    reply = test_request_alerts_list(ui, "ALL");
    test_check_result("ALL", testAlerts, &reply, 0);

    reply = test_request_alerts_list(ui, "ACTIVE");
    test_check_result("ACTIVE", testAlerts, &reply, 0);

    reply = test_request_alerts_list(ui, "ALL-ACTIVE");
    test_check_result("ALL-ACTIVE", testAlerts, &reply, 0);

    reply = test_request_alerts_list(ui, "RESOLVED");
    test_check_result("RESOLVED", testAlerts, &reply, 0);

    // add new alert
    zlist_t* actions5 = zlist_new();
    zlist_autofree(actions5);
    zlist_append(actions5, const_cast<char*>("EMAIL"));
    zlist_append(actions5, const_cast<char*>("SMS"));
    alert = alert_new("Threshold", "ŽlUťOUčKý kůň супер", "RESOLVED", "high", "description", 4, &actions5, 0);
    test_alert_publish(producer, consumer, testAlerts, &alert);

    for (bool ex : {false, true}) {
        // exercise LIST_EX a bit
        reply = test_request_alerts_list(ui, "ALL", ex);
        test_check_result("ALL", testAlerts, &reply, 0);

        reply = test_request_alerts_list(ui, "ALL-ACTIVE", ex);
        test_check_result("ALL-ACTIVE", testAlerts, &reply, 0);

        reply = test_request_alerts_list(ui, "RESOLVED", ex);
        test_check_result("RESOLVED", testAlerts, &reply, 0);

        reply = test_request_alerts_list(ui, "ACTIVE", ex);
        test_check_result("ACTIVE", testAlerts, &reply, 0);

        reply = test_request_alerts_list(ui, "ACK-SILENCE", ex);
        test_check_result("ACK-SILENCE", testAlerts, &reply, 0);
    }

    // change state (rfc-alerts-acknowledge)
    test_request_alerts_acknowledge(ui, consumer, "Threshold", "epdu", "ACK-WIP", testAlerts, 0);

    reply = test_request_alerts_list(ui, "ALL");
    test_check_result("ALL", testAlerts, &reply, 0);

    reply = test_request_alerts_list(ui, "ALL-ACTIVE");
    test_check_result("ALL-ACTIVE", testAlerts, &reply, 0);

    reply = test_request_alerts_list(ui, "RESOLVED");
    test_check_result("RESOLVED", testAlerts, &reply, 0);

    reply = test_request_alerts_list(ui, "ACK-WIP");
    test_check_result("ACK-WIP", testAlerts, &reply, 0);

    // change state back
    test_request_alerts_acknowledge(ui, consumer, "Threshold", "epdu", "ACTIVE", testAlerts, 0);

    reply = test_request_alerts_list(ui, "ALL");
    test_check_result("ALL", testAlerts, &reply, 0);

    reply = test_request_alerts_list(ui, "ALL-ACTIVE");
    test_check_result("ALL-ACTIVE", testAlerts, &reply, 0);

    reply = test_request_alerts_list(ui, "RESOLVED");
    test_check_result("RESOLVED", testAlerts, &reply, 0);

    reply = test_request_alerts_list(ui, "ACTIVE");
    test_check_result("ACTIVE", testAlerts, &reply, 0);

    // change state of two alerts
    test_request_alerts_acknowledge(ui, consumer, "Threshold", "ups", "ACK-PAUSE", testAlerts, 0);
    test_request_alerts_acknowledge(ui, consumer, "SimpleRule", "ups", "ACK-PAUSE", testAlerts, 0);

    reply = test_request_alerts_list(ui, "ALL");
    test_check_result("ALL", testAlerts, &reply, 0);

    reply = test_request_alerts_list(ui, "ALL-ACTIVE");
    test_check_result("ALL-ACTIVE", testAlerts, &reply, 0);

    reply = test_request_alerts_list(ui, "RESOLVED");
    test_check_result("RESOLVED", testAlerts, &reply, 0);

    reply = test_request_alerts_list(ui, "ACK-PAUSE");
    test_check_result("ACK-PAUSE", testAlerts, &reply, 0);

    reply = test_request_alerts_list(ui, "ACK-SILENCE");
    test_check_result("ACK-SILENCE", testAlerts, &reply, 0);

    // some more state changes
    test_request_alerts_acknowledge(ui, consumer, "SimpleRule", "ups", "ACK-WIP", testAlerts, 0);
    test_request_alerts_acknowledge(ui, consumer, "Threshold", "ups", "ACK-SILENCE", testAlerts, 0);
    test_request_alerts_acknowledge(ui, consumer, "SimpleRule", "ŽlUťOučKý Kůň супер", "ACK-SILENCE", testAlerts, 0);
    test_request_alerts_acknowledge(ui, consumer, "Threshold", "epdu", "ACK-PAUSE", testAlerts, 0);
    // alerts/ack RESOLVED->anything must fail
    test_request_alerts_acknowledge(ui, consumer, "Threshold", "ŽlUťOUčKý Kůň супер", "ACTIVE", testAlerts, 1);
    test_request_alerts_acknowledge(ui, consumer, "Threshold", "ŽlUťOUčKý kůň супер", "ACK-WIP", testAlerts, 1);
    test_request_alerts_acknowledge(ui, consumer, "Threshold", "ŽLuťOUčKý kůň супер", "ACK-IGNORE", testAlerts, 1);
    test_request_alerts_acknowledge(ui, consumer, "Threshold", "ŽlUťOUčKý kůň супер", "ACK-SILENCE", testAlerts, 1);
    test_request_alerts_acknowledge(ui, consumer, "Threshold", "ŽlUťOUčKý kůň супер", "ACK-PAUSE", testAlerts, 1);

    reply = test_request_alerts_list(ui, "ALL");
    test_check_result("ALL", testAlerts, &reply, 0);

    reply = test_request_alerts_list(ui, "ALL-ACTIVE");
    test_check_result("ALL-ACTIVE", testAlerts, &reply, 0);

    reply = test_request_alerts_list(ui, "ACTIVE");
    test_check_result("ACTIVE", testAlerts, &reply, 0);

    reply = test_request_alerts_list(ui, "ACK-WIP");
    test_check_result("ACK-WIP", testAlerts, &reply, 0);

    reply = test_request_alerts_list(ui, "ACK-IGNORE");
    test_check_result("ACK-IGNORE", testAlerts, &reply, 0);

    reply = test_request_alerts_list(ui, "ACK-PAUSE");
    test_check_result("ACK-PAUSE", testAlerts, &reply, 0);

    reply = test_request_alerts_list(ui, "ACK-SILENCE");
    test_check_result("ACK-SILENCE", testAlerts, &reply, 0);

    reply = test_request_alerts_list(ui, "RESOLVED");
    test_check_result("RESOLVED", testAlerts, &reply, 0);

    // resolve alert
    zlist_t* actions6 = zlist_new();
    zlist_autofree(actions6);
    zlist_append(actions6, const_cast<char*>("EMAIL"));
    zlist_append(actions6, const_cast<char*>("SMS"));
    alert = alert_new("SimpleRule", "Žluťoučký kůň супер", "RESOLVED", "high", "description", 13, &actions6, 0);
    test_alert_publish(producer, consumer, testAlerts, &alert);

    reply = test_request_alerts_list(ui, "ALL");
    test_check_result("ALL", testAlerts, &reply, 0);

    reply = test_request_alerts_list(ui, "ALL-ACTIVE");
    test_check_result("ALL-ACTIVE", testAlerts, &reply, 0);

    reply = test_request_alerts_list(ui, "RESOLVED");
    test_check_result("RESOLVED", testAlerts, &reply, 0);

    // test: For non-RESOLVED alerts timestamp of when first published is stored
    zlist_t* actions7 = zlist_new();
    zlist_autofree(actions7);
    zlist_append(actions7, const_cast<char*>("EMAIL"));
    zlist_append(actions7, const_cast<char*>("SMS"));
    alert = alert_new("#1549", "epdu", "ACTIVE", "high", "description", uint64_t(time(nullptr)), &actions7, 0);
    test_alert_publish(producer, consumer, testAlerts, &alert);

    reply = test_request_alerts_list(ui, "ALL");
    test_check_result("ALL", testAlerts, &reply, 0);

    test_request_alerts_acknowledge(ui, consumer, "#1549", "epdu", "ACTIVE", testAlerts, 0);

    reply = test_request_alerts_list(ui, "ALL");
    test_check_result("ALL", testAlerts, &reply, 0);

    test_request_alerts_acknowledge(ui, consumer, "#1549", "epdu", "ACTIVE", testAlerts, 0);

    reply = test_request_alerts_list(ui, "ALL");
    test_check_result("ALL", testAlerts, &reply, 0);

    test_request_alerts_acknowledge(ui, consumer, "#1549", "epdu", "ACK-WIP", testAlerts, 0);

    reply = test_request_alerts_list(ui, "ALL");
    test_check_result("ALL", testAlerts, &reply, 0);

    test_request_alerts_acknowledge(ui, consumer, "#1549", "epdu", "ACK-IGNORE", testAlerts, 0);

    reply = test_request_alerts_list(ui, "ALL");
    test_check_result("ALL", testAlerts, &reply, 0);

    test_request_alerts_acknowledge(ui, consumer, "#1549", "epdu", "ACK-PAUSE", testAlerts, 0);

    reply = test_request_alerts_list(ui, "ALL");
    test_check_result("ALL", testAlerts, &reply, 0);

    test_request_alerts_acknowledge(ui, consumer, "#1549", "epdu", "ACK-SILENCE", testAlerts, 0);

    reply = test_request_alerts_list(ui, "ALL");
    test_check_result("ALL", testAlerts, &reply, 0);

    test_request_alerts_acknowledge(ui, consumer, "#1549", "epdu", "ACTIVE", testAlerts, 0);

    reply = test_request_alerts_list(ui, "ALL");
    test_check_result("ALL", testAlerts, &reply, 0);

    reply = test_request_alerts_list(ui, "ACTIVE");
    test_check_result("ACTIVE", testAlerts, &reply, 0);

    zlist_t* actions8 = zlist_new();
    zlist_autofree(actions8);
    zlist_append(actions8, const_cast<char*>("EMAIL"));
    zlist_append(actions8, const_cast<char*>("SMS"));
    alert = alert_new("#1549", "epdu", "RESOLVED", "high", "description", uint64_t(time(nullptr)) + 8, &actions8, 0);
    test_alert_publish(producer, consumer, testAlerts, &alert);

    reply = test_request_alerts_list(ui, "ALL");
    test_check_result("ALL", testAlerts, &reply, 0);

    reply = test_request_alerts_list(ui, "ACTIVE");
    test_check_result("ACTIVE", testAlerts, &reply, 0);

    reply = test_request_alerts_list(ui, "RESOLVED");
    test_check_result("RESOLVED", testAlerts, &reply, 0);

    reply = test_request_alerts_list(ui, "ALL-ACTIVE");
    test_check_result("ALL-ACTIVE", testAlerts, &reply, 0);

    zlist_t* actions9 = zlist_new();
    zlist_autofree(actions9);
    zlist_append(actions9, const_cast<char*>("EMAIL"));
    zlist_append(actions9, const_cast<char*>("SMS"));
    alert = alert_new("#1549", "epdu", "ACTIVE", "high", "description", uint64_t(time(nullptr)) + 9, &actions9, 0);
    test_alert_publish(producer, consumer, testAlerts, &alert);

    reply = test_request_alerts_list(ui, "ALL");
    test_check_result("ALL", testAlerts, &reply, 0);

    reply = test_request_alerts_list(ui, "ACTIVE");
    test_check_result("ACTIVE", testAlerts, &reply, 0);

    reply = test_request_alerts_list(ui, "RESOLVED");
    test_check_result("RESOLVED", testAlerts, &reply, 0);

    reply = test_request_alerts_list(ui, "ALL-ACTIVE");
    test_check_result("ALL-ACTIVE", testAlerts, &reply, 0);

    test_request_alerts_acknowledge(ui, consumer, "#1549", "epdu", "ACK-IGNORE", testAlerts, 0);

    reply = test_request_alerts_list(ui, "ALL");
    test_check_result("ALL", testAlerts, &reply, 0);

    // Now, let's publish an alert as-a-byspass (i.e. we don't add it to expected)
    // and EXPECT A FAILURE (i.e. expected list != received list)
    zlist_t* actions10 = zlist_new();
    zlist_autofree(actions10);
    zlist_append(actions10, const_cast<char*>("EMAIL"));
    zlist_append(actions10, const_cast<char*>("SMS"));
    zmsg_t* alert_bypass =
        fty_proto_encode_alert(nullptr, 14, 0, "Pattern", "rack", "ACTIVE", "high", "description", actions10);
    rv = mlm_client_send(producer, "Nobody cares", &alert_bypass);
    REQUIRE(rv == 0);
    zclock_sleep(200);
    alert_bypass = mlm_client_recv(consumer);
    REQUIRE(alert_bypass);
    zmsg_destroy(&alert_bypass);

    reply = test_request_alerts_list(ui, "ALL");
    test_check_result("ALL", testAlerts, &reply, 1);

    reply = test_request_alerts_list(ui, "ACTIVE");
    test_check_result("ACTIVE", testAlerts, &reply, 1);

    reply = test_request_alerts_list(ui, "RESOLVED");
    test_check_result("RESOLVED", testAlerts, &reply, 0);

    reply = test_request_alerts_list(ui, "ACK-WIP");
    test_check_result("ACK-WIP", testAlerts, &reply, 0);

    reply = test_request_alerts_list(ui, "ALL-ACTIVE");
    test_check_result("ALL-ACTIVE", testAlerts, &reply, 1);

    zlist_t* actions11 = zlist_new();
    zlist_autofree(actions11);
    zlist_append(actions11, const_cast<char*>("EMAIL"));
    zlist_append(actions11, const_cast<char*>("SMS"));
    alert_bypass = fty_proto_encode_alert(nullptr, 15, 0, "Pattern", "rack", "RESOLVED", "high", "description", actions11);
    mlm_client_send(producer, "Nobody cares", &alert_bypass);
    REQUIRE(rv == 0);
    zclock_sleep(100);
    alert_bypass = mlm_client_recv(consumer);
    REQUIRE(alert_bypass);
    zmsg_destroy(&alert_bypass);

    reply = test_request_alerts_list(ui, "ALL");
    test_check_result("ALL", testAlerts, &reply, 1);

    reply = test_request_alerts_list(ui, "ACTIVE");
    test_check_result("ACTIVE", testAlerts, &reply, 0);

    reply = test_request_alerts_list(ui, "RESOLVED");
    test_check_result("RESOLVED", testAlerts, &reply, 1);

    reply = test_request_alerts_list(ui, "ACK-WIP");
    test_check_result("ACK-WIP", testAlerts, &reply, 0);

    reply = test_request_alerts_list(ui, "ALL-ACTIVE");
    test_check_result("ALL-ACTIVE", testAlerts, &reply, 0);

    zlist_t* actions12 = zlist_new();
    zlist_autofree(actions12);
    zlist_append(actions12, const_cast<char*>("EMAIL"));
    zlist_append(actions12, const_cast<char*>("SMS"));
    alert = alert_new("BlackBooks", "store", "ACTIVE", "high", "description", 16, &actions12, 2);
    test_alert_publish(producer, consumer, testAlerts, &alert);

    reply = test_request_alerts_list(ui, "ACTIVE");
    test_check_result("ACTIVE", testAlerts, &reply, 0);

    // early cleanup should not change the alert
    zstr_send(fty_al_server_stream, "TTLCLEANUP");
    reply = test_request_alerts_list(ui, "ACTIVE");
    test_check_result("ACTIVE", testAlerts, &reply, 0);

    zclock_sleep(3000);

    // cleanup should resolv alert
    zstr_send(fty_al_server_stream, "TTLCLEANUP");
    reply = test_request_alerts_list(ui, "RESOLVED");
    test_check_result("RESOLVED", testAlerts, &reply, 1);

    // RESOLVED used to be an error response, but it's no more true
    zmsg_t* send = zmsg_new();
    zmsg_addstr(send, "LIST");
    zmsg_addstr(send, "RESOLVED");
    rv = mlm_client_sendto(ui, "fty-alert-list", RFC_ALERTS_LIST_SUBJECT, nullptr, 5000, &send);
    REQUIRE(rv == 0);
    reply = mlm_client_recv(ui);
    CHECK(streq(mlm_client_command(ui), "MAILBOX DELIVER"));
    CHECK(streq(mlm_client_sender(ui), "fty-alert-list"));
    CHECK(streq(mlm_client_subject(ui), RFC_ALERTS_LIST_SUBJECT));
    char* part = zmsg_popstr(reply);
    CHECK(streq(part, "LIST"));
    zstr_free(&part);
    part = zmsg_popstr(reply);
    CHECK(streq(part, "RESOLVED"));
    zstr_free(&part);
    zmsg_destroy(&reply);

    // Now, let's test an error response of rfc-alerts-list
    send = zmsg_new();
    zmsg_addstr(send, "LIST");
    zmsg_addstr(send, "ACTIVE-ALL");
    rv = mlm_client_sendto(ui, "fty-alert-list", RFC_ALERTS_LIST_SUBJECT, nullptr, 5000, &send);
    REQUIRE(rv == 0);
    reply = mlm_client_recv(ui);
    CHECK(streq(mlm_client_command(ui), "MAILBOX DELIVER"));
    CHECK(streq(mlm_client_sender(ui), "fty-alert-list"));
    CHECK(streq(mlm_client_subject(ui), RFC_ALERTS_LIST_SUBJECT));
    part = zmsg_popstr(reply);
    CHECK(streq(part, "ERROR"));
    zstr_free(&part);
    part = zmsg_popstr(reply);
    CHECK(streq(part, "NOT_FOUND"));
    zstr_free(&part);
    zmsg_destroy(&reply);

    send = zmsg_new();
    zmsg_addstr(send, "LIST");
    zmsg_addstr(send, "Karolino");
    rv = mlm_client_sendto(ui, "fty-alert-list", RFC_ALERTS_LIST_SUBJECT, nullptr, 5000, &send);
    REQUIRE(rv == 0);
    reply = mlm_client_recv(ui);
    CHECK(streq(mlm_client_command(ui), "MAILBOX DELIVER"));
    CHECK(streq(mlm_client_sender(ui), "fty-alert-list"));
    CHECK(streq(mlm_client_subject(ui), RFC_ALERTS_LIST_SUBJECT));
    part = zmsg_popstr(reply);
    CHECK(streq(part, "ERROR"));
    zstr_free(&part);
    part = zmsg_popstr(reply);
    CHECK(streq(part, "NOT_FOUND"));
    zstr_free(&part);
    zmsg_destroy(&reply);

    send = zmsg_new();
    zmsg_addstr(send, "Hatatitla");
    zmsg_addstr(send, "Karolino");
    rv = mlm_client_sendto(ui, "fty-alert-list", RFC_ALERTS_LIST_SUBJECT, nullptr, 5000, &send);
    zclock_sleep(100);
    REQUIRE(rv == 0);
    reply = mlm_client_recv(ui);
    CHECK(streq(mlm_client_command(ui), "MAILBOX DELIVER"));
    CHECK(streq(mlm_client_sender(ui), "fty-alert-list"));
    CHECK(streq(mlm_client_subject(ui), RFC_ALERTS_LIST_SUBJECT));
    part = zmsg_popstr(reply);
    CHECK(streq(part, "ERROR"));
    zstr_free(&part);
    part = zmsg_popstr(reply);
    CHECK(part);
    zstr_free(&part);
    zmsg_destroy(&reply);

    // Now, let's test an error response of rfc-alerts-acknowledge
    send = zmsg_new();
    zmsg_addstr(send, "rule");
    zmsg_addstr(send, "element");
    zmsg_addstr(send, "state");
    rv = mlm_client_sendto(ui, "fty-alert-list", "sdfgrw rweg", nullptr, 5000, &send);
    zclock_sleep(100);
    REQUIRE(rv == 0);
    reply = mlm_client_recv(ui);
    part  = zmsg_popstr(reply);
    CHECK(streq(part, "ERROR"));
    zstr_free(&part);
    part            = zmsg_popstr(reply);
    std::string err = TRANSLATE_ME("UNKNOWN_PROTOCOL");
    CHECK(streq(part, err.c_str()));
    zstr_free(&part);
    zmsg_destroy(&reply);

    send = zmsg_new();
    zmsg_addstr(send, "rule");
    zmsg_addstr(send, "element");
    rv = mlm_client_sendto(ui, "fty-alert-list", RFC_ALERTS_ACKNOWLEDGE_SUBJECT, nullptr, 5000, &send);
    zclock_sleep(100);
    REQUIRE(rv == 0);
    reply = mlm_client_recv(ui);
    part  = zmsg_popstr(reply);
    CHECK(streq(part, "ERROR"));
    zstr_free(&part);
    part = zmsg_popstr(reply);
    err  = TRANSLATE_ME("BAD_MESSAGE");
    CHECK(streq(part, err.c_str()));
    zstr_free(&part);
    zmsg_destroy(&reply);

    send = zmsg_new();
    zmsg_addstr(send, "rule");
    zmsg_addstr(send, "element");
    zmsg_addstr(send, "ACTIVE");
    rv = mlm_client_sendto(ui, "fty-alert-list", RFC_ALERTS_ACKNOWLEDGE_SUBJECT, nullptr, 5000, &send);
    zclock_sleep(100);
    REQUIRE(rv == 0);
    reply = mlm_client_recv(ui);
    part  = zmsg_popstr(reply);
    CHECK(streq(part, "ERROR"));
    zstr_free(&part);
    part = zmsg_popstr(reply);
    CHECK(streq(part, "NOT_FOUND"));
    zstr_free(&part);
    zmsg_destroy(&reply);

    send = zmsg_new();
    zmsg_addstr(send, "SimpleRule");
    zmsg_addstr(send, "ups");
    zmsg_addstr(send, "ignac!");
    rv = mlm_client_sendto(ui, "fty-alert-list", RFC_ALERTS_ACKNOWLEDGE_SUBJECT, nullptr, 5000, &send);
    zclock_sleep(100);
    REQUIRE(rv == 0);
    reply = mlm_client_recv(ui);
    part  = zmsg_popstr(reply);
    CHECK(streq(part, "ERROR"));
    zstr_free(&part);
    part = zmsg_popstr(reply);
    CHECK(streq(part, "BAD_STATE"));
    zstr_free(&part);
    zmsg_destroy(&reply);

    send = zmsg_new();
    zmsg_addstr(send, "SimpleRule");
    zmsg_addstr(send, "ups");
    zmsg_addstr(send, "RESOLVED");
    rv = mlm_client_sendto(ui, "fty-alert-list", RFC_ALERTS_ACKNOWLEDGE_SUBJECT, nullptr, 5000, &send);
    zclock_sleep(100);
    REQUIRE(rv == 0);
    reply = mlm_client_recv(ui);
    part  = zmsg_popstr(reply);
    CHECK(streq(part, "ERROR"));
    zstr_free(&part);
    part = zmsg_popstr(reply);
    CHECK(streq(part, "BAD_STATE"));
    zstr_free(&part);
    zmsg_destroy(&reply);

    zlistx_destroy(&testAlerts);

    save_alerts();
    zactor_destroy(&fty_al_server_mailbox);
    zactor_destroy(&fty_al_server_stream);
    mlm_client_destroy(&consumer);
    mlm_client_destroy(&producer);
    mlm_client_destroy(&ui);
    zactor_destroy(&server);
    destroy_alert();

    if (nullptr != actions1)
        zlist_destroy(&actions1);
    if (nullptr != actions2)
        zlist_destroy(&actions2);
    if (nullptr != actions3)
        zlist_destroy(&actions3);
    if (nullptr != actions4)
        zlist_destroy(&actions4);
    if (nullptr != actions5)
        zlist_destroy(&actions5);
    if (nullptr != actions6)
        zlist_destroy(&actions6);
    if (nullptr != actions7)
        zlist_destroy(&actions7);
    if (nullptr != actions8)
        zlist_destroy(&actions8);
    if (nullptr != actions9)
        zlist_destroy(&actions9);
    if (nullptr != actions10)
        zlist_destroy(&actions10);
    if (nullptr != actions11)
        zlist_destroy(&actions11);
    if (nullptr != actions12)
        zlist_destroy(&actions12);

    printf("OK\n");
}
