#include "src/alerts_utils.h"
#include <catch2/catch.hpp>
#include <fty_common_utf8.h>

TEST_CASE("alerts utils test")
{
#define SELFTEST_RO "tests/selftest-ro"
#define SELFTEST_RW "."

    //  **************************************
    //  *****   s_string_encode/decode   *****
    //  **************************************

    {
        // clang-format off
        const char* test[] = {
            "",
            "0",
            "01",
            "012",
            "0123",
            "01234",
            "012345",
            "0123456",
            "01234567",
            "012345678",
            "0123456789",

            "UTF-8: HЯɅȤ",
            "UTF-8: ሰማይ አይታረስ ንጉሥ አይከሰስ።",
            "UTF-8: ⡍⠜⠇⠑⠹ ⠺⠁⠎ ⠙⠑⠁⠙⠒ ⠞⠕ ⠃",

            "hello world!",
            "hello world!    ",
            "{ hello world! }",
            "{ \"hello\": \"world!\" }",

            "{"
            "  \"name\": \"John\","
            "  \"age\": 30,"
            "  \"cars\": ["
            "    { \"name\": \"Ford\", \"models\": [ \"Fiesta\", \"Focus\", \"Mustang\" ] },"
            "    { \"name\": \"BMW\",  \"models\": [ \"320\", \"X3\", \"X5\" ] },"
            "    { \"name\": \"Fiat\", \"models\": [ \"500\", \"Panda\" ] }"
            "  ]"
            "}",

            nullptr
        };
        // clang-format on

        CHECK(s_string_encode(nullptr) == nullptr);
        CHECK(s_string_decode(nullptr) == nullptr);

        for (int i = 0; test[i]; i++) {
            const char* message = test[i];

            char* encoded = s_string_encode(message);
            CHECK(encoded);

            char* decoded = s_string_decode(encoded);
            CHECK(decoded);
            CHECK(streq(message, decoded));

            zstr_free(&encoded);
            zstr_free(&decoded);
        }
    }

    //  ************************************
    //  *****   is_acknowledge_state   *****
    //  ************************************

    CHECK(is_acknowledge_state("ACK-WIP") == 1);
    CHECK(is_acknowledge_state("ACK-IGNORE") == 1);
    CHECK(is_acknowledge_state("ACK-PAUSE") == 1);
    CHECK(is_acknowledge_state("ACK-SILENCE") == 1);

    CHECK(is_acknowledge_state("ACTIVE") == 0);
    CHECK(is_acknowledge_state("active") == 0);
    CHECK(is_acknowledge_state("RESOLVED") == 0);
    CHECK(is_acknowledge_state("RESOLVE") == 0);
    CHECK(is_acknowledge_state("resolve") == 0);
    CHECK(is_acknowledge_state("ack-wip") == 0);
    CHECK(is_acknowledge_state("ALL") == 0);
    CHECK(is_acknowledge_state("ALL-ACTIVE") == 0);
    CHECK(is_acknowledge_state("all") == 0);
    CHECK(is_acknowledge_state("all-active") == 0);
    CHECK(is_acknowledge_state("") == 0);
    CHECK(is_acknowledge_state(nullptr) == 0);
    CHECK(is_acknowledge_state("ACK-xyfd") == 0);
    CHECK(is_acknowledge_state("aCK-WIP") == 0);
    CHECK(is_acknowledge_state("ACKWIP") == 0);
    CHECK(is_acknowledge_state("somethign") == 0);

    //  ******************************
    //  *****   is_alert_state   *****
    //  ******************************

    CHECK(is_alert_state("ACTIVE") == 1);
    CHECK(is_alert_state("ACK-WIP") == 1);
    CHECK(is_alert_state("ACK-IGNORE") == 1);
    CHECK(is_alert_state("ACK-PAUSE") == 1);
    CHECK(is_alert_state("ACK-SILENCE") == 1);
    CHECK(is_alert_state("RESOLVED") == 1);

    CHECK(is_alert_state("ALL") == 0);
    CHECK(is_alert_state("ALL-ACTIVE") == 0);
    CHECK(is_alert_state("") == 0);
    CHECK(is_alert_state(nullptr) == 0);
    CHECK(is_alert_state("all") == 0);
    CHECK(is_alert_state("active") == 0);
    CHECK(is_alert_state("ACK") == 0);
    CHECK(is_alert_state("ack-wip") == 0);
    CHECK(is_alert_state("resolved") == 0);

    //  *************************************
    //  *****   is_list_request_state   *****
    //  *************************************

    CHECK(is_list_request_state("ACTIVE") == 1);
    CHECK(is_list_request_state("ACK-WIP") == 1);
    CHECK(is_list_request_state("ACK-IGNORE") == 1);
    CHECK(is_list_request_state("ACK-PAUSE") == 1);
    CHECK(is_list_request_state("ACK-SILENCE") == 1);
    CHECK(is_list_request_state("RESOLVED") == 1);
    CHECK(is_list_request_state("ALL") == 1);
    CHECK(is_list_request_state("ALL-ACTIVE") == 1);

    CHECK(is_list_request_state("All") == 0);
    CHECK(is_list_request_state("all") == 0);
    CHECK(is_list_request_state("Active") == 0);
    CHECK(is_list_request_state("active") == 0);
    CHECK(is_list_request_state("ack-wip") == 0);
    CHECK(is_list_request_state("resolved") == 0);
    CHECK(is_list_request_state("") == 0);
    CHECK(is_list_request_state(nullptr) == 0);
    CHECK(is_list_request_state("sdfsd") == 0);

    //  *********************************
    //  *****   is_state_included   *****
    //  *********************************

    CHECK(is_state_included("ALL", "ACTIVE") == 1);
    CHECK(is_state_included("ALL", "ACK-WIP") == 1);
    CHECK(is_state_included("ALL", "ACK-IGNORE") == 1);
    CHECK(is_state_included("ALL", "ACK-PAUSE") == 1);
    CHECK(is_state_included("ALL", "ACK-SILENCE") == 1);
    CHECK(is_state_included("ALL", "RESOLVED") == 1);

    CHECK(is_state_included("ALL-ACTIVE", "ACTIVE") == 1);
    CHECK(is_state_included("ALL-ACTIVE", "ACK-WIP") == 1);
    CHECK(is_state_included("ALL-ACTIVE", "ACK-IGNORE") == 1);
    CHECK(is_state_included("ALL-ACTIVE", "ACK-PAUSE") == 1);
    CHECK(is_state_included("ALL-ACTIVE", "ACK-SILENCE") == 1);
    CHECK(is_state_included("ALL-ACTIVE", "RESOLVED") == 0);

    CHECK(is_state_included("ACTIVE", "ACTIVE") == 1);
    CHECK(is_state_included("ACK-WIP", "ACK-WIP") == 1);
    CHECK(is_state_included("ACK-IGNORE", "ACK-IGNORE") == 1);
    CHECK(is_state_included("ACK-SILENCE", "ACK-SILENCE") == 1);
    CHECK(is_state_included("RESOLVED", "RESOLVED") == 1);

    CHECK(is_state_included("ACTIVE", "ALL") == 0);
    CHECK(is_state_included("ACTIVE", "RESOLVED") == 0);
    CHECK(is_state_included("ACTIVE", "ALL-ACTIVE") == 0);
    CHECK(is_state_included("ALL", "ALL-ACTIVE") == 0);
    CHECK(is_state_included("ALL-ACTIVE", "ALL-ACTIVE") == 0);
    CHECK(is_state_included("ALL", "ALL") == 0);
    CHECK(is_state_included("ACK-WIP", "ACTIVE") == 0);
    CHECK(is_state_included("ACK-IGNORE", "ACK-WIP") == 0);

    //  *********************************************
    //  *****   is_acknowledge_request_state    *****
    //  *********************************************

    CHECK(is_acknowledge_request_state("ACTIVE") == 1);
    CHECK(is_acknowledge_request_state("ACK-WIP") == 1);
    CHECK(is_acknowledge_request_state("ACK-IGNORE") == 1);
    CHECK(is_acknowledge_request_state("ACTIVE") == 1);
    CHECK(is_acknowledge_request_state("ACTIVE") == 1);

    CHECK(is_acknowledge_request_state("ALL") == 0);
    CHECK(is_acknowledge_request_state("RESOLVED") == 0);
    CHECK(is_acknowledge_request_state("ALL-ACTIVE") == 0);
    CHECK(is_acknowledge_request_state("active") == 0);
    CHECK(is_acknowledge_request_state("") == 0);
    CHECK(is_acknowledge_request_state(nullptr) == 0);

    //  **************************
    //  *****   alert_new    *****
    //  **************************
    {
        zlist_t* actions = zlist_new();
        zlist_autofree(actions);
        zlist_append(actions, const_cast<char*>(ACTION_EMAIL));
        zlist_append(actions, const_cast<char*>(ACTION_SMS));
        fty_proto_t* alert = alert_new("Threshold", "ups", "ACTIVE", "high", "description", 1, &actions, 0);
        CHECK(streq(fty_proto_rule(alert), "Threshold"));
        CHECK(streq(fty_proto_name(alert), "ups"));
        CHECK(streq(fty_proto_state(alert), "ACTIVE"));
        CHECK(streq(fty_proto_severity(alert), "high"));
        CHECK(streq(fty_proto_description(alert), "description"));
        CHECK(streq(fty_proto_action_first(alert), "EMAIL"));
        CHECK(streq(fty_proto_action_next(alert), "SMS"));
        CHECK(nullptr == fty_proto_action_next(alert));
        CHECK(fty_proto_time(alert) == 1);
        fty_proto_destroy(&alert);
        if (nullptr != actions)
            zlist_destroy(&actions);

        actions = zlist_new();
        zlist_autofree(actions);
        zlist_append(actions, const_cast<char*>(ACTION_SMS));
        zlist_append(actions, const_cast<char*>("Holub"));
        zlist_append(actions, const_cast<char*>("Morse code"));
        alert = alert_new("Simple@Rule@Because", "karolkove zelezo", "ACTIVE", "high Severity",
            "Holiday \nInn hotel 243", 10101795, &actions, 0);
        CHECK(streq(fty_proto_rule(alert), "Simple@Rule@Because"));
        CHECK(streq(fty_proto_name(alert), "karolkove zelezo"));
        CHECK(streq(fty_proto_state(alert), "ACTIVE"));
        CHECK(streq(fty_proto_severity(alert), "high Severity"));
        CHECK(streq(fty_proto_description(alert), "Holiday \nInn hotel 243"));
        CHECK(streq(fty_proto_action_first(alert), "SMS"));
        CHECK(streq(fty_proto_action_next(alert), "Holub"));
        CHECK(streq(fty_proto_action_next(alert), "Morse code"));
        CHECK(nullptr == fty_proto_action_next(alert));
        CHECK(fty_proto_time(alert) == 10101795);
        fty_proto_destroy(&alert);
        if (nullptr != actions)
            zlist_destroy(&actions);
    }

    //  ************************************
    //  *****   alert_id_comparator    *****
    //  ************************************


    // test case 1a:
    //  alerts are completely the same
    {
        zlist_t* actions1 = zlist_new();
        zlist_autofree(actions1);
        zlist_append(actions1, const_cast<char*>(ACTION_EMAIL));
        fty_proto_t* alert1 =
            alert_new("temperature.average@DC-Roztoky", "ups-9", "ACTIVE", "some description", "low", 10, &actions1, 0);
        CHECK(alert1);
        zlist_t* actions2 = zlist_new();
        zlist_autofree(actions2);
        zlist_append(actions2, const_cast<char*>(ACTION_EMAIL));
        fty_proto_t* alert2 =
            alert_new("temperature.average@DC-Roztoky", "ups-9", "ACTIVE", "some description", "low", 10, &actions2, 0);
        CHECK(alert2);

        CHECK(alert_id_comparator(alert1, alert2) == 0);

        if (nullptr != actions1)
            zlist_destroy(&actions1);
        if (nullptr != actions2)
            zlist_destroy(&actions2);
        fty_proto_destroy(&alert1);
        fty_proto_destroy(&alert2);
    }

    // test case 1b:
    //  alerts have the same identifier,
    //  different meta-data which represents real world use case of one alert
    //  at two different times
    {
        zlist_t* actions1 = zlist_new();
        zlist_autofree(actions1);
        zlist_append(actions1, const_cast<char*>(ACTION_EMAIL));
        fty_proto_t* alert1 =
            alert_new("temperature.average@DC-Roztoky", "ups-9", "ACTIVE", "some description", "low", 10, &actions1, 0);
        CHECK(alert1);
        zlist_t* actions2 = zlist_new();
        zlist_autofree(actions2);
        zlist_append(actions2, const_cast<char*>(ACTION_SMS));
        fty_proto_t* alert2 = alert_new(
            "temperature.average@DC-Roztoky", "ups-9", "ACK-IGNORE", "some description", "high", 10, &actions2, 0);
        CHECK(alert2);

        CHECK(alert_id_comparator(alert1, alert2) == 0);

        if (nullptr != actions1)
            zlist_destroy(&actions1);
        if (nullptr != actions2)
            zlist_destroy(&actions2);
        fty_proto_destroy(&alert1);
        fty_proto_destroy(&alert2);
    }

    // test case 1c:
    //  alerts have the same identifier,
    //  different as well as missing meta-data
    {
        zlist_t* actions1 = zlist_new();
        zlist_autofree(actions1);
        zlist_append(actions1, const_cast<char*>(ACTION_EMAIL));
        fty_proto_t* alert1 =
            alert_new("temperature.average@DC-Roztoky", "ups-9", "ACK-WIP", nullptr, "high", 10, &actions1, 0);
        CHECK(alert1);
        zlist_t* actions2 = zlist_new();
        zlist_autofree(actions2);
        fty_proto_t* alert2 =
            alert_new("temperature.average@DC-Roztoky", "ups-9", "ACTIVE", "some description", "low", 20, &actions2, 0);
        CHECK(alert2);

        CHECK(alert_id_comparator(alert1, alert2) == 0);

        if (nullptr != actions1)
            zlist_destroy(&actions1);
        if (nullptr != actions2)
            zlist_destroy(&actions2);
        fty_proto_destroy(&alert1);
        fty_proto_destroy(&alert2);
    }

    // test case 1d:
    //  alerts have the same identifier - rule name has different case
    //  different as well as missing meta-data
    {
        zlist_t* actions1 = zlist_new();
        zlist_autofree(actions1);
        zlist_append(actions1, const_cast<char*>(ACTION_EMAIL));
        fty_proto_t* alert1 =
            alert_new("temperature.average@DC-Roztoky", "ups-9", "ACK-WIP", nullptr, "high", 10, &actions1, 0);
        CHECK(alert1);
        zlist_t* actions2 = zlist_new();
        zlist_autofree(actions2);
        fty_proto_t* alert2 =
            alert_new("Temperature.Average@dC-roztoky", "ups-9", "ACTIVE", "some description", "low", 20, &actions2, 0);
        CHECK(alert2);

        CHECK(alert_id_comparator(alert1, alert2) == 0);

        if (nullptr != actions1)
            zlist_destroy(&actions1);
        if (nullptr != actions2)
            zlist_destroy(&actions2);
        fty_proto_destroy(&alert1);
        fty_proto_destroy(&alert2);
    }

    // test case 2a:
    // alerts don't have the same identifier - different rule

    {
        zlist_t* actions1 = zlist_new();
        zlist_autofree(actions1);
        fty_proto_t* alert1 =
            alert_new("temperature.average@DC-Lab", "ups-9", "ACK-WIP", nullptr, "high", 10, &actions1, 0);
        CHECK(alert1);
        zlist_t* actions2 = zlist_new();
        zlist_autofree(actions2);
        fty_proto_t* alert2 =
            alert_new("temperature.average@DC-Roztoky", "ups-9", "ACTIVE", nullptr, "low", 20, &actions2, 0);
        CHECK(alert2);

        CHECK(alert_id_comparator(alert1, alert2) == 1);

        if (nullptr != actions1)
            zlist_destroy(&actions1);
        if (nullptr != actions2)
            zlist_destroy(&actions2);
        fty_proto_destroy(&alert1);
        fty_proto_destroy(&alert2);
    }

    // test case 2b:
    // alerts don't have the same identifier - different element_src

    {
        zlist_t* actions1 = zlist_new();
        zlist_autofree(actions1);
        fty_proto_t* alert1 =
            alert_new("temperature.average@DC-Roztoky", "epdu", "ACK-WIP", "xcuy;v weohuif", "high", 10, &actions1, 0);
        CHECK(alert1);
        zlist_t* actions2 = zlist_new();
        zlist_autofree(actions2);
        fty_proto_t* alert2 =
            alert_new("temperature.average@DC-Roztoky", "ups-9", "ACTIVE", nullptr, "low", 20, &actions2, 0);
        CHECK(alert2);

        CHECK(alert_id_comparator(alert1, alert2) == 1);

        if (nullptr != actions1)
            zlist_destroy(&actions1);
        if (nullptr != actions2)
            zlist_destroy(&actions2);
        fty_proto_destroy(&alert1);
        fty_proto_destroy(&alert2);
    }

    // test case 2c:
    // alerts do have the same identifier - case of element_src is ignored now

    {
        zlist_t* actions1 = zlist_new();
        zlist_autofree(actions1);
        fty_proto_t* alert1 =
            alert_new("temperature.average@DC-Roztoky", "Ups-9", "ACK-WIP", nullptr, "high", 10, &actions1, 0);
        CHECK(alert1);
        zlist_t* actions2 = zlist_new();
        zlist_autofree(actions2);
        fty_proto_t* alert2 =
            alert_new("temperature.average@DC-Roztoky", "ups-9", "ACTIVE", nullptr, "low", 20, &actions2, 0);
        CHECK(alert2);

        CHECK(alert_id_comparator(alert1, alert2) == 0);

        if (nullptr != actions1)
            zlist_destroy(&actions1);
        if (nullptr != actions2)
            zlist_destroy(&actions2);
        fty_proto_destroy(&alert1);
        fty_proto_destroy(&alert2);
    }


    // test case 3:
    // alerts don't have the same identifier -different element_src, rule
    {
        zlist_t* actions1 = zlist_new();
        zlist_autofree(actions1);
        fty_proto_t* alert1 =
            alert_new("temperature.average@DC-Roztoky", "epdu", "ACK-WIP", nullptr, "high", 10, &actions1, 0);
        CHECK(alert1);
        zlist_t* actions2 = zlist_new();
        zlist_autofree(actions2);
        fty_proto_t* alert2 =
            alert_new("temperature.humidity@DC-Roztoky", "ups-9", "ACTIVE", nullptr, "low", 20, &actions2, 0);
        CHECK(alert2);

        CHECK(alert_id_comparator(alert1, alert2) == 1);

        if (nullptr != actions1)
            zlist_destroy(&actions1);
        if (nullptr != actions2)
            zlist_destroy(&actions2);
        fty_proto_destroy(&alert1);
        fty_proto_destroy(&alert2);
    }

    // unicode
    {
        zlist_t* actions1 = zlist_new();
        zlist_autofree(actions1);
        zlist_append(actions1, const_cast<char*>(ACTION_EMAIL));
        fty_proto_t* alert1 = alert_new(
            "realpower.DeFault", "ŽlUťOUčKý kůň супер", "ACTIVE", "some description", "low", 10, &actions1, 0);
        CHECK(alert1);
        zlist_t* actions2 = zlist_new();
        zlist_autofree(actions2);
        zlist_append(actions2, const_cast<char*>(ACTION_EMAIL));
        zlist_append(actions2, const_cast<char*>(ACTION_SMS));
        fty_proto_t* alert2 = alert_new("realpower.default", "\u017dlu\u0165ou\u010dk\xc3\xbd K\u016f\xc5\x88 супер",
            "ACK-SILENCE", "some description 2", "high", 100, &actions2, 0);
        CHECK(alert2);

        CHECK(alert_id_comparator(alert1, alert2) == 0);

        if (nullptr != actions1)
            zlist_destroy(&actions1);
        if (nullptr != actions2)
            zlist_destroy(&actions2);
        fty_proto_destroy(&alert1);
        fty_proto_destroy(&alert2);
    }

    {
        zlist_t* actions1 = zlist_new();
        zlist_autofree(actions1);
        zlist_append(actions1, const_cast<char*>(ACTION_EMAIL));
        fty_proto_t* alert1 = alert_new(
            "realpower.DeFault", "Žluťoučký kůň супер ", "ACTIVE", "some description", "low", 10, &actions1, 0);
        CHECK(alert1);
        zlist_t* actions2 = zlist_new();
        zlist_autofree(actions2);
        zlist_append(actions2, const_cast<char*>(ACTION_EMAIL));
        zlist_append(actions2, const_cast<char*>(ACTION_SMS));
        fty_proto_t* alert2 = alert_new(
            "realpower.default", "Žluťoučký kůň супер", "ACK-SILENCE", "some description 2", "high", 100, &actions2, 0);
        CHECK(alert2);

        CHECK(alert_id_comparator(alert1, alert2) == 1);

        if (nullptr != actions1)
            zlist_destroy(&actions1);
        if (nullptr != actions2)
            zlist_destroy(&actions2);
        fty_proto_destroy(&alert1);
        fty_proto_destroy(&alert2);
    }

    //  *************************************
    //  *****   is_alert_identified     *****
    //  *************************************
    {
        zlist_t* actions = zlist_new();
        zlist_autofree(actions);
        zlist_append(actions, const_cast<char*>(ACTION_EMAIL));
        fty_proto_t* alert =
            alert_new("temperature.average@DC-Roztoky", "ups-9", "ACTIVE", "some description", "low", 10, &actions, 0);
        CHECK(alert);
        CHECK(is_alert_identified(alert, "temperature.average@DC-Roztoky", "ups-9") == 1);
        CHECK(is_alert_identified(alert, "Temperature.Average@dC-Roztoky", "ups-9") == 1);
        CHECK(is_alert_identified(alert, "humidity@DC-Roztoky", "ups-9") == 0);
        CHECK(is_alert_identified(alert, "", "ups-9") == 0);
        CHECK(is_alert_identified(alert, "temperature.average@DC-Roztoky", "") == 0);
        CHECK(is_alert_identified(alert, "temperature.average@DC-Roztoky", "epDU") == 0);
        CHECK(is_alert_identified(alert, "Temperature.Average@dC-Roztoky", "epDU") == 0);
        fty_proto_destroy(&alert);
        if (nullptr != actions)
            zlist_destroy(&actions);
    }

    {
        zlist_t* actions = zlist_new();
        zlist_autofree(actions);
        zlist_append(actions, const_cast<char*>(ACTION_EMAIL));
        fty_proto_t* alert = alert_new(
            "temperature.average@DC-Roztoky", "ta2€супер14159", "ACTIVE", "some description", "low", 10, &actions, 0);
        CHECK(alert);
        CHECK(is_alert_identified(alert, "temperature.average@DC-Roztoky", "ups-9") == 0);
        CHECK(is_alert_identified(
                  alert, "temperature.average@dc-roztoky", "ta2\u20ac\u0441\u0443\u043f\u0435\u044014159") == 1);
        fty_proto_destroy(&alert);
        if (nullptr != actions)
            zlist_destroy(&actions);
    }

    {
        zlist_t* actions = zlist_new();
        zlist_autofree(actions);
        zlist_append(actions, const_cast<char*>(ACTION_EMAIL));
        fty_proto_t* alert = alert_new(
            "temperature.average@DC-Roztoky", "ŽlUťOUčKý kůň", "ACTIVE", "some description", "low", 10, &actions, 0);
        CHECK(alert);
        CHECK(is_alert_identified(alert, "temperature.average@dc-roztoky", "ŽlUťOUčKý kůň") == 1);
        CHECK(is_alert_identified(alert, "temperature.averageDC-Roztoky", "ŽlUťOUčKý kůň") == 0);
        fty_proto_destroy(&alert);
        if (nullptr != actions)
            zlist_destroy(&actions);
    }

    //  *********************************
    //  *****   alert_comparator    *****
    //  *********************************

    // test case 1a:
    //  alerts are completelly the same
    {
        zlist_t* actions1 = zlist_new();
        zlist_autofree(actions1);
        zlist_append(actions1, const_cast<char*>(ACTION_SMS));
        fty_proto_t* alert1 =
            alert_new("temperature.average@DC-Roztoky", "ups-9", "ACTIVE", "low", "some description", 10, &actions1, 0);
        CHECK(alert1);
        zlist_t* actions2 = zlist_new();
        zlist_autofree(actions2);
        zlist_append(actions2, const_cast<char*>(ACTION_SMS));
        fty_proto_t* alert2 =
            alert_new("temperature.average@DC-Roztoky", "ups-9", "ACTIVE", "low", "some description", 10, &actions2, 0);
        CHECK(alert2);

        CHECK(alert_comparator(alert1, alert2) == 0);

        if (nullptr != actions1)
            zlist_destroy(&actions1);
        if (nullptr != actions2)
            zlist_destroy(&actions2);
        fty_proto_destroy(&alert1);
        fty_proto_destroy(&alert2);
    }

    // test case 1b:
    //  alerts are same - rule different case
    {
        zlist_t* actions1 = zlist_new();
        zlist_autofree(actions1);
        zlist_append(actions1, const_cast<char*>(ACTION_SMS));
        fty_proto_t* alert1 =
            alert_new("temperature.average@DC-Roztoky", "ups-9", "ACTIVE", "low", "some description", 10, &actions1, 0);
        CHECK(alert1);
        zlist_t* actions2 = zlist_new();
        zlist_autofree(actions2);
        zlist_append(actions2, const_cast<char*>(ACTION_SMS));
        fty_proto_t* alert2 =
            alert_new("temperature.average@dC-Roztoky", "ups-9", "ACTIVE", "low", "some description", 10, &actions2, 0);
        CHECK(alert2);

        CHECK(alert_comparator(alert1, alert2) == 0);

        if (nullptr != actions1)
            zlist_destroy(&actions1);
        if (nullptr != actions2)
            zlist_destroy(&actions2);
        fty_proto_destroy(&alert1);
        fty_proto_destroy(&alert2);
    }

    // test case 2:
    //  other fields are case sensitive

    //  severity is case sensitive
    {
        zlist_t* actions1 = zlist_new();
        zlist_autofree(actions1);
        zlist_append(actions1, const_cast<char*>(ACTION_SMS));
        fty_proto_t* alert1 =
            alert_new("temperature.average@DC-Roztoky", "ups-9", "ACTIVE", "low", "some description", 10, &actions1, 0);
        CHECK(alert1);
        zlist_t* actions2 = zlist_new();
        zlist_autofree(actions2);
        zlist_append(actions2, const_cast<char*>(ACTION_SMS));
        fty_proto_t* alert2 =
            alert_new("temperature.average@DC-Roztoky", "ups-9", "ACTIVE", "lOw", "some description", 10, &actions2, 0);
        CHECK(alert2);

        CHECK(alert_comparator(alert1, alert2) == 1);

        if (nullptr != actions1)
            zlist_destroy(&actions1);
        if (nullptr != actions2)
            zlist_destroy(&actions2);
        fty_proto_destroy(&alert1);
        fty_proto_destroy(&alert2);
    }

    //  state is case sensitive
    {
        zlist_t* actions1 = zlist_new();
        zlist_autofree(actions1);
        zlist_append(actions1, const_cast<char*>(ACTION_SMS));
        fty_proto_t* alert1 =
            alert_new("temperature.average@DC-Roztoky", "ups-9", "aCTIVE", "low", "some description", 10, &actions1, 0);
        CHECK(alert1);
        zlist_t* actions2 = zlist_new();
        zlist_autofree(actions2);
        zlist_append(actions2, const_cast<char*>(ACTION_SMS));
        fty_proto_t* alert2 =
            alert_new("temperature.average@DC-Roztoky", "ups-9", "ACTIVE", "low", "some description", 10, &actions2, 0);
        CHECK(alert2);

        CHECK(alert_comparator(alert1, alert2) == 1);

        if (nullptr != actions1)
            zlist_destroy(&actions1);
        if (nullptr != actions2)
            zlist_destroy(&actions2);
        fty_proto_destroy(&alert1);
        fty_proto_destroy(&alert2);
    }

    //  element_src is case insensitive
    {
        zlist_t* actions1 = zlist_new();
        zlist_autofree(actions1);
        zlist_append(actions1, const_cast<char*>(ACTION_SMS));
        fty_proto_t* alert1 =
            alert_new("temperature.average@DC-Roztoky", "ups-9", "ACTIVE", "low", "some description", 10, &actions1, 0);
        CHECK(alert1);
        zlist_t* actions2 = zlist_new();
        zlist_autofree(actions2);
        zlist_append(actions2, const_cast<char*>(ACTION_SMS));
        fty_proto_t* alert2 =
            alert_new("temperature.average@DC-Roztoky", "Ups-9", "ACTIVE", "low", "some description", 10, &actions2, 0);
        CHECK(alert2);

        CHECK(alert_comparator(alert1, alert2) == 0);

        if (nullptr != actions1)
            zlist_destroy(&actions1);
        if (nullptr != actions2)
            zlist_destroy(&actions2);
        fty_proto_destroy(&alert1);
        fty_proto_destroy(&alert2);
    }

    //  description is case sensitive
    {
        zlist_t* actions1 = zlist_new();
        zlist_autofree(actions1);
        zlist_append(actions1, const_cast<char*>(ACTION_SMS));
        fty_proto_t* alert1 =
            alert_new("temperature.average@DC-Roztoky", "ups-9", "ACTIVE", "low", "some description", 10, &actions1, 0);
        CHECK(alert1);
        zlist_t* actions2 = zlist_new();
        zlist_autofree(actions2);
        zlist_append(actions2, const_cast<char*>(ACTION_SMS));
        fty_proto_t* alert2 =
            alert_new("temperature.average@DC-Roztoky", "ups-9", "ACTIVE", "low", "some Description", 10, &actions2, 0);
        CHECK(alert2);

        CHECK(alert_comparator(alert1, alert2) == 1);

        if (nullptr != actions1)
            zlist_destroy(&actions1);
        if (nullptr != actions2)
            zlist_destroy(&actions2);
        fty_proto_destroy(&alert1);
        fty_proto_destroy(&alert2);
    }

    //  time is different
    {
        zlist_t* actions1 = zlist_new();
        zlist_autofree(actions1);
        zlist_append(actions1, const_cast<char*>(ACTION_SMS));
        fty_proto_t* alert1 =
            alert_new("temperature.average@DC-Roztoky", "ups-9", "ACTIVE", "low", "some description", 10, &actions1, 0);
        CHECK(alert1);
        zlist_t* actions2 = zlist_new();
        zlist_autofree(actions2);
        zlist_append(actions2, const_cast<char*>(ACTION_SMS));
        fty_proto_t* alert2 =
            alert_new("temperature.average@DC-Roztoky", "ups-9", "ACTIVE", "low", "some description", 35, &actions2, 0);
        CHECK(alert2);

        CHECK(alert_comparator(alert1, alert2) == 1);

        if (nullptr != actions1)
            zlist_destroy(&actions1);
        if (nullptr != actions2)
            zlist_destroy(&actions2);
        fty_proto_destroy(&alert1);
        fty_proto_destroy(&alert2);
    }

    // test case 2g:
    //  action is case sensitive
    {
        zlist_t* actions1 = zlist_new();
        zlist_autofree(actions1);
        zlist_append(actions1, const_cast<char*>(ACTION_SMS));
        fty_proto_t* alert1 =
            alert_new("temperature.average@DC-Roztoky", "ups-9", "ACTIVE", "low", "some description", 10, &actions1, 0);
        CHECK(alert1);
        zlist_t* actions2 = zlist_new();
        zlist_autofree(actions2);
        zlist_append(actions2, const_cast<char*>("sms"));
        fty_proto_t* alert2 =
            alert_new("temperature.average@DC-Roztoky", "ups-9", "ACTIVE", "low", "some description", 10, &actions2, 0);
        CHECK(alert2);

        CHECK(alert_comparator(alert1, alert2) == 1);

        if (nullptr != actions1)
            zlist_destroy(&actions1);
        if (nullptr != actions2)
            zlist_destroy(&actions2);
        fty_proto_destroy(&alert1);
        fty_proto_destroy(&alert2);
    }

    // test case 3a:
    //  fields missing in both messages are equal
    {
        zlist_t* actions1 = zlist_new();
        zlist_autofree(actions1);
        fty_proto_t* alert1 =
            alert_new("temperature.average@DC-Roztoky", nullptr, "ACTIVE", nullptr, nullptr, 10, &actions1, 0);
        CHECK(alert1);
        zlist_t* actions2 = zlist_new();
        zlist_autofree(actions2);
        fty_proto_t* alert2 =
            alert_new("temperature.average@DC-Roztoky", nullptr, "ACTIVE", nullptr, nullptr, 10, &actions2, 0);
        CHECK(alert2);

        CHECK(alert_comparator(alert1, alert2) == 0);

        if (nullptr != actions1)
            zlist_destroy(&actions1);
        if (nullptr != actions2)
            zlist_destroy(&actions2);
        fty_proto_destroy(&alert1);
        fty_proto_destroy(&alert2);
    }

    // test case 3b:
    //  fields missing in either of messages is not equal
    {
        zlist_t* actions1 = zlist_new();
        zlist_autofree(actions1);
        zlist_append(actions1, const_cast<char*>(ACTION_SMS));
        fty_proto_t* alert1 =
            alert_new("temperature.average@DC-Roztoky", "ups-9", "ACTIVE", "low", nullptr, 10, &actions1, 0);
        CHECK(alert1);
        zlist_t* actions2 = zlist_new();
        zlist_autofree(actions2);
        zlist_append(actions2, const_cast<char*>(ACTION_SMS));
        fty_proto_t* alert2 =
            alert_new("temperature.average@DC-Roztoky", "ups-9", "ACTIVE", "low", "some description", 10, &actions2, 0);
        CHECK(alert2);

        CHECK(alert_comparator(alert1, alert2) == 1);

        if (nullptr != actions1)
            zlist_destroy(&actions1);
        if (nullptr != actions2)
            zlist_destroy(&actions2);
        fty_proto_destroy(&alert1);
        fty_proto_destroy(&alert2);
    }

    {
        zlist_t* actions1 = zlist_new();
        zlist_autofree(actions1);
        zlist_append(actions1, const_cast<char*>(ACTION_SMS));
        fty_proto_t* alert1 =
            alert_new("temperature.average@DC-Roztoky", "ups-9", "ACTIVE", "low", "some description", 10, &actions1, 0);
        CHECK(alert1);
        zlist_t* actions2 = zlist_new();
        zlist_autofree(actions2);
        zlist_append(actions2, const_cast<char*>(ACTION_SMS));
        fty_proto_t* alert2 = alert_new(nullptr, "ups-9", "ACTIVE", "low", "some description", 10, &actions2, 0);
        CHECK(alert2);

        CHECK(alert_comparator(alert1, alert2) == 1);

        if (nullptr != actions1)
            zlist_destroy(&actions1);
        if (nullptr != actions2)
            zlist_destroy(&actions2);
        fty_proto_destroy(&alert1);
        fty_proto_destroy(&alert2);
    }

    {
        zlist_t* actions1 = zlist_new();
        zlist_autofree(actions1);
        zlist_append(actions1, const_cast<char*>(ACTION_SMS));
        fty_proto_t* alert1 =
            alert_new("temperature.average@DC-Roztoky", nullptr, "ACTIVE", "low", "some description", 10, &actions1, 0);
        CHECK(alert1);
        zlist_t* actions2 = zlist_new();
        zlist_autofree(actions2);
        zlist_append(actions2, const_cast<char*>(ACTION_SMS));
        fty_proto_t* alert2 =
            alert_new("temperature.average@DC-Roztoky", "ups-9", "ACTIVE", "low", "some description", 10, &actions2, 0);
        CHECK(alert2);

        CHECK(alert_comparator(alert1, alert2) == 1);

        if (nullptr != actions1)
            zlist_destroy(&actions1);
        if (nullptr != actions2)
            zlist_destroy(&actions2);
        fty_proto_destroy(&alert1);
        fty_proto_destroy(&alert2);
    }

    // test case 4:
    //  different fields
    {
        zlist_t* actions1 = zlist_new();
        zlist_autofree(actions1);
        zlist_append(actions1, const_cast<char*>(ACTION_SMS));
        fty_proto_t* alert1 =
            alert_new("temperature.average@DC-Roztoky", "ups-9", "ACTIVE", "low", "some description", 10, &actions1, 0);
        CHECK(alert1);
        zlist_t* actions2 = zlist_new();
        zlist_autofree(actions2);
        zlist_append(actions2, const_cast<char*>(ACTION_SMS));
        fty_proto_t* alert2 = alert_new(
            "temperature.humidity@DC-Roztoky", "ups-9", "ACTIVE", "low", "some description", 10, &actions2, 0);
        CHECK(alert2);

        CHECK(alert_comparator(alert1, alert2) == 1);

        if (nullptr != actions1)
            zlist_destroy(&actions1);
        if (nullptr != actions2)
            zlist_destroy(&actions2);
        fty_proto_destroy(&alert1);
        fty_proto_destroy(&alert2);
    }

    {
        zlist_t* actions1 = zlist_new();
        zlist_autofree(actions1);
        zlist_append(actions1, const_cast<char*>(ACTION_SMS));
        fty_proto_t* alert1 =
            alert_new("temperature.average@DC-Roztoky", "ups-9", "ACTIVE", "low", "some description", 10, &actions1, 0);
        CHECK(alert1);
        zlist_t* actions2 = zlist_new();
        zlist_autofree(actions2);
        zlist_append(actions2, const_cast<char*>(ACTION_SMS));
        fty_proto_t* alert2 =
            alert_new("temperature.average@DC-Roztoky", "epdu", "ACTIVE", "low", "some description", 10, &actions2, 0);
        CHECK(alert2);

        CHECK(alert_comparator(alert1, alert2) == 1);

        if (nullptr != actions1)
            zlist_destroy(&actions1);
        if (nullptr != actions2)
            zlist_destroy(&actions2);
        fty_proto_destroy(&alert1);
        fty_proto_destroy(&alert2);
    }

    {
        zlist_t* actions1 = zlist_new();
        zlist_autofree(actions1);
        zlist_append(actions1, const_cast<char*>(ACTION_SMS));
        fty_proto_t* alert1 =
            alert_new("temperature.average@DC-Roztoky", "epdu", "ACTIVE", "hugh", "some description", 10, &actions1, 0);
        CHECK(alert1);
        zlist_t* actions2 = zlist_new();
        zlist_autofree(actions2);
        zlist_append(actions2, const_cast<char*>(ACTION_SMS));
        fty_proto_t* alert2 =
            alert_new("temperature.average@DC-Roztoky", "epdu", "ACTIVE", "low", "some description", 10, &actions2, 0);
        CHECK(alert2);

        CHECK(alert_comparator(alert1, alert2) == 1);

        if (nullptr != actions1)
            zlist_destroy(&actions1);
        if (nullptr != actions2)
            zlist_destroy(&actions2);
        fty_proto_destroy(&alert1);
        fty_proto_destroy(&alert2);
    }

    {
        zlist_t* actions1 = zlist_new();
        zlist_autofree(actions1);
        zlist_append(actions1, const_cast<char*>(ACTION_SMS));
        fty_proto_t* alert1 =
            alert_new("temperature.average@DC-Roztoky", "epdu", "ACTIVE", "low", "some description", 10, &actions1, 0);
        CHECK(alert1);
        zlist_t* actions2 = zlist_new();
        zlist_autofree(actions2);
        zlist_append(actions2, const_cast<char*>(ACTION_SMS));
        fty_proto_t* alert2 =
            alert_new("temperature.average@DC-Roztoky", "epdu", "ACK-WIP", "low", "some description", 10, &actions2, 0);
        CHECK(alert2);

        CHECK(alert_comparator(alert1, alert2) == 1);

        if (nullptr != actions1)
            zlist_destroy(&actions1);
        if (nullptr != actions2)
            zlist_destroy(&actions2);
        fty_proto_destroy(&alert1);
        fty_proto_destroy(&alert2);
    }

    {
        zlist_t* actions1 = zlist_new();
        zlist_autofree(actions1);
        zlist_append(actions1, const_cast<char*>(ACTION_SMS));
        fty_proto_t* alert1 = alert_new(
            "temperature.average@DC-Roztoky", "epdu", "ACK-WIP", "low", "shitty description", 10, &actions1, 0);
        CHECK(alert1);
        zlist_t* actions2 = zlist_new();
        zlist_autofree(actions2);
        zlist_append(actions2, const_cast<char*>(ACTION_SMS));
        fty_proto_t* alert2 =
            alert_new("temperature.average@DC-Roztoky", "epdu", "ACK-WIP", "low", "some description", 10, &actions2, 0);
        CHECK(alert2);

        CHECK(alert_comparator(alert1, alert2) == 1);

        if (nullptr != actions1)
            zlist_destroy(&actions1);
        if (nullptr != actions2)
            zlist_destroy(&actions2);
        fty_proto_destroy(&alert1);
        fty_proto_destroy(&alert2);
    }

    {
        zlist_t* actions1 = zlist_new();
        zlist_autofree(actions1);
        zlist_append(actions1, const_cast<char*>(ACTION_SMS));
        fty_proto_t* alert1 =
            alert_new("temperature.average@DC-Roztoky", "epdu", "ACK-WIP", "low", "some description", 1, &actions1, 0);
        CHECK(alert1);
        zlist_t* actions2 = zlist_new();
        zlist_autofree(actions2);
        zlist_append(actions2, const_cast<char*>(ACTION_SMS));
        fty_proto_t* alert2 =
            alert_new("temperature.average@DC-Roztoky", "epdu", "ACK-WIP", "low", "some description", 10, &actions2, 0);
        CHECK(alert2);

        CHECK(alert_comparator(alert1, alert2) == 1);

        if (nullptr != actions1)
            zlist_destroy(&actions1);
        if (nullptr != actions2)
            zlist_destroy(&actions2);
        fty_proto_destroy(&alert1);
        fty_proto_destroy(&alert2);
    }

    {
        zlist_t* actions1 = zlist_new();
        zlist_autofree(actions1);
        zlist_append(actions1, const_cast<char*>(ACTION_EMAIL));
        fty_proto_t* alert1 =
            alert_new("temperature.average@DC-Roztoky", "epdu", "ACK-WIP", "low", "some description", 10, &actions1, 0);
        CHECK(alert1);
        zlist_t* actions2 = zlist_new();
        zlist_autofree(actions2);
        zlist_append(actions2, const_cast<char*>(ACTION_SMS));
        fty_proto_t* alert2 =
            alert_new("temperature.average@DC-Roztoky", "epdu", "ACK-WIP", "low", "some description", 10, &actions2, 0);
        CHECK(alert2);

        CHECK(alert_comparator(alert1, alert2) == 1);

        if (nullptr != actions1)
            zlist_destroy(&actions1);
        if (nullptr != actions2)
            zlist_destroy(&actions2);
        fty_proto_destroy(&alert1);
        fty_proto_destroy(&alert2);
    }

    // unicode
    {
        zlist_t* actions1 = zlist_new();
        zlist_autofree(actions1);
        zlist_append(actions1, const_cast<char*>(ACTION_EMAIL));
        fty_proto_t* alert1 = alert_new(
            "temperature.average@DC-Roztoky", "ŽlUťOUčKý kůň", "ACK-WIP", "low", "some description", 10, &actions1, 0);
        CHECK(alert1);
        zlist_t* actions2 = zlist_new();
        zlist_autofree(actions2);
        zlist_append(actions2, const_cast<char*>(ACTION_SMS));
        fty_proto_t* alert2 = alert_new("temperature.average@DC-Roztoky",
            "\u017dlu\u0165ou\u010dk\xc3\xbd K\u016f\xc5\x88", "ACK-WIP", "low", "some description", 10, &actions2, 0);
        CHECK(alert2);

        CHECK(alert_comparator(alert1, alert2) == 1);

        if (nullptr != actions1)
            zlist_destroy(&actions1);
        if (nullptr != actions2)
            zlist_destroy(&actions2);
        fty_proto_destroy(&alert1);
        fty_proto_destroy(&alert2);
    }


    // TODO: action can be mixed

    //  *********************************
    //  *****   alert_save_state    *****
    //  *****   alert_load_state    *****
    //  *********************************

    {

        // Test case #1:
        //  Fill list, store, load, compare one by one
        zlistx_t* alerts = zlistx_new();
        CHECK(alerts);
        zlistx_set_destructor(alerts, reinterpret_cast<czmq_destructor*>(fty_proto_destroy));
        zlistx_set_duplicator(alerts, reinterpret_cast<czmq_duplicator*>(fty_proto_dup));

        zlist_t* actions1 = zlist_new();
        zlist_autofree(actions1);
        zlist_append(actions1, const_cast<char*>(ACTION_EMAIL));
        zlist_append(actions1, const_cast<char*>(ACTION_SMS));
        fty_proto_t* alert = alert_new("Rule1", "Element1", "ACTIVE", "high", "xyz", 1, &actions1, 0);
        CHECK(alert);
        zlistx_add_end(alerts, alert);
        fty_proto_destroy(&alert);

        zlist_t* actions2 = zlist_new();
        zlist_autofree(actions2);
        zlist_append(actions2, const_cast<char*>(ACTION_EMAIL));
        zlist_append(actions2, const_cast<char*>(ACTION_SMS));
        alert = alert_new("Rule1", "Element2", "RESOLVED", "high", "xyz", 20, &actions2, 0);
        CHECK(alert);
        zlistx_add_end(alerts, alert);
        fty_proto_destroy(&alert);

        zlist_t* actions3 = zlist_new();
        zlist_autofree(actions3);
        zlist_append(actions3, const_cast<char*>(ACTION_SMS));
        alert = alert_new("Rule2", "Element1", "ACK-WIP", "low", "this is description", 152452412, &actions3, 0);
        CHECK(alert);
        zlistx_add_end(alerts, alert);
        fty_proto_destroy(&alert);

        zlist_t* actions4 = zlist_new();
        zlist_autofree(actions4);
        zlist_append(actions4, const_cast<char*>(ACTION_EMAIL));
        alert = alert_new("Rule2", "Element2", "ACK-SILENCE", "high", "x", 5, &actions4, 0);
        CHECK(alert);
        zlistx_add_end(alerts, alert);
        fty_proto_destroy(&alert);

        zlist_t* actions5 = zlist_new();
        zlist_autofree(actions5);
        zlist_append(actions5, const_cast<char*>(ACTION_EMAIL));
        zlist_append(actions5, const_cast<char*>(ACTION_SMS));
        alert = alert_new("Rule1", "Element3", "RESOLVED", "a", "y", 50, &actions5, 0);
        CHECK(alert);
        zlistx_add_end(alerts, alert);
        fty_proto_destroy(&alert);

        zlist_t* actions6 = zlist_new();
        zlist_autofree(actions6);
        zlist_append(actions6, const_cast<char*>(ACTION_EMAIL));
        zlist_append(actions6, const_cast<char*>(ACTION_SMS));
        alert = alert_new(
            "realpower.default", "ŽlUťOUčKý kůň супер", "ACTIVE", "low", "unicode test case #1", 60, &actions6, 0);
        CHECK(alert);
        zlistx_add_end(alerts, alert);
        fty_proto_destroy(&alert);

        int rv = alert_save_state(alerts, SELFTEST_RW, "test_state_file", true);
        CHECK(rv == 0);

        zlistx_destroy(&alerts);

        zlistx_t* alerts2 = zlistx_new();
        CHECK(alerts2);
        zlistx_set_destructor(alerts2, reinterpret_cast<czmq_destructor*>(fty_proto_destroy));
        // zlistx_set_duplicator(alerts2, (czmq_duplicator *) fty_proto_dup);
        rv = alert_load_state(alerts2, SELFTEST_RW, "test_state_file");
        CHECK(rv == 0);

        // Check them one by one
        fty_proto_t* cursor = reinterpret_cast<fty_proto_t*>(zlistx_first(alerts2));
        CHECK(streq(fty_proto_rule(cursor), "Rule1"));
        CHECK(streq(fty_proto_name(cursor), "Element1"));
        CHECK(streq(fty_proto_state(cursor), "ACTIVE"));
        CHECK(streq(fty_proto_severity(cursor), "high"));
        CHECK(streq(fty_proto_description(cursor), "xyz"));
        CHECK(streq(fty_proto_action_first(cursor), "EMAIL"));
        CHECK(streq(fty_proto_action_next(cursor), "SMS"));
        CHECK(nullptr == fty_proto_action_next(cursor));
        CHECK(fty_proto_time(cursor) == 1);

        cursor = reinterpret_cast<fty_proto_t*>(zlistx_next(alerts2));
        CHECK(streq(fty_proto_rule(cursor), "Rule1"));
        CHECK(streq(fty_proto_name(cursor), "Element2"));
        CHECK(streq(fty_proto_state(cursor), "RESOLVED"));
        CHECK(streq(fty_proto_severity(cursor), "high"));
        CHECK(streq(fty_proto_description(cursor), "xyz"));
        CHECK(streq(fty_proto_action_first(cursor), "EMAIL"));
        CHECK(streq(fty_proto_action_next(cursor), "SMS"));
        CHECK(nullptr == fty_proto_action_next(cursor));
        CHECK(fty_proto_time(cursor) == 20);

        cursor = reinterpret_cast<fty_proto_t*>(zlistx_next(alerts2));
        CHECK(streq(fty_proto_rule(cursor), "Rule2"));
        CHECK(streq(fty_proto_name(cursor), "Element1"));
        CHECK(streq(fty_proto_state(cursor), "ACK-WIP"));
        CHECK(streq(fty_proto_severity(cursor), "low"));
        CHECK(streq(fty_proto_description(cursor), "this is description"));
        CHECK(streq(fty_proto_action_first(cursor), "SMS"));
        CHECK(nullptr == fty_proto_action_next(cursor));
        CHECK(fty_proto_time(cursor) == 152452412);

        cursor = reinterpret_cast<fty_proto_t*>(zlistx_next(alerts2));
        CHECK(streq(fty_proto_rule(cursor), "Rule2"));
        CHECK(streq(fty_proto_name(cursor), "Element2"));
        CHECK(streq(fty_proto_state(cursor), "ACK-SILENCE"));
        CHECK(streq(fty_proto_severity(cursor), "high"));
        CHECK(streq(fty_proto_description(cursor), "x"));
        CHECK(streq(fty_proto_action_first(cursor), "EMAIL"));
        CHECK(nullptr == fty_proto_action_next(cursor));
        CHECK(fty_proto_time(cursor) == 5);

        cursor = reinterpret_cast<fty_proto_t*>(zlistx_next(alerts2));
        CHECK(streq(fty_proto_rule(cursor), "Rule1"));
        CHECK(streq(fty_proto_name(cursor), "Element3"));
        CHECK(streq(fty_proto_state(cursor), "RESOLVED"));
        CHECK(streq(fty_proto_severity(cursor), "a"));
        CHECK(streq(fty_proto_description(cursor), "y"));
        CHECK(streq(fty_proto_action_first(cursor), "EMAIL"));
        CHECK(streq(fty_proto_action_next(cursor), "SMS"));
        CHECK(nullptr == fty_proto_action_next(cursor));
        CHECK(fty_proto_time(cursor) == 50);

        cursor = reinterpret_cast<fty_proto_t*>(zlistx_next(alerts2));
        CHECK(streq(fty_proto_rule(cursor), "realpower.default"));
        CHECK(UTF8::utf8eq(fty_proto_name(cursor), "ŽlUťOUčKý kůň супер"));
        CHECK(streq(fty_proto_state(cursor), "ACTIVE"));
        CHECK(streq(fty_proto_severity(cursor), "low"));
        CHECK(streq(fty_proto_description(cursor), "unicode test case #1"));
        CHECK(streq(fty_proto_action_first(cursor), "EMAIL"));
        CHECK(streq(fty_proto_action_next(cursor), "SMS"));
        CHECK(nullptr == fty_proto_action_next(cursor));
        CHECK(fty_proto_time(cursor) == 60);

        zlistx_destroy(&alerts2);

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
    }

    // Test case #2:
    //  file does not exist
    {
        zlistx_t* alerts = zlistx_new();
        CHECK(alerts);
        zlistx_set_destructor(alerts, reinterpret_cast<czmq_destructor*>(fty_proto_destroy));
        zlistx_set_duplicator(alerts, reinterpret_cast<czmq_duplicator*>(fty_proto_dup));
        int rv = alert_load_state(alerts, SELFTEST_RO, "does_not_exist");
        CHECK(rv == -1);
        zlistx_destroy(&alerts);
    }

    // State file with old format
    {
        zlistx_t* alerts = zlistx_new();
        CHECK(alerts);
        zlistx_set_destructor(alerts, reinterpret_cast<czmq_destructor*>(fty_proto_destroy));
        zlistx_set_duplicator(alerts, reinterpret_cast<czmq_duplicator*>(fty_proto_dup));
        int rv = alert_load_state(alerts, SELFTEST_RO, "old_state_file");
        CHECK(rv == 0);
        CHECK(zlistx_size(alerts) == 0);
        zlistx_destroy(&alerts);
    }
}
