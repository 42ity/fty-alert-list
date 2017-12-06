/*  =========================================================================
    alerts_utils - Helper functions

    Copyright (C) 2014 - 2017 Eaton

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
    alerts_utils - Helper functions
@discuss
@end
*/

#include "fty_alert_list_classes.h"

int
str_eq (const char *s1, const char *s2) {
    if ((!s1 && s2) || (s1 && !s2))
        return 0;
    if (!s1 && !s2)
        return 1;
    return streq (s1, s2);
}

int
codepoint_size (const char *uchar) {
    //ASCII
    if ((((unsigned char) uchar[0]) & 0x80) == 0)
        return 0;
    unsigned char start = ((unsigned char) uchar[0]) & 0xF0;
    if ((start & 0xF0) == 0xF0)
       return 7;
    if (((start & 0xE0) == 0xE0) || ((start & 0xC0) == 0xC0))
       return 6;
    return -1;
}

size_t
utf8_len (const char *s)
{
    size_t len = 0;
    for (; *s; ++s) if ((*s & 0xC0) != 0x80) ++len;
    return len;
}

//returns a pointer to the beginning of the pos'th utf8 codepoint
const char
*utf8_index (const char *s, size_t pos)
{
    ++pos;
    for (; *s; ++s) {
        if ((*s & 0xC0) != 0x80) --pos;
        if (pos == 0) return s;
    }
    return NULL;
}

int
utf8_to_codepoint (const char *uchar, char **codepoint) {
    //codepoint is NOT null-terminated because it makes comparison too cumbersome
    assert(codepoint);

    const unsigned char *uuchar = (unsigned char *) uchar;
    static const char hex[] = "0123456789abcdef";
    unsigned char start = uuchar[0] & 0xF0;
    unsigned char ubytes[4] = {0, 0, 0, 0};
    unsigned int codepoint_int = 0;
    int mask = 0xf;

    // 4-byte character - 7 bytes for codepoint
    if ((start & 0xF0) == 0xF0) {
            ubytes[0] = uuchar[0] & 0x7;
            for (int i = 1; i < 4; i++)
                ubytes[i] = uuchar[i] & 0x3f;

            codepoint_int = (ubytes[0] << 18) + (ubytes[1] << 12) + (ubytes[2] << 6) + ubytes[3];
            if (codepoint_int <= 0x10fff) {
                for (int i = 6; i > 1; i--) {
                    (*codepoint)[i] = hex[codepoint_int & mask];
                    codepoint_int >>= 4;
                }
                (*codepoint)[1] = 'u';
                (*codepoint)[0] = '\\';
                return 4;
            }
            // everything else is unassigned character
            else
                return -1;
    }
    // 3-byte character
    if ((start & 0xE0) == 0xE0) {
        ubytes[0] = uuchar[0] & 0xf;
        for (int i = 1; i < 3; i++)
            ubytes[i] = uuchar[i] & 0x3f;
        codepoint_int = (ubytes[0] << 12) + (ubytes[1] << 6) + ubytes[2];
        for (int i = 5; i > 1; i--) {
            (*codepoint)[i] = hex[codepoint_int & mask];
            codepoint_int >>= 4;
        }
        (*codepoint)[1] = 'u';
        (*codepoint)[0] = '\\';
        return 3;
    }
    //2-byte character
    if ((start & 0xC0) == 0xC0) {
        ubytes[0] = uuchar[0] & 0x1f;
        ubytes[1] =  uuchar[1] & 0x3f;
        codepoint_int = (ubytes[0] << 6) + ubytes[1];
        for (int i = 5; i > 2; i--) {
            (*codepoint)[i] = hex[codepoint_int & mask];
            codepoint_int >>= 4;
        }
        (*codepoint)[2] = '0';
        (*codepoint)[1] = 'u';
        (*codepoint)[0] = '\\';
        return 2;
    }
    // ASCII; don't do anything
    if ((uuchar[0] & 0x80) == 0)
        return 0;
    // in any other case, this is not a unicode character
    return -1;
}

int
compare_utf8_codepoint (const char *str_utf8, const char *str_codepoint) {
    assert (str_utf8);
    assert (str_codepoint);
    size_t len = utf8_len (str_utf8);

    int j = 0;
    for (size_t i = 0; i < len; i++) {
        const char *pos = utf8_index (str_utf8, i);
        if (codepoint_size (pos) == 0) {
            zsys_debug ("Comparing '%c' with '%c'\n", *pos, str_codepoint[j]);
            if (*pos != str_codepoint[j])
                return 0;
            j++;
        }
        else {
            char *codepoint = (char *) malloc (codepoint_size (pos) * sizeof (char));
            int rv = utf8_to_codepoint (pos, &codepoint);
            if (rv == -1)
                zsys_error ("Error while converting alert name '%s' for comparison with alert name '%s'\n", str_utf8, str_codepoint);
            for (int k = 0; k < codepoint_size (pos); k++) {
                zsys_debug ("codepoint : Comparing '%c' with '%c'\n", codepoint[k], str_codepoint[j]);
                if (tolower(codepoint[k]) != tolower(str_codepoint[j]))
                    return 0;
                j++;
            }
            free (codepoint);
        }
    }
    return 1;
}

// 1, ..., 4 - # of utf8 octets
// -1 - error
static int8_t
utf8_octets (const char *c)
{
    assert (c);
    if ((*c & 0x80 ) == 0)     // lead bit is zero, must be a single ascii
        return 1;
    else
    if ((*c & 0xE0 ) == 0xC0 ) // 110x xxxx (2 octets)
        return 2;
    else
    if ((*c & 0xF0 ) == 0xE0 ) // 1110 xxxx (3 octets)
        return 3;
    else
    if ((*c & 0xF8 ) == 0xF0 ) // 1111 0xxx (4 octets)
        return 4;
    else
        zsys_error ("Unrecognized utf8 lead byte '%x' in string '%s'", *c, c);
    return -1;
}

// ignores case on 1 octet bytes
// 0 - same
// 1 - different
static int
utf8_compare_octets (const char *s1, const char *s2, size_t pos, size_t length, uint8_t count)
{
    assert (count >= 1 && count <= 4);
    assert (pos + count <= length);

    for (int i = 0; i < count; i++) {
        const char c1 = s1[pos + i];
        const char c2 = s2[pos + i];

        if ((count == 1 && tolower (c1) != tolower (c2)) ||
            (count > 1  && c1 != c2))
            return 1;
    }
    return 0;
}

// compare utf8 strings for equality
// ignore case on ascii (i.e on 1 byte chars)
int
utf8eq (const char *s1, const char *s2)
{
    assert (s1);
    assert (s2);

    if (strlen (s1) != strlen (s2))
        return 0;

    size_t pos = 0;
    size_t length = strlen (s1);


    while (pos < length) {
        uint8_t s1_octets = utf8_octets (s1 + pos);
        uint8_t s2_octets = utf8_octets (s2 + pos);

        if (s1_octets == -1 || s2_octets == -1)
            return -1;

        if (s1_octets != s2_octets)
            return 0;

        if (utf8_compare_octets (s1, s2, pos, length, s1_octets) == 1)
            return 0;

        pos = pos + s1_octets;
    }
    return 1;
}

int
alert_id_comparator (fty_proto_t *alert1, fty_proto_t *alert2) {
    assert (alert1);
    assert (alert2);
    assert (fty_proto_id (alert1) == FTY_PROTO_ALERT);
    assert (fty_proto_id (alert2) == FTY_PROTO_ALERT);

    if (fty_proto_rule (alert1) == NULL ||
        fty_proto_rule (alert2) == NULL) {
        return 1;
    }

    if (strcasecmp (fty_proto_rule (alert1), fty_proto_rule (alert2)) == 0 &&
        utf8eq (fty_proto_name (alert1), fty_proto_name (alert2))) {
        return 0;
    }
    else {
        return 1;
    }
}

int
is_alert_identified (fty_proto_t *alert, const char *rule_name, const char *element_name) {
    assert (alert);
    assert (rule_name);
    assert (element_name);
    const char *element_src = fty_proto_name (alert);

    if (strcasecmp (fty_proto_rule (alert), rule_name) == 0 &&
        utf8eq (element_src, element_name)) {
        return 1;
    }
    return 0;
}

int
alert_comparator (fty_proto_t *alert1, fty_proto_t *alert2) {
    assert (alert1);
    assert (alert2);
    assert (fty_proto_id (alert1) == FTY_PROTO_ALERT);
    assert (fty_proto_id (alert2) == FTY_PROTO_ALERT);

    if (fty_proto_rule (alert1) == NULL ||
        fty_proto_rule (alert2) == NULL) {
        return 1;
    }

    // rule
    if (strcasecmp (fty_proto_rule (alert1), fty_proto_rule (alert2)) != 0)
        return 1;
    // element_src
    if (!utf8eq (fty_proto_name (alert1), fty_proto_name (alert2)))
        return 1;
    // state
    if (!str_eq (fty_proto_state (alert1), fty_proto_state (alert2)))
       return 1;
    // severity
    if (!str_eq (fty_proto_severity (alert1), fty_proto_severity (alert2)))
        return 1;
    // description
    if (!str_eq (fty_proto_description (alert1), fty_proto_description (alert2)))
        return 1;
    // time
    if (fty_proto_time (alert1) != fty_proto_time (alert2))
        return 1;
    // action
    // TODO: it might be needed to parse action and compare the individual actions
    //       i.e "EMAIL|SMS" eq "SMS|EMAIL". For now, we don't recognize this and for
    //       now it does not create a problem.
    const char *action1 = fty_proto_action_first(alert1);
    const char *action2 = fty_proto_action_first(alert2);
    while (NULL != action1 && NULL != action2) {
        if (!str_eq (action1, action2))
            return 1;
        action1 = fty_proto_action_next(alert1);
        action2 = fty_proto_action_next(alert2);
    }
    return 0;
}

int
is_acknowledge_state (const char *state) {
    if (str_eq (state, "ACK-WIP") ||
        str_eq (state, "ACK-IGNORE") ||
        str_eq (state, "ACK-PAUSE") ||
        str_eq (state, "ACK-SILENCE")) {
        return 1;
    }
    return 0;
}

int
is_alert_state (const char *state) {
    if (str_eq (state, "ACTIVE") ||
        str_eq (state, "RESOLVED") ||
        is_acknowledge_state (state)) {
        return 1;
    }
    return 0;
}

int
is_list_request_state (const char *state) {
    if (str_eq (state, "ALL") ||
        str_eq (state, "ALL-ACTIVE") ||
        is_alert_state (state)) {
        return 1;
    }
    return 0;
}

int
is_state_included (const char *list_request_state, const char *alert) {
    if (!is_list_request_state (list_request_state))
        return 0;
    if (!is_alert_state (alert))
        return 0;

    if (str_eq (list_request_state, "ALL"))
        return 1;
    if (str_eq (list_request_state, "ALL-ACTIVE") && !str_eq (alert, "RESOLVED"))
        return 1;
    return str_eq (list_request_state, alert);
}

int
is_acknowledge_request_state (const char *state) {
    if (str_eq (state, "ACTIVE") ||
        is_acknowledge_state (state)) {
        return 1;
    }
    return 0;
}

// 0 - ok, -1 - error
static int
s_alerts_input_checks (zlistx_t *alerts, fty_proto_t *alert) {
    assert (alerts);
    assert (alert);

    fty_proto_t *cursor = (fty_proto_t *) zlistx_first (alerts);
    while (cursor) {
        if (alert_id_comparator (cursor, alert) == 0) {
            // We already have 'alert' in zlistx 'alerts'
            return -1;
        }
        cursor = (fty_proto_t *) zlistx_next (alerts);
    }

    return 0;
}

// load alert state from disk
// 0 - success, -1 - error
int
alert_load_state (zlistx_t *alerts, const char *path, const char *filename) {
    assert (alerts);
    assert (path);
    assert (filename);

    zsys_debug ("statefile: %s/%s", path, filename);
    zfile_t *file = zfile_new (path, filename);
    if (!file) {
        zsys_error ("zfile_new (path = '%s', file = '%s') failed.", path, filename);
        return -1;
    }
    if (!zfile_is_regular (file)) {
        zsys_error ("zfile_is_regular () == false");
        zfile_close (file);
        zfile_destroy (&file);
        return -1;
    }
    if (zfile_input (file) == -1) {
        zfile_close (file);
        zfile_destroy (&file);
        zsys_error ("zfile_input () failed; filename = '%s'", zfile_filename (file, NULL));
        return -1;
    }

    off_t cursize = zfile_cursize (file);
    if (cursize == 0) {
        zsys_debug ("state file '%s' is empty", zfile_filename (file, NULL));
        zfile_close (file);
        zfile_destroy (&file);
        return 0;
    }

    zchunk_t *chunk = zchunk_read (zfile_handle (file), cursize);
    assert (chunk);
    zframe_t *frame = zframe_new (zchunk_data (chunk), zchunk_size (chunk));
    assert (frame);
    zchunk_destroy (&chunk);

    zfile_close (file);
    zfile_destroy (&file);

    /* Note: Protocol data uses 8-byte sized words, and zmsg_XXcode and file
     * functions deal with platform-dependent unsigned size_t and signed off_t.
     * The off_t is a difficult one to print portably, SO suggests casting to
     * the intmax type and printing that :)
     * https://stackoverflow.com/questions/586928/how-should-i-print-types-like-off-t-and-size-t
     */
    uint64_t offset = 0;
    zsys_debug ("zfile_cursize == %jd", (intmax_t)cursize);

    while (offset < cursize) {
        byte *prefix = zframe_data (frame) + offset;
        byte *data = zframe_data (frame) + offset + sizeof (uint64_t);
        offset += (uint64_t) *prefix +  sizeof (uint64_t);
        zsys_debug ("prefix == %" PRIu64 "; offset = %jd ", (uint64_t ) *prefix, (intmax_t)offset);

/* Note: the CZMQ_VERSION_MAJOR comparison below actually assumes versions
 * we know and care about - v3.0.2 (our legacy default, already obsoleted
 * by upstream), and v4.x that is in current upstream master. If the API
 * evolves later (incompatibly), these macros will need to be amended.
 */
        zmsg_t *zmessage = NULL;
#if CZMQ_VERSION_MAJOR == 3
        zmessage = zmsg_decode (data, (size_t) *prefix);
#else
        {
            zframe_t *fr = zframe_new (data, (size_t) *prefix);
            zmessage = zmsg_decode (fr);
            zframe_destroy (&fr);
        }
#endif
        assert (zmessage);
        fty_proto_t *alert = fty_proto_decode (&zmessage); // zmessage destroyed
        if (!alert) {
            zsys_warning ("Ignoring malformed alert in %s/%s", path, filename);
            continue;
        }
        if (s_alerts_input_checks (alerts, alert) == 0) {
            zlistx_add_end (alerts, alert);
        }
        else {
            zsys_warning (
                    "Alert id (%s, %s) already read.",
                    fty_proto_rule (alert),
                    fty_proto_name (alert));
        }
        fty_proto_destroy (&alert);
    }

    zframe_destroy (&frame);
    return 0;
}

// save alert state to disk
// 0 - success, -1 - error
int
alert_save_state (zlistx_t *alerts, const char *path, const char *filename) {
    assert (alerts);
    assert (path);
    assert (filename);

    zfile_t *file = zfile_new (path, filename);
    if (!file) {
        zsys_error ("zfile_new (path = '%s', file = '%s') failed.", path, filename);
        return -1;
    }

    zfile_remove (file);

    if (zfile_output (file) == -1) {
        zsys_error ("zfile_output () failed; filename = '%s'", zfile_filename (file, NULL));
        zfile_close (file);
        zfile_destroy (&file);
        return -1;
    }

    zchunk_t *chunk = zchunk_new (NULL, 0); // TODO: this can be tweaked to
                                            // avoid a lot of allocs
    assert (chunk);

    fty_proto_t *cursor = (fty_proto_t *) zlistx_first (alerts);
    if (cursor)
        fty_proto_print (cursor);

    while (cursor) {
        uint64_t size = 0;  // Note: the zmsg_encode() and zframe_size()
                            // below return a platform-dependent size_t,
                            // but in protocol we use fixed uint64_t
        assert ( sizeof(size_t) <= sizeof(uint64_t) );
        zframe_t *frame = NULL;
        fty_proto_t *duplicate = fty_proto_dup (cursor);
        assert (duplicate);
        zmsg_t *zmessage = fty_proto_encode (&duplicate); // duplicate destroyed here
        assert (zmessage);

#if CZMQ_VERSION_MAJOR == 3
        {
            byte *buffer = NULL;
            size = zmsg_encode (zmessage, &buffer);

            assert (buffer);
            assert (size > 0);
            frame = zframe_new (buffer, size);
            free (buffer);
            buffer = NULL;
        }
#else
        frame = zmsg_encode (zmessage);
        size = zframe_size (frame);
#endif
        zmsg_destroy (&zmessage);
        assert (frame);
        assert (size > 0);

        // prefix
// FIXME?: originally this was for uint64_t, should it be sizeof (size) instead?
// Also is usage of uint64_t here really warranted (e.g. dictated by protocol)?
        zchunk_extend (chunk, (const void *) &size, sizeof (uint64_t));
        // data
        zchunk_extend (chunk, (const void *) zframe_data (frame), size);

        zframe_destroy (&frame);

        cursor = (fty_proto_t *) zlistx_next (alerts);
    }

    if (zchunk_write (chunk, zfile_handle (file)) == -1) {
        zsys_error ("zchunk_write () failed.");
    }

    zchunk_destroy (&chunk);
    zfile_close (file);
    zfile_destroy (&file);
    return 0;
}

fty_proto_t*
alert_new (const char *rule,
           const char *element,
           const char *state,
           const char *severity,
           const char *description,
           uint64_t timestamp,
           zlist_t **action,
           int64_t ttl) {
    fty_proto_t *alert = fty_proto_new (FTY_PROTO_ALERT);
    if (!alert)
        return NULL;
    fty_proto_set_rule (alert,"%s", rule);
    fty_proto_set_name (alert,"%s", element);
    fty_proto_set_state (alert,"%s", state);
    fty_proto_set_severity (alert, "%s", severity);
    fty_proto_set_description (alert,"%s" ,description);
    fty_proto_set_action (alert, action);
    fty_proto_set_time (alert, timestamp);
    fty_proto_aux_insert (alert,"TTL", "%"PRIi64, ttl);
    return alert;
}

//  --------------------------------------------------------------------------
//  Self test of this class

void
alerts_utils_test (bool verbose)
{

    //  @selftest

    printf (" * alerts_utils: ");

    //  **********************
    //  *****   utf8eq   *****
    //  **********************
    assert ( utf8eq ("ŽlUťOUčKý kůň", "\u017dlu\u0165ou\u010dk\xc3\xbd K\u016f\xc5\x88") == 1 );
    assert ( utf8eq ("Žluťou\u0165ký kůň", "ŽLUťou\u0165Ký kůň") == 1 );
    assert ( utf8eq ("Žluťou\u0165ký kůň", "ŽLUťou\u0165Ký kůň ") == 0 );
    assert ( utf8eq ("Ka\xcc\x81rol", "K\xc3\xa1rol") == 0 );
    assert ( utf8eq ("супер test", "\u0441\u0443\u043f\u0435\u0440 Test") == 1 );
    assert ( utf8eq ("ŽlUťOUčKý kůň", "ŽlUťOUčKý kůn") == 0 );

    //  **********************
    //  *****   str_eq   *****
    //  **********************

    assert (str_eq (NULL, NULL) == 1);
    assert (str_eq ("", "") == 1);
    assert (str_eq (NULL, "") == 0);
    assert (str_eq ("", NULL) == 0);
    assert (str_eq ("a", "a") == 1);
    assert (str_eq ("a", "A") == 0);
    assert (str_eq ("A", "a") == 0);

    //  ************************************
    //  *****   is_acknowledge_state   *****
    //  ************************************

    assert (is_acknowledge_state ("ACK-WIP") == 1);
    assert (is_acknowledge_state ("ACK-IGNORE") == 1);
    assert (is_acknowledge_state ("ACK-PAUSE") == 1);
    assert (is_acknowledge_state ("ACK-SILENCE") == 1);

    assert (is_acknowledge_state ("ACTIVE") == 0);
    assert (is_acknowledge_state ("active") == 0);
    assert (is_acknowledge_state ("RESOLVED") == 0);
    assert (is_acknowledge_state ("RESOLVE") == 0);
    assert (is_acknowledge_state ("resolve") == 0);
    assert (is_acknowledge_state ("ack-wip") == 0);
    assert (is_acknowledge_state ("ALL") == 0);
    assert (is_acknowledge_state ("ALL-ACTIVE") == 0);
    assert (is_acknowledge_state ("all") == 0);
    assert (is_acknowledge_state ("all-active") == 0);
    assert (is_acknowledge_state ("") == 0);
    assert (is_acknowledge_state (NULL) == 0);
    assert (is_acknowledge_state ("ACK-xyfd") == 0);
    assert (is_acknowledge_state ("aCK-WIP") == 0);
    assert (is_acknowledge_state ("ACKWIP") == 0);
    assert (is_acknowledge_state ("somethign") == 0);


    //  ******************************
    //  *****   is_alert_state   *****
    //  ******************************

    assert (is_alert_state ("ACTIVE") == 1);
    assert (is_alert_state ("ACK-WIP") == 1);
    assert (is_alert_state ("ACK-IGNORE") == 1);
    assert (is_alert_state ("ACK-PAUSE") == 1);
    assert (is_alert_state ("ACK-SILENCE") == 1);
    assert (is_alert_state ("RESOLVED") == 1);

    assert (is_alert_state ("ALL") == 0);
    assert (is_alert_state ("ALL-ACTIVE") == 0);
    assert (is_alert_state ("") == 0);
    assert (is_alert_state (NULL) == 0);
    assert (is_alert_state ("all") == 0);
    assert (is_alert_state ("active") == 0);
    assert (is_alert_state ("ACK") == 0);
    assert (is_alert_state ("ack-wip") == 0);
    assert (is_alert_state ("resolved") == 0);

    //  *************************************
    //  *****   is_list_request_state   *****
    //  *************************************

    assert (is_list_request_state ("ACTIVE") == 1);
    assert (is_list_request_state ("ACK-WIP") == 1);
    assert (is_list_request_state ("ACK-IGNORE") == 1);
    assert (is_list_request_state ("ACK-PAUSE") == 1);
    assert (is_list_request_state ("ACK-SILENCE") == 1);
    assert (is_list_request_state ("RESOLVED") == 1);
    assert (is_list_request_state ("ALL") == 1);
    assert (is_list_request_state ("ALL-ACTIVE") == 1);

    assert (is_list_request_state ("All") == 0);
    assert (is_list_request_state ("all") == 0);
    assert (is_list_request_state ("Active") == 0);
    assert (is_list_request_state ("active") == 0);
    assert (is_list_request_state ("ack-wip") == 0);
    assert (is_list_request_state ("resolved") == 0);
    assert (is_list_request_state ("") == 0);
    assert (is_list_request_state (NULL) == 0);
    assert (is_list_request_state ("sdfsd") == 0);


    //  *********************************
    //  *****   is_state_included   *****
    //  *********************************

    assert (is_state_included ("ALL", "ACTIVE") == 1);
    assert (is_state_included ("ALL", "ACK-WIP") == 1);
    assert (is_state_included ("ALL", "ACK-IGNORE") == 1);
    assert (is_state_included ("ALL", "ACK-PAUSE") == 1);
    assert (is_state_included ("ALL", "ACK-SILENCE") == 1);
    assert (is_state_included ("ALL", "RESOLVED") == 1);

    assert (is_state_included ("ALL-ACTIVE", "ACTIVE") == 1);
    assert (is_state_included ("ALL-ACTIVE", "ACK-WIP") == 1);
    assert (is_state_included ("ALL-ACTIVE", "ACK-IGNORE") == 1);
    assert (is_state_included ("ALL-ACTIVE", "ACK-PAUSE") == 1);
    assert (is_state_included ("ALL-ACTIVE", "ACK-SILENCE") == 1);
    assert (is_state_included ("ALL-ACTIVE", "RESOLVED") == 0);

    assert (is_state_included ("ACTIVE", "ACTIVE") == 1);
    assert (is_state_included ("ACK-WIP", "ACK-WIP") == 1);
    assert (is_state_included ("ACK-IGNORE", "ACK-IGNORE") == 1);
    assert (is_state_included ("ACK-SILENCE", "ACK-SILENCE") == 1);
    assert (is_state_included ("RESOLVED", "RESOLVED") == 1);

    assert (is_state_included ("ACTIVE", "ALL") == 0);
    assert (is_state_included ("ACTIVE", "RESOLVED") == 0);
    assert (is_state_included ("ACTIVE", "ALL-ACTIVE") == 0);
    assert (is_state_included ("ALL", "ALL-ACTIVE") == 0);
    assert (is_state_included ("ALL-ACTIVE", "ALL-ACTIVE") == 0);
    assert (is_state_included ("ALL", "ALL") == 0);
    assert (is_state_included ("ACK-WIP", "ACTIVE") == 0);
    assert (is_state_included ("ACK-IGNORE", "ACK-WIP") == 0);

    //  *********************************************
    //  *****   is_acknowledge_request_state    *****
    //  *********************************************

    assert (is_acknowledge_request_state ("ACTIVE") == 1);
    assert (is_acknowledge_request_state ("ACK-WIP") == 1);
    assert (is_acknowledge_request_state ("ACK-IGNORE") == 1);
    assert (is_acknowledge_request_state ("ACTIVE") == 1);
    assert (is_acknowledge_request_state ("ACTIVE") == 1);

    assert (is_acknowledge_request_state ("ALL") == 0);
    assert (is_acknowledge_request_state ("RESOLVED") == 0);
    assert (is_acknowledge_request_state ("ALL-ACTIVE") == 0);
    assert (is_acknowledge_request_state ("active") == 0);
    assert (is_acknowledge_request_state ("") == 0);
    assert (is_acknowledge_request_state (NULL) == 0);

    //  **************************
    //  *****   alert_new    *****
    //  **************************
    {
    zlist_t *actions = zlist_new ();
    zlist_autofree (actions);
    zlist_append(actions, "EMAIL");
    zlist_append(actions, "SMS");
    fty_proto_t *alert = alert_new ("Threshold", "ups", "ACTIVE", "high", "description", 1, &actions, 0);
    assert (str_eq (fty_proto_rule (alert), "Threshold"));
    assert (str_eq (fty_proto_name (alert), "ups"));
    assert (str_eq (fty_proto_state (alert), "ACTIVE"));
    assert (str_eq (fty_proto_severity (alert), "high"));
    assert (str_eq (fty_proto_description (alert), "description"));
    assert (str_eq (fty_proto_action_first (alert), "EMAIL"));
    assert (str_eq (fty_proto_action_next (alert), "SMS"));
    assert (NULL == fty_proto_action_next (alert));
    assert (fty_proto_time (alert) == (uint64_t) 1);
    fty_proto_destroy (&alert);
    if (NULL != actions)
        zlist_destroy (&actions);

    actions = zlist_new ();
    zlist_autofree (actions);
    zlist_append(actions, "SMS");
    zlist_append(actions, "Holub");
    zlist_append(actions, "Morse code");
    alert = alert_new ("Simple@Rule@Because", "karolkove zelezo", "ACTIVE", "high Severity", "Holiday \nInn hotel 243", 10101795, &actions, 0);
    assert (str_eq (fty_proto_rule (alert), "Simple@Rule@Because"));
    assert (str_eq (fty_proto_name (alert), "karolkove zelezo"));
    assert (str_eq (fty_proto_state (alert), "ACTIVE"));
    assert (str_eq (fty_proto_severity (alert), "high Severity"));
    assert (str_eq (fty_proto_description (alert), "Holiday \nInn hotel 243"));
    assert (str_eq (fty_proto_action_first (alert), "SMS"));
    assert (str_eq (fty_proto_action_next (alert), "Holub"));
    assert (str_eq (fty_proto_action_next (alert), "Morse code"));
    assert (NULL == fty_proto_action_next (alert));
    assert (fty_proto_time (alert) == (uint64_t) 10101795);
    fty_proto_destroy (&alert);
    if (NULL != actions)
        zlist_destroy (&actions);
    }

    //  ************************************
    //  *****   alert_id_comparator    *****
    //  ************************************


    // test case 1a:
    //  alerts are completely the same
    {
    zlist_t *actions1 = zlist_new ();
    zlist_autofree (actions1);
    zlist_append(actions1, "EMAIL");
    fty_proto_t *alert1 = alert_new ("temperature.average@DC-Roztoky", "ups-9", "ACTIVE", "some description", "low", 10, &actions1, 0);
    assert (alert1);
    zlist_t *actions2 = zlist_new ();
    zlist_autofree (actions2);
    zlist_append(actions2, "EMAIL");
    fty_proto_t *alert2 = alert_new ("temperature.average@DC-Roztoky", "ups-9", "ACTIVE", "some description", "low", 10, &actions2, 0);
    assert (alert2);

    assert (alert_id_comparator (alert1, alert2) == 0);

    if (NULL != actions1)
        zlist_destroy (&actions1);
    if (NULL != actions2)
        zlist_destroy (&actions2);
    fty_proto_destroy (&alert1);
    fty_proto_destroy (&alert2);
    }

    // test case 1b:
    //  alerts have the same identifier,
    //  different meta-data which represents real world use case of one alert
    //  at two different times
    {
    zlist_t *actions1 = zlist_new ();
    zlist_autofree (actions1);
    zlist_append(actions1, "EMAIL");
    fty_proto_t *alert1 = alert_new ("temperature.average@DC-Roztoky", "ups-9", "ACTIVE", "some description", "low", 10, &actions1, 0);
    assert (alert1);
    zlist_t *actions2 = zlist_new ();
    zlist_autofree (actions2);
    zlist_append(actions2, "SMS");
    fty_proto_t *alert2 = alert_new ("temperature.average@DC-Roztoky", "ups-9", "ACK-IGNORE", "some description", "high", 10, &actions2, 0);
    assert (alert2);

    assert (alert_id_comparator (alert1, alert2) == 0);

    if (NULL != actions1)
        zlist_destroy (&actions1);
    if (NULL != actions2)
        zlist_destroy (&actions2);
    fty_proto_destroy (&alert1);
    fty_proto_destroy (&alert2);
    }

    // test case 1c:
    //  alerts have the same identifier,
    //  different as well as missing meta-data
    {
    zlist_t *actions1 = zlist_new ();
    zlist_autofree (actions1);
    zlist_append(actions1, "EMAIL");
    fty_proto_t *alert1 = alert_new ("temperature.average@DC-Roztoky", "ups-9", "ACK-WIP", NULL, "high", 10, &actions1, 0);
    assert (alert1);
    zlist_t *actions2 = zlist_new ();
    zlist_autofree (actions2);
    fty_proto_t *alert2 = alert_new ("temperature.average@DC-Roztoky", "ups-9", "ACTIVE", "some description", "low", 20, &actions2, 0);
    assert (alert2);

    assert (alert_id_comparator (alert1, alert2) == 0);

    if (NULL != actions1)
        zlist_destroy (&actions1);
    if (NULL != actions2)
        zlist_destroy (&actions2);
    fty_proto_destroy (&alert1);
    fty_proto_destroy (&alert2);
    }

    // test case 1d:
    //  alerts have the same identifier - rule name has different case
    //  different as well as missing meta-data
    {
    zlist_t *actions1 = zlist_new ();
    zlist_autofree (actions1);
    zlist_append(actions1, "EMAIL");
    fty_proto_t *alert1 = alert_new ("temperature.average@DC-Roztoky", "ups-9", "ACK-WIP", NULL, "high", 10, &actions1, 0);
    assert (alert1);
    zlist_t *actions2 = zlist_new ();
    zlist_autofree (actions2);
    fty_proto_t *alert2 = alert_new ("Temperature.Average@dC-roztoky", "ups-9", "ACTIVE", "some description", "low", 20, &actions2, 0);
    assert (alert2);

    assert (alert_id_comparator (alert1, alert2) == 0);

    if (NULL != actions1)
        zlist_destroy (&actions1);
    if (NULL != actions2)
        zlist_destroy (&actions2);
    fty_proto_destroy (&alert1);
    fty_proto_destroy (&alert2);
    }

    // test case 2a:
    // alerts don't have the same identifier - different rule

    {
    zlist_t *actions1 = zlist_new ();
    zlist_autofree (actions1);
    fty_proto_t *alert1 = alert_new ("temperature.average@DC-Lab", "ups-9", "ACK-WIP", NULL, "high", 10, &actions1, 0);
    assert (alert1);
    zlist_t *actions2 = zlist_new ();
    zlist_autofree (actions2);
    fty_proto_t *alert2 = alert_new ("temperature.average@DC-Roztoky", "ups-9", "ACTIVE", NULL, "low", 20, &actions2, 0);
    assert (alert2);

    assert (alert_id_comparator (alert1, alert2) == 1);

    if (NULL != actions1)
        zlist_destroy (&actions1);
    if (NULL != actions2)
        zlist_destroy (&actions2);
    fty_proto_destroy (&alert1);
    fty_proto_destroy (&alert2);
    }

    // test case 2b:
    // alerts don't have the same identifier - different element_src

    {
    zlist_t *actions1 = zlist_new ();
    zlist_autofree (actions1);
    fty_proto_t *alert1 = alert_new ("temperature.average@DC-Roztoky", "epdu", "ACK-WIP", "xcuy;v weohuif", "high", 10, &actions1, 0);
    assert (alert1);
    zlist_t *actions2 = zlist_new ();
    zlist_autofree (actions2);
    fty_proto_t *alert2 = alert_new ("temperature.average@DC-Roztoky", "ups-9", "ACTIVE", NULL, "low", 20, &actions2, 0);
    assert (alert2);

    assert (alert_id_comparator (alert1, alert2) == 1);

    if (NULL != actions1)
        zlist_destroy (&actions1);
    if (NULL != actions2)
        zlist_destroy (&actions2);
    fty_proto_destroy (&alert1);
    fty_proto_destroy (&alert2);
    }

    // test case 2c:
    // alerts do have the same identifier - case of element_src is ignored now

    {
    zlist_t *actions1 = zlist_new ();
    zlist_autofree (actions1);
    fty_proto_t *alert1 = alert_new ("temperature.average@DC-Roztoky", "Ups-9", "ACK-WIP", NULL, "high", 10, &actions1, 0);
    assert (alert1);
    zlist_t *actions2 = zlist_new ();
    zlist_autofree (actions2);
    fty_proto_t *alert2 = alert_new ("temperature.average@DC-Roztoky", "ups-9", "ACTIVE", NULL, "low", 20, &actions2, 0);
    assert (alert2);

    assert (alert_id_comparator (alert1, alert2) == 0);

    if (NULL != actions1)
        zlist_destroy (&actions1);
    if (NULL != actions2)
        zlist_destroy (&actions2);
    fty_proto_destroy (&alert1);
    fty_proto_destroy (&alert2);
    }


    // test case 3:
    // alerts don't have the same identifier -different element_src, rule
    {
    zlist_t *actions1 = zlist_new ();
    zlist_autofree (actions1);
    fty_proto_t *alert1 = alert_new ("temperature.average@DC-Roztoky", "epdu", "ACK-WIP", NULL, "high", 10, &actions1, 0);
    assert (alert1);
    zlist_t *actions2 = zlist_new ();
    zlist_autofree (actions2);
    fty_proto_t *alert2 = alert_new ("temperature.humidity@DC-Roztoky", "ups-9", "ACTIVE", NULL, "low", 20, &actions2, 0);
    assert (alert2);

    assert (alert_id_comparator (alert1, alert2) == 1);

    if (NULL != actions1)
        zlist_destroy (&actions1);
    if (NULL != actions2)
        zlist_destroy (&actions2);
    fty_proto_destroy (&alert1);
    fty_proto_destroy (&alert2);
    }

    // unicode
    {
    zlist_t *actions1 = zlist_new ();
    zlist_autofree (actions1);
    zlist_append(actions1, "EMAIL");
    fty_proto_t *alert1 = alert_new ("realpower.DeFault", "ŽlUťOUčKý kůň супер", "ACTIVE", "some description", "low", 10, &actions1, 0);
    assert (alert1);
    zlist_t *actions2 = zlist_new ();
    zlist_autofree (actions2);
    zlist_append(actions2, "EMAIL");
    zlist_append(actions2, "SMS");
    fty_proto_t *alert2 = alert_new ("realpower.default", "\u017dlu\u0165ou\u010dk\xc3\xbd K\u016f\xc5\x88 супер", "ACK-SILENCE",
                                      "some description 2", "high", 100, &actions2, 0);
    assert (alert2);

    assert (alert_id_comparator (alert1, alert2) == 0);

    if (NULL != actions1)
        zlist_destroy (&actions1);
    if (NULL != actions2)
        zlist_destroy (&actions2);
    fty_proto_destroy (&alert1);
    fty_proto_destroy (&alert2);
    }

    {
    zlist_t *actions1 = zlist_new ();
    zlist_autofree (actions1);
    zlist_append(actions1, "EMAIL");
    fty_proto_t *alert1 = alert_new ("realpower.DeFault", "Žluťoučký kůň супер ", "ACTIVE", "some description", "low", 10, &actions1, 0);
    assert (alert1);
    zlist_t *actions2 = zlist_new ();
    zlist_autofree (actions2);
    zlist_append(actions2, "EMAIL");
    zlist_append(actions2, "SMS");
    fty_proto_t *alert2 = alert_new ("realpower.default", "Žluťoučký kůň супер", "ACK-SILENCE",
                                      "some description 2", "high", 100, &actions2, 0);
    assert (alert2);

    assert (alert_id_comparator (alert1, alert2) == 1);

    if (NULL != actions1)
        zlist_destroy (&actions1);
    if (NULL != actions2)
        zlist_destroy (&actions2);
    fty_proto_destroy (&alert1);
    fty_proto_destroy (&alert2);
    }

    //  *************************************
    //  *****   is_alert_identified     *****
    //  *************************************
    {
    zlist_t *actions = zlist_new ();
    zlist_autofree (actions);
    zlist_append(actions, "EMAIL");
    fty_proto_t *alert = alert_new ("temperature.average@DC-Roztoky", "ups-9", "ACTIVE", "some description", "low", 10, &actions, 0);
    assert (alert);
    assert (is_alert_identified (alert, "temperature.average@DC-Roztoky", "ups-9") == 1);
    assert (is_alert_identified (alert, "Temperature.Average@dC-Roztoky", "ups-9") == 1);
    assert (is_alert_identified (alert, "humidity@DC-Roztoky", "ups-9") == 0);
    assert (is_alert_identified (alert, "", "ups-9") == 0);
    assert (is_alert_identified (alert, "temperature.average@DC-Roztoky", "") == 0);
    assert (is_alert_identified (alert, "temperature.average@DC-Roztoky", "epDU") == 0);
    assert (is_alert_identified (alert, "Temperature.Average@dC-Roztoky", "epDU") == 0);
    fty_proto_destroy (&alert);
    if (NULL != actions)
        zlist_destroy (&actions);
    }

    {
    zlist_t *actions = zlist_new ();
    zlist_autofree (actions);
    zlist_append(actions, "EMAIL");
    fty_proto_t *alert = alert_new ("temperature.average@DC-Roztoky", "ta2€супер14159", "ACTIVE", "some description", "low", 10, &actions, 0);
    assert (alert);
    assert (is_alert_identified (alert, "temperature.average@DC-Roztoky", "ups-9") == 0);
    assert (is_alert_identified (alert, "temperature.average@dc-roztoky", "ta2\u20ac\u0441\u0443\u043f\u0435\u044014159") == 1);
    fty_proto_destroy (&alert);
    if (NULL != actions)
        zlist_destroy (&actions);
    }

    {
    zlist_t *actions = zlist_new ();
    zlist_autofree (actions);
    zlist_append(actions, "EMAIL");
    fty_proto_t *alert = alert_new ("temperature.average@DC-Roztoky", "ŽlUťOUčKý kůň", "ACTIVE", "some description", "low", 10, &actions, 0);
    assert (alert);
    assert (is_alert_identified (alert, "temperature.average@dc-roztoky", "ŽlUťOUčKý kůň") == 1);
    assert (is_alert_identified (alert, "temperature.averageDC-Roztoky", "ŽlUťOUčKý kůň") == 0);
    fty_proto_destroy (&alert);
    if (NULL != actions)
        zlist_destroy (&actions);
    }

    //  *********************************
    //  *****   alert_comparator    *****
    //  *********************************

    // test case 1a:
    //  alerts are completelly the same
    {
    zlist_t *actions1 = zlist_new ();
    zlist_autofree (actions1);
    zlist_append(actions1, "SMS");
    fty_proto_t *alert1 = alert_new ("temperature.average@DC-Roztoky", "ups-9", "ACTIVE", "low", "some description", 10,  &actions1, 0);
    assert (alert1);
    zlist_t *actions2 = zlist_new ();
    zlist_autofree (actions2);
    zlist_append(actions2, "SMS");
    fty_proto_t *alert2 = alert_new ("temperature.average@DC-Roztoky", "ups-9", "ACTIVE", "low", "some description", 10,  &actions2, 0);
    assert (alert2);

    assert (alert_comparator (alert1, alert2) == 0);

    if (NULL != actions1)
        zlist_destroy (&actions1);
    if (NULL != actions2)
        zlist_destroy (&actions2);
    fty_proto_destroy (&alert1);
    fty_proto_destroy (&alert2);
    }

    // test case 1b:
    //  alerts are same - rule different case
    {
    zlist_t *actions1 = zlist_new ();
    zlist_autofree (actions1);
    zlist_append(actions1, "SMS");
    fty_proto_t *alert1 = alert_new ("temperature.average@DC-Roztoky", "ups-9", "ACTIVE", "low", "some description", 10, &actions1, 0);
    assert (alert1);
    zlist_t *actions2 = zlist_new ();
    zlist_autofree (actions2);
    zlist_append(actions2, "SMS");
    fty_proto_t *alert2 = alert_new ("temperature.average@dC-Roztoky", "ups-9", "ACTIVE", "low", "some description", 10, &actions2, 0);
    assert (alert2);

    assert (alert_comparator (alert1, alert2) == 0);

    if (NULL != actions1)
        zlist_destroy (&actions1);
    if (NULL != actions2)
        zlist_destroy (&actions2);
    fty_proto_destroy (&alert1);
    fty_proto_destroy (&alert2);
    }

    // test case 2:
    //  other fields are case sensitive

    //  severity is case sensitive
    {
    zlist_t *actions1 = zlist_new ();
    zlist_autofree (actions1);
    zlist_append(actions1, "SMS");
    fty_proto_t *alert1 = alert_new ("temperature.average@DC-Roztoky", "ups-9", "ACTIVE", "low", "some description", 10, &actions1, 0);
    assert (alert1);
    zlist_t *actions2 = zlist_new ();
    zlist_autofree (actions2);
    zlist_append(actions2, "SMS");
    fty_proto_t *alert2 = alert_new ("temperature.average@DC-Roztoky", "ups-9", "ACTIVE", "lOw", "some description", 10, &actions2, 0);
    assert (alert2);

    assert (alert_comparator (alert1, alert2) == 1);

    if (NULL != actions1)
        zlist_destroy (&actions1);
    if (NULL != actions2)
        zlist_destroy (&actions2);
    fty_proto_destroy (&alert1);
    fty_proto_destroy (&alert2);
    }

    //  state is case sensitive
    {
    zlist_t *actions1 = zlist_new ();
    zlist_autofree (actions1);
    zlist_append(actions1, "SMS");
    fty_proto_t *alert1 = alert_new ("temperature.average@DC-Roztoky", "ups-9", "aCTIVE", "low", "some description", 10, &actions1, 0);
    assert (alert1);
    zlist_t *actions2 = zlist_new ();
    zlist_autofree (actions2);
    zlist_append(actions2, "SMS");
    fty_proto_t *alert2 = alert_new ("temperature.average@DC-Roztoky", "ups-9", "ACTIVE", "low", "some description", 10, &actions2, 0);
    assert (alert2);

    assert (alert_comparator (alert1, alert2) == 1);

    if (NULL != actions1)
        zlist_destroy (&actions1);
    if (NULL != actions2)
        zlist_destroy (&actions2);
    fty_proto_destroy (&alert1);
    fty_proto_destroy (&alert2);
    }

    //  element_src is case insensitive
    {
    zlist_t *actions1 = zlist_new ();
    zlist_autofree (actions1);
    zlist_append(actions1, "SMS");
    fty_proto_t *alert1 = alert_new ("temperature.average@DC-Roztoky", "ups-9", "ACTIVE", "low", "some description", 10, &actions1, 0);
    assert (alert1);
    zlist_t *actions2 = zlist_new ();
    zlist_autofree (actions2);
    zlist_append(actions2, "SMS");
    fty_proto_t *alert2 = alert_new ("temperature.average@DC-Roztoky", "Ups-9", "ACTIVE", "low", "some description", 10, &actions2, 0);
    assert (alert2);

    assert (alert_comparator (alert1, alert2) == 0);

    if (NULL != actions1)
        zlist_destroy (&actions1);
    if (NULL != actions2)
        zlist_destroy (&actions2);
    fty_proto_destroy (&alert1);
    fty_proto_destroy (&alert2);
    }

    //  description is case sensitive
    {
    zlist_t *actions1 = zlist_new ();
    zlist_autofree (actions1);
    zlist_append(actions1, "SMS");
    fty_proto_t *alert1 = alert_new ("temperature.average@DC-Roztoky", "ups-9", "ACTIVE", "low", "some description", 10, &actions1, 0);
    assert (alert1);
    zlist_t *actions2 = zlist_new ();
    zlist_autofree (actions2);
    zlist_append(actions2, "SMS");
    fty_proto_t *alert2 = alert_new ("temperature.average@DC-Roztoky", "ups-9", "ACTIVE", "low", "some Description", 10, &actions2, 0);
    assert (alert2);

    assert (alert_comparator (alert1, alert2) == 1);

    if (NULL != actions1)
        zlist_destroy (&actions1);
    if (NULL != actions2)
        zlist_destroy (&actions2);
    fty_proto_destroy (&alert1);
    fty_proto_destroy (&alert2);
    }

    //  time is different
    {
    zlist_t *actions1 = zlist_new ();
    zlist_autofree (actions1);
    zlist_append(actions1, "SMS");
    fty_proto_t *alert1 = alert_new ("temperature.average@DC-Roztoky", "ups-9", "ACTIVE", "low", "some description", 10, &actions1, 0);
    assert (alert1);
    zlist_t *actions2 = zlist_new ();
    zlist_autofree (actions2);
    zlist_append(actions2, "SMS");
    fty_proto_t *alert2 = alert_new ("temperature.average@DC-Roztoky", "ups-9", "ACTIVE", "low", "some description", 35, &actions2, 0);
    assert (alert2);

    assert (alert_comparator (alert1, alert2) == 1);

    if (NULL != actions1)
        zlist_destroy (&actions1);
    if (NULL != actions2)
        zlist_destroy (&actions2);
    fty_proto_destroy (&alert1);
    fty_proto_destroy (&alert2);
    }

    // test case 2g:
    //  action is case sensitive
    {
    zlist_t *actions1 = zlist_new ();
    zlist_autofree (actions1);
    zlist_append(actions1, "SMS");
    fty_proto_t *alert1 = alert_new ("temperature.average@DC-Roztoky", "ups-9", "ACTIVE", "low", "some description", 10, &actions1, 0);
    assert (alert1);
    zlist_t *actions2 = zlist_new ();
    zlist_autofree (actions2);
    zlist_append(actions2, "sms");
    fty_proto_t *alert2 = alert_new ("temperature.average@DC-Roztoky", "ups-9", "ACTIVE", "low", "some description", 10, &actions2, 0);
    assert (alert2);

    assert (alert_comparator (alert1, alert2) == 1);

    if (NULL != actions1)
        zlist_destroy (&actions1);
    if (NULL != actions2)
        zlist_destroy (&actions2);
    fty_proto_destroy (&alert1);
    fty_proto_destroy (&alert2);
    }

    // test case 3a:
    //  fields missing in both messages are equal
    {
    zlist_t *actions1 = zlist_new ();
    zlist_autofree (actions1);
    fty_proto_t *alert1 = alert_new ("temperature.average@DC-Roztoky", NULL, "ACTIVE", NULL, NULL, 10, &actions1, 0);
    assert (alert1);
    zlist_t *actions2 = zlist_new ();
    zlist_autofree (actions2);
    fty_proto_t *alert2 = alert_new ("temperature.average@DC-Roztoky", NULL, "ACTIVE", NULL, NULL, 10, &actions2, 0);
    assert (alert2);

    assert (alert_comparator (alert1, alert2) == 0);

    if (NULL != actions1)
        zlist_destroy (&actions1);
    if (NULL != actions2)
        zlist_destroy (&actions2);
    fty_proto_destroy (&alert1);
    fty_proto_destroy (&alert2);
    }

    // test case 3b:
    //  fields missing in either of messages is not equal
    {
    zlist_t *actions1 = zlist_new ();
    zlist_autofree (actions1);
    zlist_append(actions1, "SMS");
    fty_proto_t *alert1 = alert_new ("temperature.average@DC-Roztoky", "ups-9", "ACTIVE", "low", NULL, 10, &actions1, 0);
    assert (alert1);
    zlist_t *actions2 = zlist_new ();
    zlist_autofree (actions2);
    zlist_append(actions2, "SMS");
    fty_proto_t *alert2 = alert_new ("temperature.average@DC-Roztoky", "ups-9", "ACTIVE", "low", "some description", 10, &actions2, 0);
    assert (alert2);

    assert (alert_comparator (alert1, alert2) == 1);

    if (NULL != actions1)
        zlist_destroy (&actions1);
    if (NULL != actions2)
        zlist_destroy (&actions2);
    fty_proto_destroy (&alert1);
    fty_proto_destroy (&alert2);
    }

    {
    zlist_t *actions1 = zlist_new ();
    zlist_autofree (actions1);
    zlist_append(actions1, "SMS");
    fty_proto_t *alert1 = alert_new ("temperature.average@DC-Roztoky", "ups-9", "ACTIVE", "low", "some description", 10, &actions1, 0);
    assert (alert1);
    zlist_t *actions2 = zlist_new ();
    zlist_autofree (actions2);
    zlist_append(actions2, "SMS");
    fty_proto_t *alert2 = alert_new (NULL,"ups-9", "ACTIVE", "low", "some description", 10, &actions2, 0);
    assert (alert2);

    assert (alert_comparator (alert1, alert2) == 1);

    if (NULL != actions1)
        zlist_destroy (&actions1);
    if (NULL != actions2)
        zlist_destroy (&actions2);
    fty_proto_destroy (&alert1);
    fty_proto_destroy (&alert2);
    }

    {
    zlist_t *actions1 = zlist_new ();
    zlist_autofree (actions1);
    zlist_append(actions1, "SMS");
    fty_proto_t *alert1 = alert_new ("temperature.average@DC-Roztoky", NULL, "ACTIVE", "low", "some description", 10, &actions1, 0);
    assert (alert1);
    zlist_t *actions2 = zlist_new ();
    zlist_autofree (actions2);
    zlist_append(actions2, "SMS");
    fty_proto_t *alert2 = alert_new ("temperature.average@DC-Roztoky", "ups-9", "ACTIVE", "low", "some description", 10, &actions2, 0);
    assert (alert2);

    assert (alert_comparator (alert1, alert2) == 1);

    if (NULL != actions1)
        zlist_destroy (&actions1);
    if (NULL != actions2)
        zlist_destroy (&actions2);
    fty_proto_destroy (&alert1);
    fty_proto_destroy (&alert2);
    }

    // test case 4:
    //  different fields
    {
    zlist_t *actions1 = zlist_new ();
    zlist_autofree (actions1);
    zlist_append(actions1, "SMS");
    fty_proto_t *alert1 = alert_new ("temperature.average@DC-Roztoky", "ups-9", "ACTIVE", "low", "some description", 10, &actions1, 0);
    assert (alert1);
    zlist_t *actions2 = zlist_new ();
    zlist_autofree (actions2);
    zlist_append(actions2, "SMS");
    fty_proto_t *alert2 = alert_new ("temperature.humidity@DC-Roztoky", "ups-9", "ACTIVE", "low", "some description", 10, &actions2, 0);
    assert (alert2);

    assert (alert_comparator (alert1, alert2) == 1);

    if (NULL != actions1)
        zlist_destroy (&actions1);
    if (NULL != actions2)
        zlist_destroy (&actions2);
    fty_proto_destroy (&alert1);
    fty_proto_destroy (&alert2);
    }

    {
    zlist_t *actions1 = zlist_new ();
    zlist_autofree (actions1);
    zlist_append(actions1, "SMS");
    fty_proto_t *alert1 = alert_new ("temperature.average@DC-Roztoky", "ups-9", "ACTIVE", "low", "some description", 10, &actions1, 0);
    assert (alert1);
    zlist_t *actions2 = zlist_new ();
    zlist_autofree (actions2);
    zlist_append(actions2, "SMS");
    fty_proto_t *alert2 = alert_new ("temperature.average@DC-Roztoky", "epdu", "ACTIVE", "low", "some description", 10, &actions2, 0);
    assert (alert2);

    assert (alert_comparator (alert1, alert2) == 1);

    if (NULL != actions1)
        zlist_destroy (&actions1);
    if (NULL != actions2)
        zlist_destroy (&actions2);
    fty_proto_destroy (&alert1);
    fty_proto_destroy (&alert2);
    }

    {
    zlist_t *actions1 = zlist_new ();
    zlist_autofree (actions1);
    zlist_append(actions1, "SMS");
    fty_proto_t *alert1 = alert_new ("temperature.average@DC-Roztoky", "epdu", "ACTIVE", "hugh", "some description", 10, &actions1, 0);
    assert (alert1);
    zlist_t *actions2 = zlist_new ();
    zlist_autofree (actions2);
    zlist_append(actions2, "SMS");
    fty_proto_t *alert2 = alert_new ("temperature.average@DC-Roztoky", "epdu", "ACTIVE", "low", "some description", 10, &actions2, 0);
    assert (alert2);

    assert (alert_comparator (alert1, alert2) == 1);

    if (NULL != actions1)
        zlist_destroy (&actions1);
    if (NULL != actions2)
        zlist_destroy (&actions2);
    fty_proto_destroy (&alert1);
    fty_proto_destroy (&alert2);
    }

    {
    zlist_t *actions1 = zlist_new ();
    zlist_autofree (actions1);
    zlist_append(actions1, "SMS");
    fty_proto_t *alert1 = alert_new ("temperature.average@DC-Roztoky", "epdu", "ACTIVE", "low", "some description", 10, &actions1, 0);
    assert (alert1);
    zlist_t *actions2 = zlist_new ();
    zlist_autofree (actions2);
    zlist_append(actions2, "SMS");
    fty_proto_t *alert2 = alert_new ("temperature.average@DC-Roztoky", "epdu", "ACK-WIP", "low", "some description", 10, &actions2, 0);
    assert (alert2);

    assert (alert_comparator (alert1, alert2) == 1);

    if (NULL != actions1)
        zlist_destroy (&actions1);
    if (NULL != actions2)
        zlist_destroy (&actions2);
    fty_proto_destroy (&alert1);
    fty_proto_destroy (&alert2);
    }

    {
    zlist_t *actions1 = zlist_new ();
    zlist_autofree (actions1);
    zlist_append(actions1, "SMS");
    fty_proto_t *alert1 = alert_new ("temperature.average@DC-Roztoky", "epdu", "ACK-WIP", "low", "shitty description", 10, &actions1, 0);
    assert (alert1);
    zlist_t *actions2 = zlist_new ();
    zlist_autofree (actions2);
    zlist_append(actions2, "SMS");
    fty_proto_t *alert2 = alert_new ("temperature.average@DC-Roztoky", "epdu", "ACK-WIP", "low", "some description", 10, &actions2, 0);
    assert (alert2);

    assert (alert_comparator (alert1, alert2) == 1);

    if (NULL != actions1)
        zlist_destroy (&actions1);
    if (NULL != actions2)
        zlist_destroy (&actions2);
    fty_proto_destroy (&alert1);
    fty_proto_destroy (&alert2);
    }

    {
    zlist_t *actions1 = zlist_new ();
    zlist_autofree (actions1);
    zlist_append(actions1, "SMS");
    fty_proto_t *alert1 = alert_new ("temperature.average@DC-Roztoky", "epdu", "ACK-WIP", "low", "some description", 1, &actions1, 0);
    assert (alert1);
    zlist_t *actions2 = zlist_new ();
    zlist_autofree (actions2);
    zlist_append(actions2, "SMS");
    fty_proto_t *alert2 = alert_new ("temperature.average@DC-Roztoky", "epdu", "ACK-WIP", "low", "some description", 10, &actions2, 0);
    assert (alert2);

    assert (alert_comparator (alert1, alert2) == 1);

    if (NULL != actions1)
        zlist_destroy (&actions1);
    if (NULL != actions2)
        zlist_destroy (&actions2);
    fty_proto_destroy (&alert1);
    fty_proto_destroy (&alert2);
    }

    {
    zlist_t *actions1 = zlist_new ();
    zlist_autofree (actions1);
    zlist_append(actions1, "EMAIL");
    fty_proto_t *alert1 = alert_new ("temperature.average@DC-Roztoky", "epdu", "ACK-WIP", "low", "some description", 10, &actions1, 0);
    assert (alert1);
    zlist_t *actions2 = zlist_new ();
    zlist_autofree (actions2);
    zlist_append(actions2, "SMS");
    fty_proto_t *alert2 = alert_new ("temperature.average@DC-Roztoky", "epdu", "ACK-WIP", "low", "some description", 10, &actions2, 0);
    assert (alert2);

    assert (alert_comparator (alert1, alert2) == 1);

    if (NULL != actions1)
        zlist_destroy (&actions1);
    if (NULL != actions2)
        zlist_destroy (&actions2);
    fty_proto_destroy (&alert1);
    fty_proto_destroy (&alert2);
    }

    // unicode
    {
    zlist_t *actions1 = zlist_new ();
    zlist_autofree (actions1);
    zlist_append(actions1, "EMAIL");
    fty_proto_t *alert1 = alert_new ("temperature.average@DC-Roztoky", "ŽlUťOUčKý kůň", "ACK-WIP", "low", "some description", 10, &actions1, 0);
    assert (alert1);
    zlist_t *actions2 = zlist_new ();
    zlist_autofree (actions2);
    zlist_append(actions2, "SMS");
    fty_proto_t *alert2 = alert_new ("temperature.average@DC-Roztoky", "\u017dlu\u0165ou\u010dk\xc3\xbd K\u016f\xc5\x88", "ACK-WIP", "low", "some description", 10, &actions2, 0);
    assert (alert2);

    assert (alert_comparator (alert1, alert2) == 1);

    if (NULL != actions1)
        zlist_destroy (&actions1);
    if (NULL != actions2)
        zlist_destroy (&actions2);
    fty_proto_destroy (&alert1);
    fty_proto_destroy (&alert2);
    }


    // TODO: action can be mixed

    //  *********************************
    //  *****   alert_save_state    *****
    //  *****   alert_load_state    *****
    //  *********************************

    {

    // Test case #1:
    //  Fill list, store, load, compare one by one
    zlistx_t *alerts = zlistx_new ();
    assert (alerts);
    zlistx_set_destructor (alerts, (czmq_destructor *) fty_proto_destroy);
    zlistx_set_duplicator (alerts, (czmq_duplicator *) fty_proto_dup);

    zlist_t *actions1 = zlist_new ();
    zlist_autofree (actions1);
    zlist_append(actions1, "EMAIL");
    zlist_append(actions1, "SMS");
    fty_proto_t *alert = alert_new ("Rule1", "Element1", "ACTIVE", "high", "xyz", 1, &actions1, 0);
    assert (alert);
    zlistx_add_end (alerts, alert);
    fty_proto_destroy (&alert);

    zlist_t *actions2 = zlist_new ();
    zlist_autofree (actions2);
    zlist_append(actions2, "EMAIL");
    zlist_append(actions2, "SMS");
    alert = alert_new ("Rule1", "Element2", "RESOLVED", "high", "xyz", 20, &actions2, 0);
    assert (alert);
    zlistx_add_end (alerts, alert);
    fty_proto_destroy (&alert);

    zlist_t *actions3 = zlist_new ();
    zlist_autofree (actions3);
    zlist_append(actions3, "SMS");
    alert = alert_new ("Rule2", "Element1", "ACK-WIP", "low", "this is description", 152452412, &actions3, 0);
    assert (alert);
    zlistx_add_end (alerts, alert);
    fty_proto_destroy (&alert);

    zlist_t *actions4 = zlist_new ();
    zlist_autofree (actions4);
    zlist_append(actions4, "EMAIL");
    alert = alert_new ("Rule2", "Element2", "ACK-SILENCE", "high", "x", 5, &actions4, 0);
    assert (alert);
    zlistx_add_end (alerts, alert);
    fty_proto_destroy (&alert);

    zlist_t *actions5 = zlist_new ();
    zlist_autofree (actions5);
    zlist_append(actions5, "EMAIL");
    zlist_append(actions5, "SMS");
    alert = alert_new ("Rule1", "Element3", "RESOLVED", "a", "y", 50, &actions5, 0);
    assert (alert);
    zlistx_add_end (alerts, alert);
    fty_proto_destroy (&alert);

    zlist_t *actions6 = zlist_new ();
    zlist_autofree (actions6);
    zlist_append(actions6, "EMAIL");
    zlist_append(actions6, "SMS");
    alert = alert_new ("realpower.default", "ŽlUťOUčKý kůň супер", "ACTIVE", "low", "unicode test case #1", 60, &actions6, 0);
    assert (alert);
    zlistx_add_end (alerts, alert);
    fty_proto_destroy (&alert);

    int rv = alert_save_state (alerts, ".", "test_state_file");
    assert (rv == 0);

    zlistx_destroy (&alerts);

    alerts = zlistx_new ();
    assert (alerts);
    zlistx_set_destructor (alerts, (czmq_destructor *) fty_proto_destroy);
    zlistx_set_duplicator (alerts, (czmq_duplicator *) fty_proto_dup);
    rv = alert_load_state (alerts, ".", "test_state_file");
    assert  (rv == 0);

    zsys_debug ("zlistx size == %d", zlistx_size (alerts));

    // Check them one by one
    fty_proto_t *cursor = (fty_proto_t *) zlistx_first (alerts);
    assert (str_eq (fty_proto_rule (cursor), "Rule1"));
    assert (str_eq (fty_proto_name (cursor), "Element1"));
    assert (str_eq (fty_proto_state (cursor), "ACTIVE"));
    assert (str_eq (fty_proto_severity (cursor), "high"));
    assert (str_eq (fty_proto_description (cursor), "xyz"));
    assert (str_eq (fty_proto_action_first (cursor), "EMAIL"));
    assert (str_eq (fty_proto_action_next (cursor), "SMS"));
    assert (NULL == fty_proto_action_next (cursor));
    assert (fty_proto_time (cursor) == (uint64_t) 1);

    cursor = (fty_proto_t *) zlistx_next (alerts);
    assert (str_eq (fty_proto_rule (cursor), "Rule1"));
    assert (str_eq (fty_proto_name (cursor), "Element2"));
    assert (str_eq (fty_proto_state (cursor), "RESOLVED"));
    assert (str_eq (fty_proto_severity (cursor), "high"));
    assert (str_eq (fty_proto_description (cursor), "xyz"));
    assert (str_eq (fty_proto_action_first (cursor), "EMAIL"));
    assert (str_eq (fty_proto_action_next (cursor), "SMS"));
    assert (NULL == fty_proto_action_next (cursor));
    assert (fty_proto_time (cursor) == (uint64_t) 20);

    cursor = (fty_proto_t *) zlistx_next (alerts);
    assert (str_eq (fty_proto_rule (cursor), "Rule2"));
    assert (str_eq (fty_proto_name (cursor), "Element1"));
    assert (str_eq (fty_proto_state (cursor), "ACK-WIP"));
    assert (str_eq (fty_proto_severity (cursor), "low"));
    assert (str_eq (fty_proto_description (cursor), "this is description"));
    assert (str_eq (fty_proto_action_first (cursor), "SMS"));
    assert (NULL == fty_proto_action_next (cursor));
    assert (fty_proto_time (cursor) == (uint64_t) 152452412);

    cursor = (fty_proto_t *) zlistx_next (alerts);
    assert (str_eq (fty_proto_rule (cursor), "Rule2"));
    assert (str_eq (fty_proto_name (cursor), "Element2"));
    assert (str_eq (fty_proto_state (cursor), "ACK-SILENCE"));
    assert (str_eq (fty_proto_severity (cursor), "high"));
    assert (str_eq (fty_proto_description (cursor), "x"));
    assert (str_eq (fty_proto_action_first (cursor), "EMAIL"));
    assert (NULL == fty_proto_action_next (cursor));
    assert (fty_proto_time (cursor) == (uint64_t) 5);

    cursor = (fty_proto_t *) zlistx_next (alerts);
    assert (str_eq (fty_proto_rule (cursor), "Rule1"));
    assert (str_eq (fty_proto_name (cursor), "Element3"));
    assert (str_eq (fty_proto_state (cursor), "RESOLVED"));
    assert (str_eq (fty_proto_severity (cursor), "a"));
    assert (str_eq (fty_proto_description (cursor), "y"));
    assert (str_eq (fty_proto_action_first (cursor), "EMAIL"));
    assert (str_eq (fty_proto_action_next (cursor), "SMS"));
    assert (NULL == fty_proto_action_next (cursor));
    assert (fty_proto_time (cursor) == (uint64_t) 50);

    cursor = (fty_proto_t *) zlistx_next (alerts);
    assert (str_eq (fty_proto_rule (cursor), "realpower.default"));
    assert (utf8eq (fty_proto_name (cursor), "ŽlUťOUčKý kůň супер"));
    assert (str_eq (fty_proto_state (cursor), "ACTIVE"));
    assert (str_eq (fty_proto_severity (cursor), "low"));
    assert (str_eq (fty_proto_description (cursor), "unicode test case #1"));
    assert (str_eq (fty_proto_action_first (cursor), "EMAIL"));
    assert (str_eq (fty_proto_action_next (cursor), "SMS"));
    assert (NULL == fty_proto_action_next (cursor));
    assert (fty_proto_time (cursor) == (uint64_t) 60);
    zlistx_destroy (&alerts);

    if (NULL != actions1)
        zlist_destroy (&actions1);
    if (NULL != actions2)
        zlist_destroy (&actions2);
    if (NULL != actions3)
        zlist_destroy (&actions3);
    if (NULL != actions4)
        zlist_destroy (&actions4);
    if (NULL != actions5)
        zlist_destroy (&actions5);
    if (NULL != actions6)
        zlist_destroy (&actions6);
    }

    // Test case #2:
    //  file does not exist
    {
    zlistx_t *alerts = zlistx_new ();
    assert (alerts);
    zlistx_set_destructor (alerts, (czmq_destructor *) fty_proto_destroy);
    zlistx_set_duplicator (alerts, (czmq_duplicator *) fty_proto_dup);
    int rv = alert_load_state (alerts, ".", "does_not_exist");
    assert  (rv == -1);
    zlistx_destroy (&alerts);
    }

    // State file with old format
    {
    zlistx_t *alerts = zlistx_new ();
    assert (alerts);
    zlistx_set_destructor (alerts, (czmq_destructor *) fty_proto_destroy);
    zlistx_set_duplicator (alerts, (czmq_duplicator *) fty_proto_dup);
    int rv = alert_load_state (alerts, "src/selftest-ro", "old_state_file");
    assert (rv == 0);
    assert (zlistx_size(alerts) == 0);
    zlistx_destroy (&alerts);
    }

    //  @end
    printf ("OK\n");
}
