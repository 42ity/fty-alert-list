/*  =========================================================================
    alerts_utils - Helper functions

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
    alerts_utils - Helper functions
@discuss
@end
*/

#include "alerts_list_classes.h"

int
str_eq (const char *s1, const char *s2) {
    if ((!s1 && s2) || (s1 && !s2))
        return 0;
    if (!s1 && !s2)
        return 1;
    return streq (s1, s2);
}

int
alert_id_comparator (bios_proto_t *alert1, bios_proto_t *alert2) {
    assert (alert1);
    assert (alert2);
    assert (bios_proto_id (alert1) == BIOS_PROTO_ALERT);
    assert (bios_proto_id (alert2) == BIOS_PROTO_ALERT);

    if (bios_proto_rule (alert1) == NULL ||
        bios_proto_rule (alert2) == NULL) {
        return 1;
    }

    if (strcasecmp (bios_proto_rule (alert1), bios_proto_rule (alert2)) == 0 &&
        str_eq (bios_proto_element_src (alert1), bios_proto_element_src (alert2))) {
        return 0;
    }
    else {
        return 1;
    }
}

int
alert_comparator (bios_proto_t *alert1, bios_proto_t *alert2) {
    // TODO: it might be needed to parse action and compare the individual actions
    assert (alert1);
    assert (alert2);
    assert (bios_proto_id (alert1) == BIOS_PROTO_ALERT);
    assert (bios_proto_id (alert2) == BIOS_PROTO_ALERT);

    if (bios_proto_rule (alert1) == NULL ||
        bios_proto_rule (alert2) == NULL) {
        return 1;
    }

    if (strcasecmp (bios_proto_rule (alert1), bios_proto_rule (alert2)) == 0 &&
        str_eq (bios_proto_element_src (alert1), bios_proto_element_src (alert2)) &&
        str_eq (bios_proto_state (alert1), bios_proto_state (alert2)) &&
        str_eq (bios_proto_severity (alert1), bios_proto_severity (alert2)) &&
        str_eq (bios_proto_description (alert1), bios_proto_description (alert2)) &&
        str_eq (bios_proto_action (alert1), bios_proto_action (alert2)) &&
        bios_proto_time (alert1) == bios_proto_time (alert2)) {
        return 0;
    }
    else {
        return 1;
    }
}

int
is_alertstate (const char *state) {
    if (str_eq (state, "ALL") ||
        str_eq (state, "ACTIVE") ||
        str_eq (state, "ACK-WIP") ||
        str_eq (state, "ACK-IGNORE") ||
        str_eq (state, "ACK-PAUSE") ||
        str_eq (state, "ACK-SILENCE")) {
        return 1;
    }
    return 0;
}

//  --------------------------------------------------------------------------
//  Self test of this class

void
alerts_utils_test (bool verbose)
{
    
    //  @selftest

    printf (" * alerts_utils: ");

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
    
    //  *****************************
    //  *****   is_alertstate   *****
    //  *****************************
    
    assert (is_alertstate ("ALL") == 1);   
    assert (is_alertstate ("ACTIVE") == 1);   
    assert (is_alertstate ("ACK-WIP") == 1);   
    assert (is_alertstate ("ACK-IGNORE") == 1);   
    assert (is_alertstate ("ACK-PAUSE") == 1);   
    assert (is_alertstate ("ACK-SILENCE") == 1);

    assert (is_alertstate ("") == 0);
    assert (is_alertstate ("RESOLVED") == 0);
    assert (is_alertstate ("all") == 0);
    assert (is_alertstate ("active") == 0);
    assert (is_alertstate ("ACK") == 0);

    //  ************************************
    //  *****   alert_id_comparator    *****
    //  ************************************


    // test case 1a:
    //  alerts are completely the same
    {
    bios_proto_t *alert1 = bios_proto_new (BIOS_PROTO_ALERT);
    assert (alert1);
    bios_proto_t *alert2 = bios_proto_new (BIOS_PROTO_ALERT);
    assert (alert2);
     
    bios_proto_set_rule (alert1, "%s", "temperature.average@DC-Roztoky");
    bios_proto_set_rule (alert2, "%s", "temperature.average@DC-Roztoky");
    bios_proto_set_element_src (alert1, "%s", "ups-9");
    bios_proto_set_element_src (alert2, "%s", "ups-9");
    bios_proto_set_state (alert1, "%s", "ACTIVE");
    bios_proto_set_state (alert2, "%s", "ACTIVE");
    bios_proto_set_description (alert1, "%s", "some description");
    bios_proto_set_description (alert2, "%s", "some description");
    bios_proto_set_severity (alert1, "%s", "low");
    bios_proto_set_severity (alert2, "%s", "low");
    bios_proto_set_time (alert1, 10);
    bios_proto_set_time (alert2, 10);
    bios_proto_set_action (alert1, "EMAIL");
    bios_proto_set_action (alert2, "EMAIL");

    assert (alert_id_comparator (alert1, alert2) == 0);

    bios_proto_destroy (&alert1);   
    bios_proto_destroy (&alert2);
    }

    // test case 1b:
    //  alerts have the same identifier,
    //  different meta-data which represents real world use case of one alert
    //  at two different times
    {
    bios_proto_t *alert1 = bios_proto_new (BIOS_PROTO_ALERT);
    assert (alert1);
    bios_proto_t *alert2 = bios_proto_new (BIOS_PROTO_ALERT);
    assert (alert2);
     
    bios_proto_set_rule (alert1, "%s", "temperature.average@DC-Roztoky");
    bios_proto_set_rule (alert2, "%s", "temperature.average@DC-Roztoky");
    bios_proto_set_element_src (alert1, "%s", "ups-9");
    bios_proto_set_element_src (alert2, "%s", "ups-9");
    bios_proto_set_state (alert1, "%s", "ACTIVE");
    bios_proto_set_state (alert2, "%s", "ACK-IGNORE");
    bios_proto_set_description (alert1, "%s", "some description");
    bios_proto_set_description (alert2, "%s", "some description");
    bios_proto_set_severity (alert1, "%s", "low");
    bios_proto_set_severity (alert2, "%s", "high");
    bios_proto_set_time (alert1, 10);
    bios_proto_set_time (alert2, 10);
    bios_proto_set_action (alert1, "EMAIL");
    bios_proto_set_action (alert2, "SMS");

    assert (alert_id_comparator (alert1, alert2) == 0);

    bios_proto_destroy (&alert1);   
    bios_proto_destroy (&alert2);
    }

    // test case 1c:
    //  alerts have the same identifier,
    //  different as well as missing meta-data 
    {    
    bios_proto_t *alert1 = bios_proto_new (BIOS_PROTO_ALERT);
    assert (alert1);
    bios_proto_t *alert2 = bios_proto_new (BIOS_PROTO_ALERT);
    assert (alert2);
     
    bios_proto_set_rule (alert1, "%s", "temperature.average@DC-Roztoky");
    bios_proto_set_rule (alert2, "%s", "temperature.average@DC-Roztoky");
    bios_proto_set_element_src (alert1, "%s", "ups-9");
    bios_proto_set_element_src (alert2, "%s", "ups-9");
    bios_proto_set_state (alert1, "%s", "ACK-WIP");
    bios_proto_set_state (alert2, "%s", "ACTIVE");
    // description for alert1 is missing (NULL)
    bios_proto_set_description (alert2, "%s", "some description");
    bios_proto_set_severity (alert1, "%s", "high");
    bios_proto_set_severity (alert2, "%s", "low");
    bios_proto_set_time (alert1, 10);
    bios_proto_set_time (alert2, 20);
    bios_proto_set_action (alert1, "EMAIL");
    // description for alert 2 is missing (NULL);

    assert (alert_id_comparator (alert1, alert2) == 0);

    bios_proto_destroy (&alert1);   
    bios_proto_destroy (&alert2);   
    }
    
    // test case 1d:
    //  alerts have the same identifier - rule name has different case
    //  different as well as missing meta-data 
    {    
    bios_proto_t *alert1 = bios_proto_new (BIOS_PROTO_ALERT);
    assert (alert1);
    bios_proto_t *alert2 = bios_proto_new (BIOS_PROTO_ALERT);
    assert (alert2);
     
    bios_proto_set_rule (alert1, "%s", "temperature.average@DC-Roztoky");
    bios_proto_set_rule (alert2, "%s", "Temperature.Average@dC-roztoky");
    bios_proto_set_element_src (alert1, "%s", "ups-9");
    bios_proto_set_element_src (alert2, "%s", "ups-9");
    bios_proto_set_state (alert1, "%s", "ACK-WIP");
    bios_proto_set_state (alert2, "%s", "ACTIVE");
    // description for alert1 is missing (NULL)
    bios_proto_set_description (alert2, "%s", "some description");
    bios_proto_set_severity (alert1, "%s", "high");
    bios_proto_set_severity (alert2, "%s", "low");
    bios_proto_set_time (alert1, 10);
    bios_proto_set_time (alert2, 20);
    bios_proto_set_action (alert1, "EMAIL");
    // description for alert 2 is missing (NULL);

    assert (alert_id_comparator (alert1, alert2) == 0);

    bios_proto_destroy (&alert1);   
    bios_proto_destroy (&alert2);   
    }   

    // test case 2a:
    // alerts don't have the same identifier - different rule

    {    
    bios_proto_t *alert1 = bios_proto_new (BIOS_PROTO_ALERT);
    assert (alert1);
    bios_proto_t *alert2 = bios_proto_new (BIOS_PROTO_ALERT);
    assert (alert2);
     
    bios_proto_set_rule (alert1, "%s", "temperature.average@DC-Lab");
    bios_proto_set_rule (alert2, "%s", "temperature.average@DC-Roztoky");
    bios_proto_set_element_src (alert1, "%s", "ups-9");
    bios_proto_set_element_src (alert2, "%s", "ups-9");
    bios_proto_set_state (alert1, "%s", "ACK-WIP");
    bios_proto_set_state (alert2, "%s", "ACTIVE");
    bios_proto_set_severity (alert1, "%s", "high");
    bios_proto_set_severity (alert2, "%s", "low");
    bios_proto_set_time (alert1, 10);
    bios_proto_set_time (alert2, 20);

    assert (alert_id_comparator (alert1, alert2) == 1);

    bios_proto_destroy (&alert1);   
    bios_proto_destroy (&alert2);   
    }

    // test case 2b:
    // alerts don't have the same identifier - different element_src
    
    {    
    bios_proto_t *alert1 = bios_proto_new (BIOS_PROTO_ALERT);
    assert (alert1);
    bios_proto_t *alert2 = bios_proto_new (BIOS_PROTO_ALERT);
    assert (alert2);
     
    bios_proto_set_rule (alert1, "%s", "temperature.average@DC-Roztoky");
    bios_proto_set_rule (alert2, "%s", "temperature.average@DC-Roztoky");
    bios_proto_set_element_src (alert1, "%s", "epdu");
    bios_proto_set_element_src (alert2, "%s", "ups-9");
    bios_proto_set_state (alert1, "%s", "ACK-WIP");
    bios_proto_set_state (alert2, "%s", "ACTIVE");
    bios_proto_set_severity (alert1, "%s", "high");
    bios_proto_set_severity (alert2, "%s", "low");
    bios_proto_set_time (alert1, 10);
    bios_proto_set_time (alert2, 20);

    assert (alert_id_comparator (alert1, alert2) == 1);

    bios_proto_destroy (&alert1);   
    bios_proto_destroy (&alert2);   
    }

    // test case 2c:
    // alerts don't have the same identifier - different case of element_src
    
    {    
    bios_proto_t *alert1 = bios_proto_new (BIOS_PROTO_ALERT);
    assert (alert1);
    bios_proto_t *alert2 = bios_proto_new (BIOS_PROTO_ALERT);
    assert (alert2);
     
    bios_proto_set_rule (alert1, "%s", "temperature.average@DC-Roztoky");
    bios_proto_set_rule (alert2, "%s", "temperature.average@DC-Roztoky");
    bios_proto_set_element_src (alert1, "%s", "Ups-9");
    bios_proto_set_element_src (alert2, "%s", "ups-9");
    bios_proto_set_state (alert1, "%s", "ACK-WIP");
    bios_proto_set_state (alert2, "%s", "ACTIVE");
    bios_proto_set_severity (alert1, "%s", "high");
    bios_proto_set_severity (alert2, "%s", "low");
    bios_proto_set_time (alert1, 10);
    bios_proto_set_time (alert2, 20);

    assert (alert_id_comparator (alert1, alert2) == 1);

    bios_proto_destroy (&alert1);   
    bios_proto_destroy (&alert2);   
    }


    // test case 3:
    // alerts don't have the same identifier -different element_src, rule
    {    
    bios_proto_t *alert1 = bios_proto_new (BIOS_PROTO_ALERT);
    assert (alert1);
    bios_proto_t *alert2 = bios_proto_new (BIOS_PROTO_ALERT);
    assert (alert2);
     
    bios_proto_set_rule (alert1, "%s", "temperature.average@DC-Roztoky");
    bios_proto_set_rule (alert2, "%s", "temperature.humidity@DC-Roztoky");
    bios_proto_set_element_src (alert1, "%s", "epdu");
    bios_proto_set_element_src (alert2, "%s", "ups-9");
    bios_proto_set_state (alert1, "%s", "ACK-WIP");
    bios_proto_set_state (alert2, "%s", "ACTIVE");
    bios_proto_set_severity (alert1, "%s", "high");
    bios_proto_set_severity (alert2, "%s", "low");
    bios_proto_set_time (alert1, 10);
    bios_proto_set_time (alert2, 20);

    assert (alert_id_comparator (alert1, alert2) == 1);

    bios_proto_destroy (&alert1);   
    bios_proto_destroy (&alert2);   
    }
    

    //  *********************************
    //  *****   alert_comparator    *****
    //  *********************************

    // test case 1a:
    //  alerts are completelly the same
    {    
    bios_proto_t *alert1 = bios_proto_new (BIOS_PROTO_ALERT);
    assert (alert1);
    bios_proto_t *alert2 = bios_proto_new (BIOS_PROTO_ALERT);
    assert (alert2);
     
    bios_proto_set_rule (alert1, "%s", "temperature.average@DC-Roztoky");
    bios_proto_set_rule (alert2, "%s", "temperature.average@DC-Roztoky");
    bios_proto_set_element_src (alert1, "%s", "ups-9");
    bios_proto_set_element_src (alert2, "%s", "ups-9");
    bios_proto_set_state (alert1, "%s", "ACTIVE");
    bios_proto_set_state (alert2, "%s", "ACTIVE");
    bios_proto_set_severity (alert1, "%s", "low");
    bios_proto_set_severity (alert2, "%s", "low");
    bios_proto_set_description (alert1, "%s", "some description");
    bios_proto_set_description (alert2, "%s", "some description");
    bios_proto_set_time (alert1, 10);
    bios_proto_set_time (alert2, 10);
    bios_proto_set_action (alert1, "%s", "SMS");
    bios_proto_set_action (alert2, "%s", "SMS");

    assert (alert_comparator (alert1, alert2) == 0);

    bios_proto_destroy (&alert1);   
    bios_proto_destroy (&alert2);   
    }

    // test case 1b:
    //  alerts are same - rule different case
    {    
    bios_proto_t *alert1 = bios_proto_new (BIOS_PROTO_ALERT);
    assert (alert1);
    bios_proto_t *alert2 = bios_proto_new (BIOS_PROTO_ALERT);
    assert (alert2);
     
    bios_proto_set_rule (alert1, "%s", "temperature.average@DC-Roztoky");
    bios_proto_set_rule (alert2, "%s", "temperature.average@dC-Roztoky");
    bios_proto_set_element_src (alert1, "%s", "ups-9");
    bios_proto_set_element_src (alert2, "%s", "ups-9");
    bios_proto_set_state (alert1, "%s", "ACTIVE");
    bios_proto_set_state (alert2, "%s", "ACTIVE");
    bios_proto_set_severity (alert1, "%s", "low");
    bios_proto_set_severity (alert2, "%s", "low");
    bios_proto_set_description (alert1, "%s", "some description");
    bios_proto_set_description (alert2, "%s", "some description");
    bios_proto_set_time (alert1, 10);
    bios_proto_set_time (alert2, 10);
    bios_proto_set_action (alert1, "%s", "SMS");
    bios_proto_set_action (alert2, "%s", "SMS");

    assert (alert_comparator (alert1, alert2) == 0);

    bios_proto_destroy (&alert1);   
    bios_proto_destroy (&alert2);   
    }

    // test case 2:
    //  other fields are case sensitive
    
    //  severity is case sensitive
    {    
    bios_proto_t *alert1 = bios_proto_new (BIOS_PROTO_ALERT);
    assert (alert1);
    bios_proto_t *alert2 = bios_proto_new (BIOS_PROTO_ALERT);
    assert (alert2);
     
    bios_proto_set_rule (alert1, "%s", "temperature.average@DC-Roztoky");
    bios_proto_set_rule (alert2, "%s", "temperature.average@DC-Roztoky");
    bios_proto_set_element_src (alert1, "%s", "ups-9");
    bios_proto_set_element_src (alert2, "%s", "ups-9");
    bios_proto_set_state (alert1, "%s", "ACTIVE");
    bios_proto_set_state (alert2, "%s", "ACTIVE");
    bios_proto_set_severity (alert1, "%s", "low");
    bios_proto_set_severity (alert2, "%s", "lOw");
    bios_proto_set_description (alert1, "%s", "some description");
    bios_proto_set_description (alert2, "%s", "some description");
    bios_proto_set_time (alert1, 10);
    bios_proto_set_time (alert2, 10);
    bios_proto_set_action (alert1, "%s", "SMS");
    bios_proto_set_action (alert2, "%s", "SMS");

    assert (alert_comparator (alert1, alert2) == 1);

    bios_proto_destroy (&alert1);   
    bios_proto_destroy (&alert2);   
    }

    //  state is case sensitive
    {    
    bios_proto_t *alert1 = bios_proto_new (BIOS_PROTO_ALERT);
    assert (alert1);
    bios_proto_t *alert2 = bios_proto_new (BIOS_PROTO_ALERT);
    assert (alert2);
     
    bios_proto_set_rule (alert1, "%s", "temperature.average@DC-Roztoky");
    bios_proto_set_rule (alert2, "%s", "temperature.average@DC-Roztoky");
    bios_proto_set_element_src (alert1, "%s", "ups-9");
    bios_proto_set_element_src (alert2, "%s", "ups-9");
    bios_proto_set_state (alert1, "%s", "aCTIVE");
    bios_proto_set_state (alert2, "%s", "ACTIVE");
    bios_proto_set_severity (alert1, "%s", "low");
    bios_proto_set_severity (alert2, "%s", "low");
    bios_proto_set_description (alert1, "%s", "some description");
    bios_proto_set_description (alert2, "%s", "some description");
    bios_proto_set_time (alert1, 10);
    bios_proto_set_time (alert2, 10);
    bios_proto_set_action (alert1, "%s", "SMS");
    bios_proto_set_action (alert2, "%s", "SMS");

    assert (alert_comparator (alert1, alert2) == 1);

    bios_proto_destroy (&alert1);   
    bios_proto_destroy (&alert2);   
    }

    //  element_src is case sensitive
    {    
    bios_proto_t *alert1 = bios_proto_new (BIOS_PROTO_ALERT);
    assert (alert1);
    bios_proto_t *alert2 = bios_proto_new (BIOS_PROTO_ALERT);
    assert (alert2);
     
    bios_proto_set_rule (alert1, "%s", "temperature.average@DC-Roztoky");
    bios_proto_set_rule (alert2, "%s", "temperature.average@DC-Roztoky");
    bios_proto_set_element_src (alert1, "%s", "ups-9");
    bios_proto_set_element_src (alert2, "%s", "Ups-9");
    bios_proto_set_state (alert1, "%s", "ACTIVE");
    bios_proto_set_state (alert2, "%s", "ACTIVE");
    bios_proto_set_severity (alert1, "%s", "low");
    bios_proto_set_severity (alert2, "%s", "low");
    bios_proto_set_description (alert1, "%s", "some description");
    bios_proto_set_description (alert2, "%s", "some description");
    bios_proto_set_time (alert1, 10);
    bios_proto_set_time (alert2, 10);
    bios_proto_set_action (alert1, "%s", "SMS");
    bios_proto_set_action (alert2, "%s", "SMS");

    assert (alert_comparator (alert1, alert2) == 1);

    bios_proto_destroy (&alert1);   
    bios_proto_destroy (&alert2);   
    }

    //  description is case sensitive
    {    
    bios_proto_t *alert1 = bios_proto_new (BIOS_PROTO_ALERT);
    assert (alert1);
    bios_proto_t *alert2 = bios_proto_new (BIOS_PROTO_ALERT);
    assert (alert2);
     
    bios_proto_set_rule (alert1, "%s", "temperature.average@DC-Roztoky");
    bios_proto_set_rule (alert2, "%s", "temperature.average@DC-Roztoky");
    bios_proto_set_element_src (alert1, "%s", "ups-9");
    bios_proto_set_element_src (alert2, "%s", "ups-9");
    bios_proto_set_state (alert1, "%s", "ACTIVE");
    bios_proto_set_state (alert2, "%s", "ACTIVE");
    bios_proto_set_severity (alert1, "%s", "low");
    bios_proto_set_severity (alert2, "%s", "low");
    bios_proto_set_description (alert1, "%s", "some description");
    bios_proto_set_description (alert2, "%s", "some Description");
    bios_proto_set_time (alert1, 10);
    bios_proto_set_time (alert2, 10);
    bios_proto_set_action (alert1, "%s", "SMS");
    bios_proto_set_action (alert2, "%s", "SMS");

    assert (alert_comparator (alert1, alert2) == 1);

    bios_proto_destroy (&alert1);   
    bios_proto_destroy (&alert2);   
    }

    //  time is different
    {    
    bios_proto_t *alert1 = bios_proto_new (BIOS_PROTO_ALERT);
    assert (alert1);
    bios_proto_t *alert2 = bios_proto_new (BIOS_PROTO_ALERT);
    assert (alert2);
     
    bios_proto_set_rule (alert1, "%s", "temperature.average@DC-Roztoky");
    bios_proto_set_rule (alert2, "%s", "temperature.average@DC-Roztoky");
    bios_proto_set_element_src (alert1, "%s", "ups-9");
    bios_proto_set_element_src (alert2, "%s", "ups-9");
    bios_proto_set_state (alert1, "%s", "ACTIVE");
    bios_proto_set_state (alert2, "%s", "ACTIVE");
    bios_proto_set_severity (alert1, "%s", "low");
    bios_proto_set_severity (alert2, "%s", "low");
    bios_proto_set_description (alert1, "%s", "some description");
    bios_proto_set_description (alert2, "%s", "some description");
    bios_proto_set_time (alert1, 10);
    bios_proto_set_time (alert2, 35);
    bios_proto_set_action (alert1, "%s", "SMS");
    bios_proto_set_action (alert2, "%s", "SMS");

    assert (alert_comparator (alert1, alert2) == 1);

    bios_proto_destroy (&alert1);   
    bios_proto_destroy (&alert2);   
    }

    // test case 2g:
    //  action is case sensitive
    {    
    bios_proto_t *alert1 = bios_proto_new (BIOS_PROTO_ALERT);
    assert (alert1);
    bios_proto_t *alert2 = bios_proto_new (BIOS_PROTO_ALERT);
    assert (alert2);
     
    bios_proto_set_rule (alert1, "%s", "temperature.average@DC-Roztoky");
    bios_proto_set_rule (alert2, "%s", "temperature.average@DC-Roztoky");
    bios_proto_set_element_src (alert1, "%s", "ups-9");
    bios_proto_set_element_src (alert2, "%s", "ups-9");
    bios_proto_set_state (alert1, "%s", "ACTIVE");
    bios_proto_set_state (alert2, "%s", "ACTIVE");
    bios_proto_set_severity (alert1, "%s", "low");
    bios_proto_set_severity (alert2, "%s", "low");
    bios_proto_set_description (alert1, "%s", "some description");
    bios_proto_set_description (alert2, "%s", "some description");
    bios_proto_set_time (alert1, 10);
    bios_proto_set_time (alert2, 10);
    bios_proto_set_action (alert1, "%s", "SMS");
    bios_proto_set_action (alert2, "%s", "sms");

    assert (alert_comparator (alert1, alert2) == 1);

    bios_proto_destroy (&alert1);   
    bios_proto_destroy (&alert2);   
    }

    // test case 3a:
    //  fields missing in both messages are equal
    {    
    bios_proto_t *alert1 = bios_proto_new (BIOS_PROTO_ALERT);
    assert (alert1);
    bios_proto_t *alert2 = bios_proto_new (BIOS_PROTO_ALERT);
    assert (alert2);
     
    bios_proto_set_rule (alert1, "%s", "temperature.average@DC-Roztoky");
    bios_proto_set_rule (alert2, "%s", "temperature.average@DC-Roztoky");
    bios_proto_set_state (alert1, "%s", "ACTIVE");
    bios_proto_set_state (alert2, "%s", "ACTIVE");
    bios_proto_set_time (alert1, 10);
    bios_proto_set_time (alert2, 10);

    assert (alert_comparator (alert1, alert2) == 0);

    bios_proto_destroy (&alert1);   
    bios_proto_destroy (&alert2);   
    }
    
    // test case 3b:
    //  fields missing in either of messages is not equal
    {    
    bios_proto_t *alert1 = bios_proto_new (BIOS_PROTO_ALERT);
    assert (alert1);
    bios_proto_t *alert2 = bios_proto_new (BIOS_PROTO_ALERT);
    assert (alert2);
     
    bios_proto_set_rule (alert1, "%s", "temperature.average@DC-Roztoky");
    bios_proto_set_rule (alert2, "%s", "temperature.average@DC-Roztoky");
    bios_proto_set_element_src (alert1, "%s", "ups-9");
    bios_proto_set_element_src (alert2, "%s", "ups-9");
    bios_proto_set_state (alert1, "%s", "ACTIVE");
    bios_proto_set_state (alert2, "%s", "ACTIVE");
    bios_proto_set_severity (alert1, "%s", "low");
    bios_proto_set_severity (alert2, "%s", "low");
    bios_proto_set_description (alert2, "%s", "some description");
    bios_proto_set_time (alert1, 10);
    bios_proto_set_time (alert2, 10);
    bios_proto_set_action (alert1, "%s", "SMS");
    bios_proto_set_action (alert2, "%s", "SMS");

    assert (alert_comparator (alert1, alert2) == 1);

    bios_proto_destroy (&alert1);   
    bios_proto_destroy (&alert2);   
    }

    {    
    bios_proto_t *alert1 = bios_proto_new (BIOS_PROTO_ALERT);
    assert (alert1);
    bios_proto_t *alert2 = bios_proto_new (BIOS_PROTO_ALERT);
    assert (alert2);
     
    bios_proto_set_rule (alert1, "%s", "temperature.average@DC-Roztoky");
    bios_proto_set_element_src (alert1, "%s", "ups-9");
    bios_proto_set_element_src (alert2, "%s", "ups-9");
    bios_proto_set_state (alert1, "%s", "ACTIVE");
    bios_proto_set_state (alert2, "%s", "ACTIVE");
    bios_proto_set_severity (alert1, "%s", "low");
    bios_proto_set_severity (alert2, "%s", "low");
    bios_proto_set_description (alert1, "%s", "some description");
    bios_proto_set_description (alert2, "%s", "some description");
    bios_proto_set_time (alert1, 10);
    bios_proto_set_time (alert2, 10);
    bios_proto_set_action (alert1, "%s", "SMS");
    bios_proto_set_action (alert2, "%s", "SMS");

    assert (alert_comparator (alert1, alert2) == 1);

    bios_proto_destroy (&alert1);   
    bios_proto_destroy (&alert2);   
    }

    {    
    bios_proto_t *alert1 = bios_proto_new (BIOS_PROTO_ALERT);
    assert (alert1);
    bios_proto_t *alert2 = bios_proto_new (BIOS_PROTO_ALERT);
    assert (alert2);
     
    bios_proto_set_rule (alert1, "%s", "temperature.average@DC-Roztoky");
    bios_proto_set_rule (alert2, "%s", "temperature.average@DC-Roztoky");
    bios_proto_set_element_src (alert2, "%s", "ups-9");
    bios_proto_set_state (alert1, "%s", "ACTIVE");
    bios_proto_set_state (alert2, "%s", "ACTIVE");
    bios_proto_set_severity (alert1, "%s", "low");
    bios_proto_set_severity (alert2, "%s", "low");
    bios_proto_set_description (alert1, "%s", "some description");
    bios_proto_set_description (alert2, "%s", "some description");
    bios_proto_set_time (alert1, 10);
    bios_proto_set_time (alert2, 10);
    bios_proto_set_action (alert1, "%s", "SMS");
    bios_proto_set_action (alert2, "%s", "SMS");

    assert (alert_comparator (alert1, alert2) == 1);

    bios_proto_destroy (&alert1);   
    bios_proto_destroy (&alert2);   
    }

    // test case 4:
    //  different fields
    {    
    bios_proto_t *alert1 = bios_proto_new (BIOS_PROTO_ALERT);
    assert (alert1);
    bios_proto_t *alert2 = bios_proto_new (BIOS_PROTO_ALERT);
    assert (alert2);
     
    bios_proto_set_rule (alert1, "%s", "temperature.average@DC-Roztoky");
    bios_proto_set_rule (alert2, "%s", "temperature.humidity@DC-Roztoky");
    bios_proto_set_element_src (alert1, "%s", "ups-9");
    bios_proto_set_element_src (alert2, "%s", "ups-9");
    bios_proto_set_state (alert1, "%s", "ACTIVE");
    bios_proto_set_state (alert2, "%s", "ACTIVE");
    bios_proto_set_severity (alert1, "%s", "low");
    bios_proto_set_severity (alert2, "%s", "low");
    bios_proto_set_description (alert1, "%s", "some description");
    bios_proto_set_description (alert2, "%s", "some description");
    bios_proto_set_time (alert1, 10);
    bios_proto_set_time (alert2, 10);
    bios_proto_set_action (alert1, "%s", "SMS");
    bios_proto_set_action (alert2, "%s", "SMS");

    assert (alert_comparator (alert1, alert2) == 1);

    bios_proto_destroy (&alert1);   
    bios_proto_destroy (&alert2);   
    }

    {    
    bios_proto_t *alert1 = bios_proto_new (BIOS_PROTO_ALERT);
    assert (alert1);
    bios_proto_t *alert2 = bios_proto_new (BIOS_PROTO_ALERT);
    assert (alert2);
     
    bios_proto_set_rule (alert1, "%s", "temperature.average@DC-Roztoky");
    bios_proto_set_rule (alert2, "%s", "temperature.average@DC-Roztoky");
    bios_proto_set_element_src (alert1, "%s", "ups-9");
    bios_proto_set_element_src (alert2, "%s", "epdu");
    bios_proto_set_state (alert1, "%s", "ACTIVE");
    bios_proto_set_state (alert2, "%s", "ACTIVE");
    bios_proto_set_severity (alert1, "%s", "low");
    bios_proto_set_severity (alert2, "%s", "low");
    bios_proto_set_description (alert1, "%s", "some description");
    bios_proto_set_description (alert2, "%s", "some description");
    bios_proto_set_time (alert1, 10);
    bios_proto_set_time (alert2, 10);
    bios_proto_set_action (alert1, "%s", "SMS");
    bios_proto_set_action (alert2, "%s", "SMS");

    assert (alert_comparator (alert1, alert2) == 1);

    bios_proto_destroy (&alert1);   
    bios_proto_destroy (&alert2);   
    }

    {    
    bios_proto_t *alert1 = bios_proto_new (BIOS_PROTO_ALERT);
    assert (alert1);
    bios_proto_t *alert2 = bios_proto_new (BIOS_PROTO_ALERT);
    assert (alert2);
     
    bios_proto_set_rule (alert1, "%s", "temperature.average@DC-Roztoky");
    bios_proto_set_rule (alert2, "%s", "temperature.average@DC-Roztoky");
    bios_proto_set_element_src (alert1, "%s", "epdu");
    bios_proto_set_element_src (alert2, "%s", "epdu");
    bios_proto_set_state (alert1, "%s", "ACTIVE");
    bios_proto_set_state (alert2, "%s", "ACTIVE");
    bios_proto_set_severity (alert1, "%s", "hugh");
    bios_proto_set_severity (alert2, "%s", "low");
    bios_proto_set_description (alert1, "%s", "some description");
    bios_proto_set_description (alert2, "%s", "some description");
    bios_proto_set_time (alert1, 10);
    bios_proto_set_time (alert2, 10);
    bios_proto_set_action (alert1, "%s", "SMS");
    bios_proto_set_action (alert2, "%s", "SMS");

    assert (alert_comparator (alert1, alert2) == 1);

    bios_proto_destroy (&alert1);   
    bios_proto_destroy (&alert2);   
    }

    {    
    bios_proto_t *alert1 = bios_proto_new (BIOS_PROTO_ALERT);
    assert (alert1);
    bios_proto_t *alert2 = bios_proto_new (BIOS_PROTO_ALERT);
    assert (alert2);
     
    bios_proto_set_rule (alert1, "%s", "temperature.average@DC-Roztoky");
    bios_proto_set_rule (alert2, "%s", "temperature.average@DC-Roztoky");
    bios_proto_set_element_src (alert1, "%s", "epdu");
    bios_proto_set_element_src (alert2, "%s", "epdu");
    bios_proto_set_state (alert1, "%s", "ACTIVE");
    bios_proto_set_state (alert2, "%s", "ACK-WIP");
    bios_proto_set_severity (alert1, "%s", "low");
    bios_proto_set_severity (alert2, "%s", "low");
    bios_proto_set_description (alert1, "%s", "some description");
    bios_proto_set_description (alert2, "%s", "some description");
    bios_proto_set_time (alert1, 10);
    bios_proto_set_time (alert2, 10);
    bios_proto_set_action (alert1, "%s", "SMS");
    bios_proto_set_action (alert2, "%s", "SMS");

    assert (alert_comparator (alert1, alert2) == 1);

    bios_proto_destroy (&alert1);   
    bios_proto_destroy (&alert2);   
    }

    {    
    bios_proto_t *alert1 = bios_proto_new (BIOS_PROTO_ALERT);
    assert (alert1);
    bios_proto_t *alert2 = bios_proto_new (BIOS_PROTO_ALERT);
    assert (alert2);
     
    bios_proto_set_rule (alert1, "%s", "temperature.average@DC-Roztoky");
    bios_proto_set_rule (alert2, "%s", "temperature.average@DC-Roztoky");
    bios_proto_set_element_src (alert1, "%s", "epdu");
    bios_proto_set_element_src (alert2, "%s", "epdu");
    bios_proto_set_state (alert1, "%s", "ACK-WIP");
    bios_proto_set_state (alert2, "%s", "ACK-WIP");
    bios_proto_set_severity (alert1, "%s", "low");
    bios_proto_set_severity (alert2, "%s", "low");
    bios_proto_set_description (alert1, "%s", "shitty description");
    bios_proto_set_description (alert2, "%s", "some description");
    bios_proto_set_time (alert1, 10);
    bios_proto_set_time (alert2, 10);
    bios_proto_set_action (alert1, "%s", "SMS");
    bios_proto_set_action (alert2, "%s", "SMS");

    assert (alert_comparator (alert1, alert2) == 1);

    bios_proto_destroy (&alert1);   
    bios_proto_destroy (&alert2);   
    }

    {    
    bios_proto_t *alert1 = bios_proto_new (BIOS_PROTO_ALERT);
    assert (alert1);
    bios_proto_t *alert2 = bios_proto_new (BIOS_PROTO_ALERT);
    assert (alert2);
     
    bios_proto_set_rule (alert1, "%s", "temperature.average@DC-Roztoky");
    bios_proto_set_rule (alert2, "%s", "temperature.average@DC-Roztoky");
    bios_proto_set_element_src (alert1, "%s", "epdu");
    bios_proto_set_element_src (alert2, "%s", "epdu");
    bios_proto_set_state (alert1, "%s", "ACK-WIP");
    bios_proto_set_state (alert2, "%s", "ACK-WIP");
    bios_proto_set_severity (alert1, "%s", "low");
    bios_proto_set_severity (alert2, "%s", "low");
    bios_proto_set_description (alert1, "%s", "some description");
    bios_proto_set_description (alert2, "%s", "some description");
    bios_proto_set_time (alert1, 1);
    bios_proto_set_time (alert2, 10);
    bios_proto_set_action (alert1, "%s", "SMS");
    bios_proto_set_action (alert2, "%s", "SMS");

    assert (alert_comparator (alert1, alert2) == 1);

    bios_proto_destroy (&alert1);   
    bios_proto_destroy (&alert2);   
    }

    {    
    bios_proto_t *alert1 = bios_proto_new (BIOS_PROTO_ALERT);
    assert (alert1);
    bios_proto_t *alert2 = bios_proto_new (BIOS_PROTO_ALERT);
    assert (alert2);
     
    bios_proto_set_rule (alert1, "%s", "temperature.average@DC-Roztoky");
    bios_proto_set_rule (alert2, "%s", "temperature.average@DC-Roztoky");
    bios_proto_set_element_src (alert1, "%s", "epdu");
    bios_proto_set_element_src (alert2, "%s", "epdu");
    bios_proto_set_state (alert1, "%s", "ACK-WIP");
    bios_proto_set_state (alert2, "%s", "ACK-WIP");
    bios_proto_set_severity (alert1, "%s", "low");
    bios_proto_set_severity (alert2, "%s", "low");
    bios_proto_set_description (alert1, "%s", "some description");
    bios_proto_set_description (alert2, "%s", "some description");
    bios_proto_set_time (alert1, 10);
    bios_proto_set_time (alert2, 10);
    bios_proto_set_action (alert1, "%s", "EMAIL");
    bios_proto_set_action (alert2, "%s", "SMS");

    assert (alert_comparator (alert1, alert2) == 1);

    bios_proto_destroy (&alert1);   
    bios_proto_destroy (&alert2);   
    }

    // TODO: action can be mixed

    //  @end
    printf ("OK\n");
}
