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
        str_eq (fty_proto_element_src (alert1), fty_proto_element_src (alert2))) {
        return 0;
    }
    else {
        return 1;
    }
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
    if (!str_eq (fty_proto_element_src (alert1), fty_proto_element_src (alert2)))
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
    if (!str_eq (fty_proto_action (alert1), fty_proto_action (alert2)))
        return 1;

    return 0;
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
    fty_proto_t *alert1 = fty_proto_new (FTY_PROTO_ALERT);
    assert (alert1);
    fty_proto_t *alert2 = fty_proto_new (FTY_PROTO_ALERT);
    assert (alert2);
     
    fty_proto_set_rule (alert1, "%s", "temperature.average@DC-Roztoky");
    fty_proto_set_rule (alert2, "%s", "temperature.average@DC-Roztoky");
    fty_proto_set_element_src (alert1, "%s", "ups-9");
    fty_proto_set_element_src (alert2, "%s", "ups-9");
    fty_proto_set_state (alert1, "%s", "ACTIVE");
    fty_proto_set_state (alert2, "%s", "ACTIVE");
    fty_proto_set_description (alert1, "%s", "some description");
    fty_proto_set_description (alert2, "%s", "some description");
    fty_proto_set_severity (alert1, "%s", "low");
    fty_proto_set_severity (alert2, "%s", "low");
    fty_proto_set_time (alert1, 10);
    fty_proto_set_time (alert2, 10);
    fty_proto_set_action (alert1, "EMAIL");
    fty_proto_set_action (alert2, "EMAIL");

    assert (alert_id_comparator (alert1, alert2) == 0);

    fty_proto_destroy (&alert1);   
    fty_proto_destroy (&alert2);
    }

    // test case 1b:
    //  alerts have the same identifier,
    //  different meta-data which represents real world use case of one alert
    //  at two different times
    {
    fty_proto_t *alert1 = fty_proto_new (FTY_PROTO_ALERT);
    assert (alert1);
    fty_proto_t *alert2 = fty_proto_new (FTY_PROTO_ALERT);
    assert (alert2);
     
    fty_proto_set_rule (alert1, "%s", "temperature.average@DC-Roztoky");
    fty_proto_set_rule (alert2, "%s", "temperature.average@DC-Roztoky");
    fty_proto_set_element_src (alert1, "%s", "ups-9");
    fty_proto_set_element_src (alert2, "%s", "ups-9");
    fty_proto_set_state (alert1, "%s", "ACTIVE");
    fty_proto_set_state (alert2, "%s", "ACK-IGNORE");
    fty_proto_set_description (alert1, "%s", "some description");
    fty_proto_set_description (alert2, "%s", "some description");
    fty_proto_set_severity (alert1, "%s", "low");
    fty_proto_set_severity (alert2, "%s", "high");
    fty_proto_set_time (alert1, 10);
    fty_proto_set_time (alert2, 10);
    fty_proto_set_action (alert1, "EMAIL");
    fty_proto_set_action (alert2, "SMS");

    assert (alert_id_comparator (alert1, alert2) == 0);

    fty_proto_destroy (&alert1);   
    fty_proto_destroy (&alert2);
    }

    // test case 1c:
    //  alerts have the same identifier,
    //  different as well as missing meta-data 
    {    
    fty_proto_t *alert1 = fty_proto_new (FTY_PROTO_ALERT);
    assert (alert1);
    fty_proto_t *alert2 = fty_proto_new (FTY_PROTO_ALERT);
    assert (alert2);
     
    fty_proto_set_rule (alert1, "%s", "temperature.average@DC-Roztoky");
    fty_proto_set_rule (alert2, "%s", "temperature.average@DC-Roztoky");
    fty_proto_set_element_src (alert1, "%s", "ups-9");
    fty_proto_set_element_src (alert2, "%s", "ups-9");
    fty_proto_set_state (alert1, "%s", "ACK-WIP");
    fty_proto_set_state (alert2, "%s", "ACTIVE");
    // description for alert1 is missing (NULL)
    fty_proto_set_description (alert2, "%s", "some description");
    fty_proto_set_severity (alert1, "%s", "high");
    fty_proto_set_severity (alert2, "%s", "low");
    fty_proto_set_time (alert1, 10);
    fty_proto_set_time (alert2, 20);
    fty_proto_set_action (alert1, "EMAIL");
    // description for alert 2 is missing (NULL);

    assert (alert_id_comparator (alert1, alert2) == 0);

    fty_proto_destroy (&alert1);   
    fty_proto_destroy (&alert2);   
    }
    
    // test case 1d:
    //  alerts have the same identifier - rule name has different case
    //  different as well as missing meta-data 
    {    
    fty_proto_t *alert1 = fty_proto_new (FTY_PROTO_ALERT);
    assert (alert1);
    fty_proto_t *alert2 = fty_proto_new (FTY_PROTO_ALERT);
    assert (alert2);
     
    fty_proto_set_rule (alert1, "%s", "temperature.average@DC-Roztoky");
    fty_proto_set_rule (alert2, "%s", "Temperature.Average@dC-roztoky");
    fty_proto_set_element_src (alert1, "%s", "ups-9");
    fty_proto_set_element_src (alert2, "%s", "ups-9");
    fty_proto_set_state (alert1, "%s", "ACK-WIP");
    fty_proto_set_state (alert2, "%s", "ACTIVE");
    // description for alert1 is missing (NULL)
    fty_proto_set_description (alert2, "%s", "some description");
    fty_proto_set_severity (alert1, "%s", "high");
    fty_proto_set_severity (alert2, "%s", "low");
    fty_proto_set_time (alert1, 10);
    fty_proto_set_time (alert2, 20);
    fty_proto_set_action (alert1, "EMAIL");
    // description for alert 2 is missing (NULL);

    assert (alert_id_comparator (alert1, alert2) == 0);

    fty_proto_destroy (&alert1);   
    fty_proto_destroy (&alert2);   
    }   

    // test case 2a:
    // alerts don't have the same identifier - different rule

    {    
    fty_proto_t *alert1 = fty_proto_new (FTY_PROTO_ALERT);
    assert (alert1);
    fty_proto_t *alert2 = fty_proto_new (FTY_PROTO_ALERT);
    assert (alert2);
     
    fty_proto_set_rule (alert1, "%s", "temperature.average@DC-Lab");
    fty_proto_set_rule (alert2, "%s", "temperature.average@DC-Roztoky");
    fty_proto_set_element_src (alert1, "%s", "ups-9");
    fty_proto_set_element_src (alert2, "%s", "ups-9");
    fty_proto_set_state (alert1, "%s", "ACK-WIP");
    fty_proto_set_state (alert2, "%s", "ACTIVE");
    fty_proto_set_severity (alert1, "%s", "high");
    fty_proto_set_severity (alert2, "%s", "low");
    fty_proto_set_time (alert1, 10);
    fty_proto_set_time (alert2, 20);

    assert (alert_id_comparator (alert1, alert2) == 1);

    fty_proto_destroy (&alert1);   
    fty_proto_destroy (&alert2);   
    }

    // test case 2b:
    // alerts don't have the same identifier - different element_src
    
    {    
    fty_proto_t *alert1 = fty_proto_new (FTY_PROTO_ALERT);
    assert (alert1);
    fty_proto_t *alert2 = fty_proto_new (FTY_PROTO_ALERT);
    assert (alert2);
     
    fty_proto_set_rule (alert1, "%s", "temperature.average@DC-Roztoky");
    fty_proto_set_rule (alert2, "%s", "temperature.average@DC-Roztoky");
    fty_proto_set_element_src (alert1, "%s", "epdu");
    fty_proto_set_element_src (alert2, "%s", "ups-9");
    fty_proto_set_state (alert1, "%s", "ACK-WIP");
    fty_proto_set_state (alert2, "%s", "ACTIVE");
    fty_proto_set_severity (alert1, "%s", "high");
    fty_proto_set_severity (alert2, "%s", "low");
    fty_proto_set_time (alert1, 10);
    fty_proto_set_time (alert2, 20);

    assert (alert_id_comparator (alert1, alert2) == 1);

    fty_proto_destroy (&alert1);   
    fty_proto_destroy (&alert2);   
    }

    // test case 2c:
    // alerts don't have the same identifier - different case of element_src
    
    {    
    fty_proto_t *alert1 = fty_proto_new (FTY_PROTO_ALERT);
    assert (alert1);
    fty_proto_t *alert2 = fty_proto_new (FTY_PROTO_ALERT);
    assert (alert2);
     
    fty_proto_set_rule (alert1, "%s", "temperature.average@DC-Roztoky");
    fty_proto_set_rule (alert2, "%s", "temperature.average@DC-Roztoky");
    fty_proto_set_element_src (alert1, "%s", "Ups-9");
    fty_proto_set_element_src (alert2, "%s", "ups-9");
    fty_proto_set_state (alert1, "%s", "ACK-WIP");
    fty_proto_set_state (alert2, "%s", "ACTIVE");
    fty_proto_set_severity (alert1, "%s", "high");
    fty_proto_set_severity (alert2, "%s", "low");
    fty_proto_set_time (alert1, 10);
    fty_proto_set_time (alert2, 20);

    assert (alert_id_comparator (alert1, alert2) == 1);

    fty_proto_destroy (&alert1);   
    fty_proto_destroy (&alert2);   
    }


    // test case 3:
    // alerts don't have the same identifier -different element_src, rule
    {    
    fty_proto_t *alert1 = fty_proto_new (FTY_PROTO_ALERT);
    assert (alert1);
    fty_proto_t *alert2 = fty_proto_new (FTY_PROTO_ALERT);
    assert (alert2);
     
    fty_proto_set_rule (alert1, "%s", "temperature.average@DC-Roztoky");
    fty_proto_set_rule (alert2, "%s", "temperature.humidity@DC-Roztoky");
    fty_proto_set_element_src (alert1, "%s", "epdu");
    fty_proto_set_element_src (alert2, "%s", "ups-9");
    fty_proto_set_state (alert1, "%s", "ACK-WIP");
    fty_proto_set_state (alert2, "%s", "ACTIVE");
    fty_proto_set_severity (alert1, "%s", "high");
    fty_proto_set_severity (alert2, "%s", "low");
    fty_proto_set_time (alert1, 10);
    fty_proto_set_time (alert2, 20);

    assert (alert_id_comparator (alert1, alert2) == 1);

    fty_proto_destroy (&alert1);   
    fty_proto_destroy (&alert2);   
    }
    

    //  *********************************
    //  *****   alert_comparator    *****
    //  *********************************

    // test case 1a:
    //  alerts are completelly the same
    {    
    fty_proto_t *alert1 = fty_proto_new (FTY_PROTO_ALERT);
    assert (alert1);
    fty_proto_t *alert2 = fty_proto_new (FTY_PROTO_ALERT);
    assert (alert2);
     
    fty_proto_set_rule (alert1, "%s", "temperature.average@DC-Roztoky");
    fty_proto_set_rule (alert2, "%s", "temperature.average@DC-Roztoky");
    fty_proto_set_element_src (alert1, "%s", "ups-9");
    fty_proto_set_element_src (alert2, "%s", "ups-9");
    fty_proto_set_state (alert1, "%s", "ACTIVE");
    fty_proto_set_state (alert2, "%s", "ACTIVE");
    fty_proto_set_severity (alert1, "%s", "low");
    fty_proto_set_severity (alert2, "%s", "low");
    fty_proto_set_description (alert1, "%s", "some description");
    fty_proto_set_description (alert2, "%s", "some description");
    fty_proto_set_time (alert1, 10);
    fty_proto_set_time (alert2, 10);
    fty_proto_set_action (alert1, "%s", "SMS");
    fty_proto_set_action (alert2, "%s", "SMS");

    assert (alert_comparator (alert1, alert2) == 0);

    fty_proto_destroy (&alert1);   
    fty_proto_destroy (&alert2);   
    }

    // test case 1b:
    //  alerts are same - rule different case
    {    
    fty_proto_t *alert1 = fty_proto_new (FTY_PROTO_ALERT);
    assert (alert1);
    fty_proto_t *alert2 = fty_proto_new (FTY_PROTO_ALERT);
    assert (alert2);
     
    fty_proto_set_rule (alert1, "%s", "temperature.average@DC-Roztoky");
    fty_proto_set_rule (alert2, "%s", "temperature.average@dC-Roztoky");
    fty_proto_set_element_src (alert1, "%s", "ups-9");
    fty_proto_set_element_src (alert2, "%s", "ups-9");
    fty_proto_set_state (alert1, "%s", "ACTIVE");
    fty_proto_set_state (alert2, "%s", "ACTIVE");
    fty_proto_set_severity (alert1, "%s", "low");
    fty_proto_set_severity (alert2, "%s", "low");
    fty_proto_set_description (alert1, "%s", "some description");
    fty_proto_set_description (alert2, "%s", "some description");
    fty_proto_set_time (alert1, 10);
    fty_proto_set_time (alert2, 10);
    fty_proto_set_action (alert1, "%s", "SMS");
    fty_proto_set_action (alert2, "%s", "SMS");

    assert (alert_comparator (alert1, alert2) == 0);

    fty_proto_destroy (&alert1);   
    fty_proto_destroy (&alert2);   
    }

    // test case 2:
    //  other fields are case sensitive
    
    //  severity is case sensitive
    {    
    fty_proto_t *alert1 = fty_proto_new (FTY_PROTO_ALERT);
    assert (alert1);
    fty_proto_t *alert2 = fty_proto_new (FTY_PROTO_ALERT);
    assert (alert2);
     
    fty_proto_set_rule (alert1, "%s", "temperature.average@DC-Roztoky");
    fty_proto_set_rule (alert2, "%s", "temperature.average@DC-Roztoky");
    fty_proto_set_element_src (alert1, "%s", "ups-9");
    fty_proto_set_element_src (alert2, "%s", "ups-9");
    fty_proto_set_state (alert1, "%s", "ACTIVE");
    fty_proto_set_state (alert2, "%s", "ACTIVE");
    fty_proto_set_severity (alert1, "%s", "low");
    fty_proto_set_severity (alert2, "%s", "lOw");
    fty_proto_set_description (alert1, "%s", "some description");
    fty_proto_set_description (alert2, "%s", "some description");
    fty_proto_set_time (alert1, 10);
    fty_proto_set_time (alert2, 10);
    fty_proto_set_action (alert1, "%s", "SMS");
    fty_proto_set_action (alert2, "%s", "SMS");

    assert (alert_comparator (alert1, alert2) == 1);

    fty_proto_destroy (&alert1);   
    fty_proto_destroy (&alert2);   
    }

    //  state is case sensitive
    {    
    fty_proto_t *alert1 = fty_proto_new (FTY_PROTO_ALERT);
    assert (alert1);
    fty_proto_t *alert2 = fty_proto_new (FTY_PROTO_ALERT);
    assert (alert2);
     
    fty_proto_set_rule (alert1, "%s", "temperature.average@DC-Roztoky");
    fty_proto_set_rule (alert2, "%s", "temperature.average@DC-Roztoky");
    fty_proto_set_element_src (alert1, "%s", "ups-9");
    fty_proto_set_element_src (alert2, "%s", "ups-9");
    fty_proto_set_state (alert1, "%s", "aCTIVE");
    fty_proto_set_state (alert2, "%s", "ACTIVE");
    fty_proto_set_severity (alert1, "%s", "low");
    fty_proto_set_severity (alert2, "%s", "low");
    fty_proto_set_description (alert1, "%s", "some description");
    fty_proto_set_description (alert2, "%s", "some description");
    fty_proto_set_time (alert1, 10);
    fty_proto_set_time (alert2, 10);
    fty_proto_set_action (alert1, "%s", "SMS");
    fty_proto_set_action (alert2, "%s", "SMS");

    assert (alert_comparator (alert1, alert2) == 1);

    fty_proto_destroy (&alert1);   
    fty_proto_destroy (&alert2);   
    }

    //  element_src is case sensitive
    {    
    fty_proto_t *alert1 = fty_proto_new (FTY_PROTO_ALERT);
    assert (alert1);
    fty_proto_t *alert2 = fty_proto_new (FTY_PROTO_ALERT);
    assert (alert2);
     
    fty_proto_set_rule (alert1, "%s", "temperature.average@DC-Roztoky");
    fty_proto_set_rule (alert2, "%s", "temperature.average@DC-Roztoky");
    fty_proto_set_element_src (alert1, "%s", "ups-9");
    fty_proto_set_element_src (alert2, "%s", "Ups-9");
    fty_proto_set_state (alert1, "%s", "ACTIVE");
    fty_proto_set_state (alert2, "%s", "ACTIVE");
    fty_proto_set_severity (alert1, "%s", "low");
    fty_proto_set_severity (alert2, "%s", "low");
    fty_proto_set_description (alert1, "%s", "some description");
    fty_proto_set_description (alert2, "%s", "some description");
    fty_proto_set_time (alert1, 10);
    fty_proto_set_time (alert2, 10);
    fty_proto_set_action (alert1, "%s", "SMS");
    fty_proto_set_action (alert2, "%s", "SMS");

    assert (alert_comparator (alert1, alert2) == 1);

    fty_proto_destroy (&alert1);   
    fty_proto_destroy (&alert2);   
    }

    //  description is case sensitive
    {    
    fty_proto_t *alert1 = fty_proto_new (FTY_PROTO_ALERT);
    assert (alert1);
    fty_proto_t *alert2 = fty_proto_new (FTY_PROTO_ALERT);
    assert (alert2);
     
    fty_proto_set_rule (alert1, "%s", "temperature.average@DC-Roztoky");
    fty_proto_set_rule (alert2, "%s", "temperature.average@DC-Roztoky");
    fty_proto_set_element_src (alert1, "%s", "ups-9");
    fty_proto_set_element_src (alert2, "%s", "ups-9");
    fty_proto_set_state (alert1, "%s", "ACTIVE");
    fty_proto_set_state (alert2, "%s", "ACTIVE");
    fty_proto_set_severity (alert1, "%s", "low");
    fty_proto_set_severity (alert2, "%s", "low");
    fty_proto_set_description (alert1, "%s", "some description");
    fty_proto_set_description (alert2, "%s", "some Description");
    fty_proto_set_time (alert1, 10);
    fty_proto_set_time (alert2, 10);
    fty_proto_set_action (alert1, "%s", "SMS");
    fty_proto_set_action (alert2, "%s", "SMS");

    assert (alert_comparator (alert1, alert2) == 1);

    fty_proto_destroy (&alert1);   
    fty_proto_destroy (&alert2);   
    }

    //  time is different
    {    
    fty_proto_t *alert1 = fty_proto_new (FTY_PROTO_ALERT);
    assert (alert1);
    fty_proto_t *alert2 = fty_proto_new (FTY_PROTO_ALERT);
    assert (alert2);
     
    fty_proto_set_rule (alert1, "%s", "temperature.average@DC-Roztoky");
    fty_proto_set_rule (alert2, "%s", "temperature.average@DC-Roztoky");
    fty_proto_set_element_src (alert1, "%s", "ups-9");
    fty_proto_set_element_src (alert2, "%s", "ups-9");
    fty_proto_set_state (alert1, "%s", "ACTIVE");
    fty_proto_set_state (alert2, "%s", "ACTIVE");
    fty_proto_set_severity (alert1, "%s", "low");
    fty_proto_set_severity (alert2, "%s", "low");
    fty_proto_set_description (alert1, "%s", "some description");
    fty_proto_set_description (alert2, "%s", "some description");
    fty_proto_set_time (alert1, 10);
    fty_proto_set_time (alert2, 35);
    fty_proto_set_action (alert1, "%s", "SMS");
    fty_proto_set_action (alert2, "%s", "SMS");

    assert (alert_comparator (alert1, alert2) == 1);

    fty_proto_destroy (&alert1);   
    fty_proto_destroy (&alert2);   
    }

    // test case 2g:
    //  action is case sensitive
    {    
    fty_proto_t *alert1 = fty_proto_new (FTY_PROTO_ALERT);
    assert (alert1);
    fty_proto_t *alert2 = fty_proto_new (FTY_PROTO_ALERT);
    assert (alert2);
     
    fty_proto_set_rule (alert1, "%s", "temperature.average@DC-Roztoky");
    fty_proto_set_rule (alert2, "%s", "temperature.average@DC-Roztoky");
    fty_proto_set_element_src (alert1, "%s", "ups-9");
    fty_proto_set_element_src (alert2, "%s", "ups-9");
    fty_proto_set_state (alert1, "%s", "ACTIVE");
    fty_proto_set_state (alert2, "%s", "ACTIVE");
    fty_proto_set_severity (alert1, "%s", "low");
    fty_proto_set_severity (alert2, "%s", "low");
    fty_proto_set_description (alert1, "%s", "some description");
    fty_proto_set_description (alert2, "%s", "some description");
    fty_proto_set_time (alert1, 10);
    fty_proto_set_time (alert2, 10);
    fty_proto_set_action (alert1, "%s", "SMS");
    fty_proto_set_action (alert2, "%s", "sms");

    assert (alert_comparator (alert1, alert2) == 1);

    fty_proto_destroy (&alert1);   
    fty_proto_destroy (&alert2);   
    }

    // test case 3a:
    //  fields missing in both messages are equal
    {    
    fty_proto_t *alert1 = fty_proto_new (FTY_PROTO_ALERT);
    assert (alert1);
    fty_proto_t *alert2 = fty_proto_new (FTY_PROTO_ALERT);
    assert (alert2);
     
    fty_proto_set_rule (alert1, "%s", "temperature.average@DC-Roztoky");
    fty_proto_set_rule (alert2, "%s", "temperature.average@DC-Roztoky");
    fty_proto_set_state (alert1, "%s", "ACTIVE");
    fty_proto_set_state (alert2, "%s", "ACTIVE");
    fty_proto_set_time (alert1, 10);
    fty_proto_set_time (alert2, 10);

    assert (alert_comparator (alert1, alert2) == 0);

    fty_proto_destroy (&alert1);   
    fty_proto_destroy (&alert2);   
    }
    
    // test case 3b:
    //  fields missing in either of messages is not equal
    {    
    fty_proto_t *alert1 = fty_proto_new (FTY_PROTO_ALERT);
    assert (alert1);
    fty_proto_t *alert2 = fty_proto_new (FTY_PROTO_ALERT);
    assert (alert2);
     
    fty_proto_set_rule (alert1, "%s", "temperature.average@DC-Roztoky");
    fty_proto_set_rule (alert2, "%s", "temperature.average@DC-Roztoky");
    fty_proto_set_element_src (alert1, "%s", "ups-9");
    fty_proto_set_element_src (alert2, "%s", "ups-9");
    fty_proto_set_state (alert1, "%s", "ACTIVE");
    fty_proto_set_state (alert2, "%s", "ACTIVE");
    fty_proto_set_severity (alert1, "%s", "low");
    fty_proto_set_severity (alert2, "%s", "low");
    fty_proto_set_description (alert2, "%s", "some description");
    fty_proto_set_time (alert1, 10);
    fty_proto_set_time (alert2, 10);
    fty_proto_set_action (alert1, "%s", "SMS");
    fty_proto_set_action (alert2, "%s", "SMS");

    assert (alert_comparator (alert1, alert2) == 1);

    fty_proto_destroy (&alert1);   
    fty_proto_destroy (&alert2);   
    }

    {    
    fty_proto_t *alert1 = fty_proto_new (FTY_PROTO_ALERT);
    assert (alert1);
    fty_proto_t *alert2 = fty_proto_new (FTY_PROTO_ALERT);
    assert (alert2);
     
    fty_proto_set_rule (alert1, "%s", "temperature.average@DC-Roztoky");
    fty_proto_set_element_src (alert1, "%s", "ups-9");
    fty_proto_set_element_src (alert2, "%s", "ups-9");
    fty_proto_set_state (alert1, "%s", "ACTIVE");
    fty_proto_set_state (alert2, "%s", "ACTIVE");
    fty_proto_set_severity (alert1, "%s", "low");
    fty_proto_set_severity (alert2, "%s", "low");
    fty_proto_set_description (alert1, "%s", "some description");
    fty_proto_set_description (alert2, "%s", "some description");
    fty_proto_set_time (alert1, 10);
    fty_proto_set_time (alert2, 10);
    fty_proto_set_action (alert1, "%s", "SMS");
    fty_proto_set_action (alert2, "%s", "SMS");

    assert (alert_comparator (alert1, alert2) == 1);

    fty_proto_destroy (&alert1);   
    fty_proto_destroy (&alert2);   
    }

    {    
    fty_proto_t *alert1 = fty_proto_new (FTY_PROTO_ALERT);
    assert (alert1);
    fty_proto_t *alert2 = fty_proto_new (FTY_PROTO_ALERT);
    assert (alert2);
     
    fty_proto_set_rule (alert1, "%s", "temperature.average@DC-Roztoky");
    fty_proto_set_rule (alert2, "%s", "temperature.average@DC-Roztoky");
    fty_proto_set_element_src (alert2, "%s", "ups-9");
    fty_proto_set_state (alert1, "%s", "ACTIVE");
    fty_proto_set_state (alert2, "%s", "ACTIVE");
    fty_proto_set_severity (alert1, "%s", "low");
    fty_proto_set_severity (alert2, "%s", "low");
    fty_proto_set_description (alert1, "%s", "some description");
    fty_proto_set_description (alert2, "%s", "some description");
    fty_proto_set_time (alert1, 10);
    fty_proto_set_time (alert2, 10);
    fty_proto_set_action (alert1, "%s", "SMS");
    fty_proto_set_action (alert2, "%s", "SMS");

    assert (alert_comparator (alert1, alert2) == 1);

    fty_proto_destroy (&alert1);   
    fty_proto_destroy (&alert2);   
    }

    // test case 4:
    //  different fields
    {    
    fty_proto_t *alert1 = fty_proto_new (FTY_PROTO_ALERT);
    assert (alert1);
    fty_proto_t *alert2 = fty_proto_new (FTY_PROTO_ALERT);
    assert (alert2);
     
    fty_proto_set_rule (alert1, "%s", "temperature.average@DC-Roztoky");
    fty_proto_set_rule (alert2, "%s", "temperature.humidity@DC-Roztoky");
    fty_proto_set_element_src (alert1, "%s", "ups-9");
    fty_proto_set_element_src (alert2, "%s", "ups-9");
    fty_proto_set_state (alert1, "%s", "ACTIVE");
    fty_proto_set_state (alert2, "%s", "ACTIVE");
    fty_proto_set_severity (alert1, "%s", "low");
    fty_proto_set_severity (alert2, "%s", "low");
    fty_proto_set_description (alert1, "%s", "some description");
    fty_proto_set_description (alert2, "%s", "some description");
    fty_proto_set_time (alert1, 10);
    fty_proto_set_time (alert2, 10);
    fty_proto_set_action (alert1, "%s", "SMS");
    fty_proto_set_action (alert2, "%s", "SMS");

    assert (alert_comparator (alert1, alert2) == 1);

    fty_proto_destroy (&alert1);   
    fty_proto_destroy (&alert2);   
    }

    {    
    fty_proto_t *alert1 = fty_proto_new (FTY_PROTO_ALERT);
    assert (alert1);
    fty_proto_t *alert2 = fty_proto_new (FTY_PROTO_ALERT);
    assert (alert2);
     
    fty_proto_set_rule (alert1, "%s", "temperature.average@DC-Roztoky");
    fty_proto_set_rule (alert2, "%s", "temperature.average@DC-Roztoky");
    fty_proto_set_element_src (alert1, "%s", "ups-9");
    fty_proto_set_element_src (alert2, "%s", "epdu");
    fty_proto_set_state (alert1, "%s", "ACTIVE");
    fty_proto_set_state (alert2, "%s", "ACTIVE");
    fty_proto_set_severity (alert1, "%s", "low");
    fty_proto_set_severity (alert2, "%s", "low");
    fty_proto_set_description (alert1, "%s", "some description");
    fty_proto_set_description (alert2, "%s", "some description");
    fty_proto_set_time (alert1, 10);
    fty_proto_set_time (alert2, 10);
    fty_proto_set_action (alert1, "%s", "SMS");
    fty_proto_set_action (alert2, "%s", "SMS");

    assert (alert_comparator (alert1, alert2) == 1);

    fty_proto_destroy (&alert1);   
    fty_proto_destroy (&alert2);   
    }

    {    
    fty_proto_t *alert1 = fty_proto_new (FTY_PROTO_ALERT);
    assert (alert1);
    fty_proto_t *alert2 = fty_proto_new (FTY_PROTO_ALERT);
    assert (alert2);
     
    fty_proto_set_rule (alert1, "%s", "temperature.average@DC-Roztoky");
    fty_proto_set_rule (alert2, "%s", "temperature.average@DC-Roztoky");
    fty_proto_set_element_src (alert1, "%s", "epdu");
    fty_proto_set_element_src (alert2, "%s", "epdu");
    fty_proto_set_state (alert1, "%s", "ACTIVE");
    fty_proto_set_state (alert2, "%s", "ACTIVE");
    fty_proto_set_severity (alert1, "%s", "hugh");
    fty_proto_set_severity (alert2, "%s", "low");
    fty_proto_set_description (alert1, "%s", "some description");
    fty_proto_set_description (alert2, "%s", "some description");
    fty_proto_set_time (alert1, 10);
    fty_proto_set_time (alert2, 10);
    fty_proto_set_action (alert1, "%s", "SMS");
    fty_proto_set_action (alert2, "%s", "SMS");

    assert (alert_comparator (alert1, alert2) == 1);

    fty_proto_destroy (&alert1);   
    fty_proto_destroy (&alert2);   
    }

    {    
    fty_proto_t *alert1 = fty_proto_new (FTY_PROTO_ALERT);
    assert (alert1);
    fty_proto_t *alert2 = fty_proto_new (FTY_PROTO_ALERT);
    assert (alert2);
     
    fty_proto_set_rule (alert1, "%s", "temperature.average@DC-Roztoky");
    fty_proto_set_rule (alert2, "%s", "temperature.average@DC-Roztoky");
    fty_proto_set_element_src (alert1, "%s", "epdu");
    fty_proto_set_element_src (alert2, "%s", "epdu");
    fty_proto_set_state (alert1, "%s", "ACTIVE");
    fty_proto_set_state (alert2, "%s", "ACK-WIP");
    fty_proto_set_severity (alert1, "%s", "low");
    fty_proto_set_severity (alert2, "%s", "low");
    fty_proto_set_description (alert1, "%s", "some description");
    fty_proto_set_description (alert2, "%s", "some description");
    fty_proto_set_time (alert1, 10);
    fty_proto_set_time (alert2, 10);
    fty_proto_set_action (alert1, "%s", "SMS");
    fty_proto_set_action (alert2, "%s", "SMS");

    assert (alert_comparator (alert1, alert2) == 1);

    fty_proto_destroy (&alert1);   
    fty_proto_destroy (&alert2);   
    }

    {    
    fty_proto_t *alert1 = fty_proto_new (FTY_PROTO_ALERT);
    assert (alert1);
    fty_proto_t *alert2 = fty_proto_new (FTY_PROTO_ALERT);
    assert (alert2);
     
    fty_proto_set_rule (alert1, "%s", "temperature.average@DC-Roztoky");
    fty_proto_set_rule (alert2, "%s", "temperature.average@DC-Roztoky");
    fty_proto_set_element_src (alert1, "%s", "epdu");
    fty_proto_set_element_src (alert2, "%s", "epdu");
    fty_proto_set_state (alert1, "%s", "ACK-WIP");
    fty_proto_set_state (alert2, "%s", "ACK-WIP");
    fty_proto_set_severity (alert1, "%s", "low");
    fty_proto_set_severity (alert2, "%s", "low");
    fty_proto_set_description (alert1, "%s", "shitty description");
    fty_proto_set_description (alert2, "%s", "some description");
    fty_proto_set_time (alert1, 10);
    fty_proto_set_time (alert2, 10);
    fty_proto_set_action (alert1, "%s", "SMS");
    fty_proto_set_action (alert2, "%s", "SMS");

    assert (alert_comparator (alert1, alert2) == 1);

    fty_proto_destroy (&alert1);   
    fty_proto_destroy (&alert2);   
    }

    {    
    fty_proto_t *alert1 = fty_proto_new (FTY_PROTO_ALERT);
    assert (alert1);
    fty_proto_t *alert2 = fty_proto_new (FTY_PROTO_ALERT);
    assert (alert2);
     
    fty_proto_set_rule (alert1, "%s", "temperature.average@DC-Roztoky");
    fty_proto_set_rule (alert2, "%s", "temperature.average@DC-Roztoky");
    fty_proto_set_element_src (alert1, "%s", "epdu");
    fty_proto_set_element_src (alert2, "%s", "epdu");
    fty_proto_set_state (alert1, "%s", "ACK-WIP");
    fty_proto_set_state (alert2, "%s", "ACK-WIP");
    fty_proto_set_severity (alert1, "%s", "low");
    fty_proto_set_severity (alert2, "%s", "low");
    fty_proto_set_description (alert1, "%s", "some description");
    fty_proto_set_description (alert2, "%s", "some description");
    fty_proto_set_time (alert1, 1);
    fty_proto_set_time (alert2, 10);
    fty_proto_set_action (alert1, "%s", "SMS");
    fty_proto_set_action (alert2, "%s", "SMS");

    assert (alert_comparator (alert1, alert2) == 1);

    fty_proto_destroy (&alert1);   
    fty_proto_destroy (&alert2);   
    }

    {    
    fty_proto_t *alert1 = fty_proto_new (FTY_PROTO_ALERT);
    assert (alert1);
    fty_proto_t *alert2 = fty_proto_new (FTY_PROTO_ALERT);
    assert (alert2);
     
    fty_proto_set_rule (alert1, "%s", "temperature.average@DC-Roztoky");
    fty_proto_set_rule (alert2, "%s", "temperature.average@DC-Roztoky");
    fty_proto_set_element_src (alert1, "%s", "epdu");
    fty_proto_set_element_src (alert2, "%s", "epdu");
    fty_proto_set_state (alert1, "%s", "ACK-WIP");
    fty_proto_set_state (alert2, "%s", "ACK-WIP");
    fty_proto_set_severity (alert1, "%s", "low");
    fty_proto_set_severity (alert2, "%s", "low");
    fty_proto_set_description (alert1, "%s", "some description");
    fty_proto_set_description (alert2, "%s", "some description");
    fty_proto_set_time (alert1, 10);
    fty_proto_set_time (alert2, 10);
    fty_proto_set_action (alert1, "%s", "EMAIL");
    fty_proto_set_action (alert2, "%s", "SMS");

    assert (alert_comparator (alert1, alert2) == 1);

    fty_proto_destroy (&alert1);   
    fty_proto_destroy (&alert2);   
    }

    // TODO: action can be mixed

    //  @end
    printf ("OK\n");
}
