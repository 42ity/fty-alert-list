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

#ifndef ALERTS_UTILS_H_INCLUDED
#define ALERTS_UTILS_H_INCLUDED

#ifdef __cplusplus
extern "C" {
#endif

// czmq_comparator of two alert's identifiers; alert is identified by pair (name, element)
// 0 - same, 1 - different
ALERTS_LIST_EXPORT int
    alert_id_comparator (bios_proto_t *alert1, bios_proto_t *alert2);

// czmq_comparator of two alerts
// 0 - same, 1 - different
ALERTS_LIST_EXPORT int
    alert_comparator (bios_proto_t *alert1, bios_proto_t *alert2);

// does 'state' represent valid alert state?
// 1 - valid alert state, 0 - NOT valid alert state
ALERTS_LIST_EXPORT int
    is_alertstate (const char *state);

// null-safe streq; returns true for two NULLs as well
// 1 - equal, 0 - NOT equal
ALERTS_LIST_EXPORT int
    str_eq (const char *s1, const char *s2);

//  Self test of this class
ALERTS_LIST_EXPORT void
    alerts_utils_test (bool verbose);

//  @end

#ifdef __cplusplus
}
#endif

#endif
