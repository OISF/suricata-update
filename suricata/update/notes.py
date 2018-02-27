# Copyright (C) 2018 Open Information Security Foundation
#
# You can copy, redistribute or modify this Program under the terms of
# the GNU General Public License version 2 as published by the Free
# Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# version 2 along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
# 02110-1301, USA.

from __future__ import print_function

import textwrap

# Address group notes.
address_group_vars = set()

# Port group notes.
port_group_vars = set()

# Template for missing address-group variable.
missing_address_group_var_template = """ 
A rule has been disabled due to the unknown address-group variable
%(var)s being used. You may want to add this variable to your Suricata
configuration file.
"""

# Template for missing port-group variable.
missing_port_group_var_template = """ 
A rule has been disabled due to the unknown port-group variable
%(var)s being used. You may want to add this variable to your Suricata
configuration file.
"""

def render_note(note):
    lines = textwrap.wrap(note.strip().replace("\n", " "))
    print("* %s" % (lines[0]))
    for line in lines[1:]:
        print("  %s" % (line))

def dump_notes():
    notes = []

    for var in address_group_vars:
        notes.append(missing_address_group_var_template % {"var": var})

    for var in port_group_vars:
        notes.append(missing_port_group_var_template % {"var": var})

    if notes:
        print("\nNotes:\n")
        for note in notes:
            render_note(note)
            print("")
