# Copyright (C) 2017 Open Information Security Foundation
# Copyright (c) 2013 Jason Ish
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

"""Provide mappings from ID's to descriptions.

Includes mapping classes for event ID messages and classification
information.
"""

from __future__ import print_function

import re

class SignatureMap(object):
    """SignatureMap maps signature IDs to a signature info dict.

    The signature map can be build up from classification.config,
    gen-msg.map, and new and old-style sid-msg.map files.

    The dict's in the map will have at a minimum the following
    fields:

    * gid *(int)*
    * sid *(int)*
    * msg *(string)*
    * refs *(list of strings)*

    Signatures loaded from a new style sid-msg.map file will also have
    *rev*, *classification* and *priority* fields.

    Example::

        >>> from idstools import maps
        >>> sigmap = maps.SignatureMap()
        >>> sigmap.load_generator_map(open("tests/gen-msg.map"))
        >>> sigmap.load_signature_map(open("tests/sid-msg-v2.map"))
        >>> print(sigmap.get(1, 2495))
        {'classification': 'misc-attack', 'rev': 8, 'priority': 0, 'gid': 1,
        'sid': 2495,
        'msg': 'GPL NETBIOS SMB DCEPRC ORPCThis request flood attempt',
        'ref': ['bugtraq,8811', 'cve,2003-0813', 'nessus,12206',
        'url,www.microsoft.com/technet/security/bulletin/MS04-011.mspx']}

    """

    def __init__(self):
        self.map = {}

    def size(self):
        return len(self.map)

    def get(self, generator_id, signature_id):
        """Get signature info by generator_id and signature_id.

        :param generator_id: The generator id of the signature to lookup.
        :param signature_id: The signature id of the signature to lookup.

        For convenience, if the generator_id is 3 and the signature is
        not found, a second lookup will be done using a generator_id
        of 1.

        """

        key = (generator_id, signature_id)
        sig = self.map.get(key)
        if sig is None and generator_id == 3:
            return self.get(1, signature_id)
        return sig

    def load_generator_map(self, fileobj):
        """Load the generator message map (gen-msg.map) from a
        file-like object.

        """
        for line in fileobj:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            gid, sid, msg = [part.strip() for part in line.split("||")]
            entry = {
                "gid": int(gid),
                "sid": int(sid),
                "msg": msg,
                "refs": [],
            }
            self.map[(entry["gid"], entry["sid"])] = entry

    def load_signature_map(self, fileobj, defaultgid=1):
        """Load signature message map (sid-msg.map) from a file-like
        object.

        """

        for line in fileobj:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = [p.strip() for p in line.split("||")]

            # If we have at least 6 parts, attempt to parse as a v2
            # signature map file.
            try:
                entry = {
                    "gid": int(parts[0]),
                    "sid": int(parts[1]),
                    "rev": int(parts[2]),
                    "classification": parts[3],
                    "priority": int(parts[4]),
                    "msg": parts[5],
                    "ref": parts[6:],
                }
            except:
                entry = {
                    "gid": defaultgid,
                    "sid": int(parts[0]),
                    "msg": parts[1],
                    "ref": parts[2:],
                }
            self.map[(entry["gid"], entry["sid"])] = entry

class ClassificationMap(object):
    """ClassificationMap maps classification IDs and names to a dict
    object describing a classification.

    :param fileobj: (Optional) A file like object to load
      classifications from on initialization.

    The classification dicts stored in the map have the following
    fields:

    * name *(string)*
    * description *(string)*
    * priority *(int)*

    Example::

        >>> from idstools import maps
        >>> classmap = maps.ClassificationMap()
        >>> classmap.load_from_file(open("tests/classification.config"))

        >>> classmap.get(3)
        {'priority': 2, 'name': 'bad-unknown', 'description': 'Potentially Bad Traffic'}
        >>> classmap.get_by_name("bad-unknown")
        {'priority': 2, 'name': 'bad-unknown', 'description': 'Potentially Bad Traffic'}

    """

    def __init__(self, fileobj=None):
        self.id_map = []
        self.name_map = {}

        if fileobj:
            self.load_from_file(fileobj)

    def size(self):
        return len(self.id_map)

    def add(self, classification):
        """Add a classification to the map."""
        self.id_map.append(classification)
        self.name_map[classification["name"]] = classification

    def get(self, class_id):
        """Get a classification by ID.

        :param class_id: The classification ID to get.

        :returns: A dict describing the classification or None.

        """
        if 0 < class_id <= len(self.id_map):
            return self.id_map[class_id - 1]
        else:
            return None

    def get_by_name(self, name):
        """Get a classification by name.

        :param name: The name of the classification

        :returns: A dict describing the classification or None.

        """
        if name in self.name_map:
            return self.name_map[name]
        else:
            return None

    def load_from_file(self, fileobj):
        """Load classifications from a Snort style
        classification.config file object.

        """
        pattern = "config classification: ([^,]+),([^,]+),([^,]+)"
        for line in fileobj:
            m = re.match(pattern, line.strip())
            if m:
                self.add({
                    "name": m.group(1),
                    "description": m.group(2),
                    "priority": int(m.group(3))})
