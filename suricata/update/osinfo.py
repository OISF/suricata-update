# Copyright (C) 2020 Open Information Security Foundation
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

import re
import os.path
import platform

def parse_os_release(filename="/etc/os-release"):
    os_release={}

    if not os.path.exists(filename):
        return os_release
    
    with open(filename) as fileobj:
        for line in fileobj:
            line = line.strip()
            m = re.match("^(\w+)=\"?(.*?)\"?$", line)
            if m:
                os_release[m.group(1)] = m.group(2)
    return os_release

def dist():
    os_release = parse_os_release()
    if "NAME" in os_release:
        version_fields = ["VERSION_ID", "BUILD_ID"]
        for vf in version_fields:
            if vf in os_release:
                return "{}/{}".format(os_release["NAME"], os_release[vf])
        return os_release["NAME"]

    # Arch may or may not have /etc/os-release, but its easy to
    # detect.
    if os.path.exists("/etc/arch-release"):
        return "Arch Linux"

    # Uname fallback.
    uname = platform.uname()
    return "{}/{}".format(uname[0], uname[2])

normalized_arch = {
    "amd64": "x86_64",
}

def arch():
    """Return the machine architecture. """
    machine = platform.machine()
    return normalized_arch.get(machine, machine)

if __name__ == "__main__":
    # Build a user agent string. Something like:
    # Suricata-Update/1.2.0dev0 (OS: Linux; \
    #    CPU: x86_64; \
    #    Python: 3.7.7; \
    #    Dist: Fedora/31; \
    #    Suricata: 4.0.0)
    parts = []
    parts.append("OS: {}".format(platform.system()))
    parts.append("CPU: {}".format(arch()))
    parts.append("Python: {}".format(platform.python_version()))
    parts.append("Dist: {}".format(dist()))

    print("Suricata-Update/1.2.0dev0 ({})".format("; ".join(parts)))
