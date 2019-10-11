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

import os.path

try:
    from urllib2 import urlopen
except:
    from urllib.request import urlopen

import yaml

def embed_index():
    """Embed a copy of the index as a Python source file. We can't use a
    datafile yet as there is no easy way to do with distutils."""
    dist_filename = os.path.join(os.path.dirname(__file__), "index.py")
    url = "https://raw.githubusercontent.com/oisf/suricata-intel-index/master/index.yaml"
    response = urlopen(url)
    index = yaml.safe_load(response.read())

    # Delete the version info to prevent the issue of the version info being out of
    # date around a new release of Suricata where the index has not been updated
    # to the latest recommended version.  The user will be asked to update their
    # sources to run the version check.
    del(index["versions"])

    with open(dist_filename, "w") as fileobj:
        fileobj.write("index = %s" % (str(index)))
    
if __name__ == "__main__":
    embed_index()
