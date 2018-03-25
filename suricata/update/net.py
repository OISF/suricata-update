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

""" Module for network related operations. """

import platform
import logging
import ssl

try:
    # Python 3.3...
    from urllib.request import urlopen, build_opener
    from urllib.error import HTTPError
    from urllib.request import HTTPSHandler
except ImportError:
    # Python 2.6, 2.7.
    from urllib2 import urlopen, build_opener
    from urllib2 import HTTPError
    from urllib2 import HTTPSHandler

from suricata.update.version import version
from suricata.update import config

logger = logging.getLogger()

# Number of bytes to read at a time in a GET request.
GET_BLOCK_SIZE = 8192

user_agent_suricata_verison = "Unknown"
custom_user_agent = None

def set_custom_user_agent(ua):
    global custom_user_agent
    custom_user_agent = ua

def set_user_agent_suricata_version(version):
    global user_agent_suricata_verison
    user_agent_suricata_verison = version

def build_user_agent():
    params = []

    if custom_user_agent is not None:
        return custom_user_agent

    uname_system = platform.uname()[0]

    params.append("OS: %s" % (uname_system))
    params.append("CPU: %s" % (platform.machine()))
    params.append("Python: %s" % (platform.python_version()))

    if uname_system == "Linux":
        distribution = platform.linux_distribution()
        params.append("Dist: %s/%s" % (
            str(distribution[0]), str(distribution[1])))

    params.append("Suricata: %s" % (user_agent_suricata_verison))

    return "Suricata-Update/%s (%s)" % (
        version, "; ".join(params))

def get(url, fileobj, progress_hook=None):
    """ Perform a GET request against a URL writing the contents into
    the provideded file like object.

    :param url: The URL to fetch
    :param fileobj: The fileobj to write the content to
    :param progress_hook: The function to call with progress updates

    :returns: Returns a tuple containing the number of bytes read and
      the result of the info() function from urllib2.urlopen().

    :raises: Exceptions from urllib2.urlopen() and writing to the
      provided fileobj may occur.
    """

    user_agent = build_user_agent()
    logger.debug("Setting HTTP user-agent to %s", user_agent)

    try:
        # Wrap in a try as Python versions prior to 2.7.9 don't have
        # create_default_context, but some distros have backported it.
        ssl_context = ssl.create_default_context()
        if config.get("no-check-certificate"):
            logger.debug("Disabling SSL/TLS certificate verification.")
            ssl_context.check_hostname = False
            ssl_context.verify_mode = ssl.CERT_NONE
        opener = build_opener(HTTPSHandler(context=ssl_context))
    except:
        opener = build_opener()

    opener.addheaders = [
        ("User-Agent", build_user_agent()),
    ]

    remote = opener.open(url)
    info = remote.info()
    try:
        content_length = int(info["content-length"])
    except:
        content_length = 0
    bytes_read = 0
    while True:
        buf = remote.read(GET_BLOCK_SIZE)
        if not buf:
            # EOF
            break
        bytes_read += len(buf)
        fileobj.write(buf)
        if progress_hook:
            progress_hook(content_length, bytes_read)
    remote.close()
    fileobj.flush()
    return bytes_read, info

if __name__ == "__main__":

    import sys

    try:
        get(sys.argv[1], sys.stdout)
    except Exception as err:
        print("ERROR: %s" % (err))
