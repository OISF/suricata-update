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
import re

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
from suricata.update import osinfo

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
    has_custom_user_agent = config.has("user-agent")
    if has_custom_user_agent:
        user_agent = config.get("user-agent")
        if user_agent is None or len(user_agent.strip()) == 0:
            logger.debug("Suppressing HTTP User-Agent header")
            return None
        return user_agent

    params = []
    try:
        params.append("OS: {}".format(platform.system()))
    except Exception as err:
        logger.error("Failed to set user-agent OS: {}".format(str(err)))
    try:
        params.append("CPU: {}".format(osinfo.arch()))
    except Exception as err:
        logger.error("Failed to set user-agent architecture: {}".format(str(err)))
    try:
        params.append("Python: {}".format(platform.python_version()))
    except Exception as err:
        logger.error("Failed to set user-agent python version: {}".format(str(err)))
    try:
        params.append("Dist: {}".format(osinfo.dist()))
    except Exception as err:
        logger.error("Failed to set user-agent distribution: {}".format(str(err)))

    params.append("Suricata: %s" % (user_agent_suricata_verison))

    return "Suricata-Update/%s (%s)" % (
        version, "; ".join(params))


def is_header_clean(header):
    if len(header) != 2:
        return False
    name, val = header[0].strip(), header[1].strip()
    if re.match( r"^[\w-]+$", name) and re.match(r"^[\w-]+$", val):
        return True
    return False


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

    if user_agent:
        logger.debug("Setting HTTP User-Agent to %s", user_agent)
        http_headers = [("User-Agent", user_agent)]
    else:
        http_headers = [(header, value) for header,
                        value in opener.addheaders if header.lower() != "user-agent"]
    if isinstance(url, tuple):
        header = url[1].split(":") if url[1] is not None else None
        if header and is_header_clean(header=header):
            name, val = header[0].strip(), header[1].strip()
            logger.debug("Setting HTTP header %s to %s", name, val)
            http_headers.append((name, val))
        elif header:
            logger.error("Header not set as it does not meet the criteria")
        url = url[0]
    opener.addheaders = http_headers

    try:
        remote = opener.open(url, timeout=30)
    except ValueError as ve:
        logger.error(ve)
    else:
        info = remote.info()
        content_length = info.get("content-length")
        content_length = int(content_length) if content_length else 0
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
