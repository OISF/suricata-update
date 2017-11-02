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

try:
    # Python 3.3...
    from urllib.request import urlopen
    from urllib.error import HTTPError
except ImportError:
    # Python 2.6, 2.7.
    from urllib2 import urlopen
    from urllib2 import HTTPError

# Number of bytes to read at a time in a GET request.
GET_BLOCK_SIZE = 8192

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

    remote = urlopen(url)
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
