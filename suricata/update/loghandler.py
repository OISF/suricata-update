# Copyright (C) 2017 Open Information Security Foundation
# Copyright (c) 2016 Jason Ish
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

import sys
import os
import logging
import time

# A list of secrets that will be replaced in the log output.
secrets = {}


def add_secret(secret, replacement):
    """Register a secret to be masked. The secret will be replaced with:
           <replacement>
    """
    secrets[str(secret)] = str(replacement)


class SuriColourLogHandler(logging.StreamHandler):
    """An alternative stream log handler that logs with Suricata inspired
    log colours."""

    GREEN = "\x1b[32m"
    BLUE = "\x1b[34m"
    REDB = "\x1b[1;31m"
    YELLOW = "\x1b[33m"
    RED = "\x1b[31m"
    YELLOWB = "\x1b[1;33m"
    ORANGE = "\x1b[38;5;208m"
    RESET = "\x1b[0m"

    def formatTime(self, record):
        lt = time.localtime(record.created)
        t = "%d/%d/%d -- %02d:%02d:%02d" % (lt.tm_mday,
                                            lt.tm_mon,
                                            lt.tm_year,
                                            lt.tm_hour,
                                            lt.tm_min,
                                            lt.tm_sec)
        return "%s" % (t)

    def emit(self, record):

        if record.levelname == "ERROR":
            level_prefix = self.REDB
            message_prefix = self.REDB
        elif record.levelname == "WARNING":
            level_prefix = self.ORANGE
            message_prefix = self.ORANGE
        else:
            level_prefix = self.YELLOW
            message_prefix = ""

        if os.isatty(self.stream.fileno()):
            self.stream.write("%s%s%s - <%s%s%s> -- %s%s%s\n" % (
                self.GREEN,
                self.formatTime(record),
                self.RESET,
                level_prefix,
                record.levelname.title(),
                self.RESET,
                message_prefix,
                self.mask_secrets(record.getMessage()),
                self.RESET))
        else:
            self.stream.write("%s - <%s> -- %s\n" % (
                self.formatTime(record),
                record.levelname.title(),
                self.mask_secrets(record.getMessage())))

    def mask_secrets(self, msg):
        for secret in secrets:
            msg = msg.replace(secret, "<%s>" % secrets[secret])
        return msg


class LessThanFilter(logging.Filter):
    def __init__(self, exclusive_maximum, name=""):
        super(LessThanFilter, self).__init__(name)
        self.max_level = exclusive_maximum

    def filter(self, record):
        return 1 if record.levelno < self.max_level else 0


def configure_logging():
    if os.fstat(sys.stdout.fileno()) == os.fstat(sys.stderr.fileno()):
        filter_stdout = True
    else:
        filter_stdout = False
    logger = logging.getLogger()
    logger.setLevel(logging.NOTSET)
    logging_handler_out = SuriColourLogHandler(sys.stdout)
    logging_handler_out.setLevel(logging.DEBUG)
    if filter_stdout:
        logging_handler_out.addFilter(LessThanFilter(logging.WARNING))
    logger.addHandler(logging_handler_out)
    logging_handler_err = SuriColourLogHandler(sys.stderr)
    logging_handler_err.setLevel(logging.WARNING)
    logger.addHandler(logging_handler_err)
