# Copyright (C) 2019 Open Information Security Foundation
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
import logging
from suricata.update import sources, engine

logger = logging.getLogger()


def register(parser):
    parser.set_defaults(func=check_version)


def check_version(suricata_version):
    index_filename = sources.get_index_filename()
    if not os.path.exists(index_filename):
        logger.warning("No index exists, will use bundled index.")
        logger.warning("Please run suricata-update update-sources.")
    index = sources.Index(index_filename)
    version = index.get_versions()
    recommended = engine.parse_version(version['suricata']['recommended'])
    if suricata_version.full in recommended.full:
        logger.info("Suricata version %s is up to date", suricata_version.full)
    elif suricata_version.short > recommended.short:
        return None
    elif "dev" in suricata_version.full:
        if (suricata_version.short not in recommended.short or
                suricata_version.short not in version['suricata']) and \
                float(suricata_version.short) < float(recommended.short):
            logger.warning(
                "Suricata version %s has reached EOL. Please upgrade to %s.",
                suricata_version.full, recommended.full)
        elif float(suricata_version.short) >= float(recommended.short):
            logger.info(
                "Suricata version %s is up to date", suricata_version.full)
    elif suricata_version.short in version['suricata'] and \
            suricata_version.full not in recommended.full:
        logger.warning(
            "Suricata version %s is outdated. Please upgrade to %s.",
            suricata_version.full, recommended.full)
    else:
        logger.warning(
            "Suricata version %s has reached EOL. Please upgrade to %s.",
            suricata_version.full, recommended.full)
