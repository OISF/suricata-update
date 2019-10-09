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
    if "dev" in suricata_version.full:
        logger.warning("Development version of Suricata found: %s. "
                "Skipping version check.", suricata_version.full)
        return

    index_filename = sources.get_index_filename()
    if not os.path.exists(index_filename):
        logger.warning("No index exists, will use bundled index.")
        logger.warning("Please run suricata-update update-sources.")
    index = sources.Index(index_filename)
    version = index.get_versions()
    recommended = engine.parse_version(version["suricata"]["recommended"])
    if not recommended:
        logger.error("Recommended version was not parsed properly")
        sys.exit(1)
    # In case index is out of date
    if float(suricata_version.short) > float(recommended.short):
        return
    # Evaluate if the installed version is present in index
    upgrade_version = version["suricata"].get(suricata_version.short)
    if not upgrade_version:
        logger.warning("Suricata version %s has reached EOL. Please upgrade to %s.",
                suricata_version.full, recommended.full)
        return
    if suricata_version.full == upgrade_version:
        logger.info("Suricata version %s is up to date", suricata_version.full)
    elif upgrade_version == recommended.full:
        logger.warning(
            "Suricata version %s is outdated. Please upgrade to %s.",
            suricata_version.full, recommended.full)
    else:
        logger.warning(
            "Suricata version %s is outdated. Please upgrade to %s or %s.",
            suricata_version.full, upgrade_version, recommended.full)

