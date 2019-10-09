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
    # Do nothing if dev version is running
    if "dev" in suricata_version.full:
        logger.warning(
                "Development version of Suricata found: %s. Skipping version check.",
                suricata_version.full)
        return

    index_filename = sources.get_index_filename()
    if not os.path.exists(index_filename):
        logger.warning("No index exists, will use bundled index.")
        logger.warning("Please run suricata-update update-sources.")
    index = sources.Index(index_filename)
    # Get version info from index of the form
    # "suricata": {
    #     "recommended": 5.x.x,
    #     "4.x": "4.x.y",
    #     "5.a": "5.a.b",
    # }
    version = index.get_versions()
    # Save the short versions in index in a list for later use
    version_keys = [k for k in version["suricata"].keys() if k != "recommended"]
    recommended = engine.parse_version(version["suricata"]["recommended"])
    if not recommended:
        logger.error("Recommended version was not parsed properly")
        sys.exit(1)
    # If the short suricata version is in list version_keys, proceed to
    # figure out if the version is up to date or outdated
    if suricata_version.short in version_keys:
        # Get full version corresponding to the short version in index
        upgrade_version = version["suricata"][suricata_version.short]
        if suricata_version.full == upgrade_version:
            logger.info("Suricata version %s is up to date.",
                    suricata_version.full)
            return
        status = "outdated"
        version_msg = upgrade_version if upgrade_version == recommended.full \
                else "{} or {}".format(upgrade_version, recommended.full)
    # If short suricata version was not in index, it is EOL
    else:
        status = "EOL"
        version_msg = recommended.full
    logger.warning("Suricata version %s is %s. Please upgrade to %s.",
            suricata_version.full, status, version_msg)
