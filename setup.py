import sys
import os.path
import subprocess
import distutils
from distutils.core import setup
from distutils.core import sys

from suricata.update.version import version


version_major = sys.version_info[0]
version_minor = sys.version_info[1]

if version_major < 3 and version_minor < 7:
    print("Suricata-Update requires Python 2.7 or newer.")
    sys.exit(0)

def write_git_revision():
    if not os.path.exists(".git"):
        return
    try:
        revision = subprocess.check_output(
            ["git", "rev-parse", "--short", "HEAD"])
        with open("./suricata/update/revision.py", "w") as fileobj:
            fileobj.write("revision = '%s'" % (revision.decode().strip()))
    except Exception as err:
        print("Failed to get current git revision: %s" % (err))

write_git_revision()

args = {
    "name": "suricata-update",
    "version": version,
    "description": "Suricata Update Tool",
    "author": "Jason Ish",
    "author_email": "ish@unx.ca",
    "packages": [
        "suricata",
        "suricata.update",
        "suricata.update.commands",
        "suricata.update.configs",
        "suricata.update.compat",
        "suricata.update.compat.argparse",
        "suricata.update.data",
    ],
    "package_data": {"suricata.update.configs": ["*.conf", "*.yaml", "*.in"]},
    "url": "https://github.com/OISF/suricata-update",
    "license": "GPLv2",
    "classifiers": [
        'License :: OSI Approved :: GNU General Public License v2 (GPLv2)',
    ],
    "scripts": [
        "bin/suricata-update",
    ],
}

if any("pip" in arg for arg in sys.argv):
    args["install_requires"] = ["pyyaml", ]

setup(**args)
