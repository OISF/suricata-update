from setuptools import setup

import suricata.update

setup(
    name="suricata-update",
    version=suricata.update.version,
    description="Suricata Update Tool",
    author="Jason Ish",
    author_email="ish@unx.ca",
    packages=[
        "suricata",
        "suricata.update",
        "suricata.update.configs",
        "suricata.update.compat",
        "suricata.update.compat.argparse",
    ],
    url="https://github.com/OISF/suricata-update",
    license="GPLv2",
    classifiers=[
        'License :: OSI Approved :: GNU General Public License v2 (GPLv2)',
    ],
    scripts = [
        "bin/suricata-update",
    ],
)
