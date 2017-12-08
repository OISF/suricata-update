#! /bin/sh

set -e
set -x

# Test the commands in a scenario a user might.
test_commands() {
    # Cleanup.
    rm -rf /var/lib/suricata

    suricata-update
    test -e /var/lib/suricata/rules/suricata.rules

    suricata-update update-sources
    test -e /var/lib/suricata/update/cache/index.yaml

    suricata-update enable-source oisf/trafficid
    test -e /var/lib/suricata/update/sources/et-open.yaml
    test -e /var/lib/suricata/update/sources/oisf-trafficid.yaml
    suricata-update

    suricata-update disable-source oisf/trafficid
    test ! -e /var/lib/suricata/update/sources/oisf-trafficid.yaml
    test -e /var/lib/suricata/update/sources/oisf-trafficid.yaml.disabled

    suricata-update remove-source oisf/trafficid
    test ! -e /var/lib/suricata/update/sources/oisf-trafficid.yaml.disabled
}

# Python 2 unit tests.
PYTHONPATH=. ${PYTEST2}

# Python 3 unit tests.
PYTHONPATH=. ${PYTEST3}

# Install with Python 2.
${PIP2} install .
test -e /usr/local/bin/suricata-update

test_commands

# Uninstall Python 2 version.
${PIP2} uninstall --yes suricata-update
test ! -e /usr/local/bin/suricata-update

# Install and run with Python 3.
${PIP3} install .
test -e /usr/local/bin/suricata-update
grep python3 -s /usr/local/bin/suricata-update

test_commands

${PIP3} uninstall --yes suricata-update
test ! -e /usr/local/bin/suricata-update
