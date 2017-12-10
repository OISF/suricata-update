.. option:: -h, --help

   Show help.

.. option:: -D <directory>, --data-dir <directory>

   Set an alternate data directory.

   Default: */var/lib/suricata*

.. option:: -c <filename>, --config <filename>

   Path to the suricata-update config file.

   Default: */etc/suricata/update.yaml*

.. option:: -q, --quiet

   Run quietly. Only warning and error messages will be displayed.

.. option:: -v, --verbose

   Provide more verbose output.

.. option:: --suricata-conf <path>

   Path to the suricata config file.

   Default: */etc/suricata/suricata.yaml*

.. option:: --suricata <path>

   The path to the Suricata program. If not provided
   ``suricata-update`` will attempt to find Suricata on your path.

   The Suricata program is used to determine the version of Suricata
   as well as providing information about the Suricata configuration.

.. option:: --suricata-version <version>

   Set the Suricata version to a specific version instead of checking
   the version of Suricata on the path.

.. option:: --user-agent <string>

   Set a custom user agent string for HTTP requests.
