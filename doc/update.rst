########################
suricata-update - Update
########################

Synopsis
========

``suricata-update`` [OPTIONS]

Description
===========

``suricata-update`` aims to be a simple to use rule download and
management tool for Suricata.

Options
=======

.. include:: ./common-options.rst

.. option:: -o, --output

   The directory to output the rules to.

   Default: */var/lib/suricata/rules*

.. option:: --force

   Force remote rule files to be downloaded if they otherwise wouldn't
   be due to just recently downloaded, or the remote checksum matching
   the cached copy.

.. option:: --merged=<filename>

   Write a single file containing all rules. This can be used in
   addition to ``--output`` or instead of ``--output``.

.. option:: --no-merge

   Do not merge the rules into a single rule file.

   *Warning: No attempt is made to resolve conflicts if 2 input rule files have the same name.*

.. option:: --yaml-fragment=<filename.yaml>

   Output a fragment of YAML containing the *rule-files* section will
   all downloaded rule files listed for inclusion in your
   *suricata.yaml*.

.. option:: --url=<url>

   A URL to download rules from. This option can be used multiple
   times.

.. option:: --local=<filename or directory>

   A path to a filename or directory of local rule files to include.

   If the path is a directory all files ending in *.rules* will be
   loaded.

   Wildcards are accepted but to avoid shell expansion the argument
   must be quoted, for example::

     --local '/etc/suricata/custom-*.rules'

   This option can be specified multiple times.

.. option:: --sid-msg-map=<filename>

   Output a v1 style sid-msg.map file.

.. option:: --sid-msg-map-2=<filename>

   Output a v2 style sid-msg.map file.

.. option:: --disable-conf=<disable.conf>

   Specify the configuration file for disable filters.

   See :ref:`example-disable-conf`

.. option:: --enable-conf=<enable.conf>

   Specify the configuration file for enable rules.

   See :ref:`example-enable-conf`

.. option:: --modify-conf=<modify.conf>

   Specify the configuration file for rule modification filters.

   See :ref:`example-modify-conf`

.. option:: --drop-conf=<drop.conf>

   Specify the configuration file for drop filters.

   See :ref:`example-drop-conf`

.. option:: --ignore=<pattern>

   Filenames to ignore. This is a pattern that will be matched against
   the basename of a rule files.

   This argument may be specified multiple times.

   Default: *\*deleted.rules*

   Example::

     --ignore dnp3-events.rules --ignore deleted.rules --ignore "modbus*"

   .. note::

     If specified the default value of *\*deleted.rules* will no longer
     be used, so add it as an extra ignore if needed.

.. option:: --no-ignore

   Disable the --ignore option. Most useful to disable the default
   ignore pattern without adding others.

.. option:: --etopen

   Download the ET/Open ruleset.

   This is the default action of no ``--url`` options are provided or
   no sources are configured.

   Use this option to enable the ET/Open ruleset in addition to any
   URLs provided on the command line or sources provided in the
   configuration.

.. option:: --dump-sample-configs

   Output sample configuration files for the ``--disable``,
   ``--enable``, ``--modify`` and ``--threshold-in`` commands.

.. option:: --threshold-in=<threshold.conf.in>

   Specify the threshold.conf input template.

.. option:: --threshold-out=<threshold.conf>

   Specify the name of the processed threshold.conf to output.

.. option:: -T <command>, --test-command <command>

   Specifies a custom test command to test the rules before reloading
   Suricata. This overrides the default command and can also be
   specified in the configuration file under ``test-command``.

.. option:: --no-test

   Disables the test command and proceed as if it had passed.

.. option:: --reload-command=<command>

   A command to run after the rules have been updated; will not run if
   no change to the output files was made.  For example::

     --reload-command='sudo kill -USR2 $(cat /var/run/suricata.pid)'

   will tell Suricata to reload its rules.

.. option:: --no-reload

   Disable Suricata rule reload.
	    
.. option:: -V, --version

   Display the version of **suricata-update**.

Rule Matching
=============

Matching rules for disabling, enabling, converting to drop or
modification can be done with the following:

- signature ID
- regular expression
- rule group
- filename

Signature ID Matching
---------------------

A signature ID can be matched by just its signature ID, for example::

    1034

The generator ID can also be used for compatibility with other tools::

    1:1034

Regular Expression Matching
---------------------------

Regular expression matching will match a regular expression over the
complete rule. Example::

    re:heartbleed
    re:MS(0[7-9]|10)-\d+

Group Matching
--------------

The group matcher matches against the group the rule was loaded
from. Basically this is the filename without the leading path or file
extension. Example::

  group:emerging-icmp.rules
  group:emerging-dos

Wild card matching similar to wildcards used in a Unix shell can also
be used::

  group:*deleted*

Filename Matching
-----------------

The filename matcher matches against the filename the rule was loaded
from taking into consideration the full path. Shell wildcard patterns
are allowed::

  filename:rules/*deleted*
  filename:*/emerging-dos.rules

Modifying Rules
---------------

Rule modification can be done with regular expression search and
replace. The basic format for a rule modification specifier is::

  <match> <from> <to>

where <match> is one of the rule matchers from above, <from> is the
text to be replaced and <to> is the replacement text.

Example converting all alert rules to drop::

  re:. ^alert drop

Example converting all drop rules with noalert back to alert::

  re:. "^drop(.*)noalert(.*)" "alert\\1noalert\\2"  

Example Configuration Files
===========================

.. _example_update_yaml:

Example Configuration File (/etc/suricata/update.yaml)
------------------------------------------------------

.. literalinclude:: ../suricata/update/configs/update.yaml

.. _example-enable-conf:

Example Configuration to Enable Rules (--enable-conf)
-----------------------------------------------------

.. literalinclude:: ../suricata/update/configs/enable.conf

.. _example-disable-conf:

Example Configuration to Disable Rules (--disable-conf)
--------------------------------------------------------

.. literalinclude:: ../suricata/update/configs/disable.conf

.. _example-drop-conf:

Example Configuration to convert Rules to Drop (--drop-conf)
------------------------------------------------------------

.. literalinclude:: ../suricata/update/configs/drop.conf

.. _example-modify-conf:

Example Configuration to modify Rules (--modify-conf)
-----------------------------------------------------

.. literalinclude:: ../suricata/update/configs/modify.conf
