Suricata-Update
===============

The tool for updating your Suricata rules.

Installation
------------

    pip install --upgrade suricata-update

Documentation
-------------

https://suricata-update.readthedocs.io/en/latest/

Issues
------

https://redmine.openinfosecfoundation.org/projects/suricata-update

Example Usage
-------------

    suricata-update

The default invocation of ``suricata-update`` will perform the following:

- Read the configuration, /etc/suricata/update.yaml, if it exists.
- Read in the rule filter configuration files:

  - /etc/suricata/disable.conf
  - /etc/suricata/enable.conf
  - /etc/suricata/drop.conf
  - /etc/suricata/modify.conf

- Download the best version of the Emerging Threats Open ruleset for
  the version of Suricata found.
- Read in the rule files provided with the Suricata distribution from
  /etc/suricata/rules.
- Apply disable, enable, drop and modify filters.
- Resolve flowbits.
- Write the rules to /var/lib/suricata/rules/suricata.rules.

If you are not yet ready to use /var/lib/suricata/rules then you may
be interested in the `--output
<http://suricata-update.readthedocs.io/en/latest/#cmdoption-o>`_ and
`--no-merge
<http://suricata-update.readthedocs.io/en/latest/#cmdoption-o>`_
command line options.

Suricata Configuration
----------------------

The default Suricata configuration needs to be updated to find the rules
in the new location.

Example suricata.yaml

.. code-block:: yaml

  default-rule-path: /var/lib/suricata/rules
  rule-files:
    - suricata.rules

Optionally ``-S /var/lib/suricata/rules/suricata.rules`` could be
provided on the Suricata command line.

Notes
-----

This ``suricata-update`` tool is based around the idea
``/etc/suricata`` should not be used for active rule management, but
instead as a location for more or less static configuration.  Instead
``/var/lib/suricata`` is used for rule management and
``/etc/suricata/rules`` is used as a source for rule files provided by
the Suricata distribution.

Files and Directories
---------------------

``/usr/share/suricata/rules``
   Used as a source of rules provided by the Suricata engine. If this
   directory does not exist, ``etc/suricata/rules`` will be used.

``/etc/suricata/update.yaml``
  The default location for the ``suricata-update`` configuration file.

``/etc/suricata/disable.conf``
  Default location for disable rule filters if not provided in the
  configuration file or command line.

``/etc/suricata/enable.conf``
  Default location for enable rule filters if not provided in the
  configuration file or command line.

``/etc/suricata/drop.conf``
  Default location for drop rule filters if not provided in the
  configuration file or command line.

``/etc/suricata/modify.conf``
  Default location for modify rule filters if not provided in the
  configuration file or command line.
  
``/var/lib/suricata/rules``
  The output directory for rules processed by the ``suricata-update``
  tool. This directory is owned and managed by ``suricata-update`` and
  should not be touched by the user.

``/var/lib/suricata/rules/suricata.rules``
  The default output filename for the rules processed by ``suricata-update``.

  This is a single file that contains all the rules from all input
  files and should be used by Suricata.

``/var/lib/suricata/update/cache``
  Directory where downloaded rule files are cached here.

``/var/lib/suricata/rules/cache/index.yaml``
  Cached copy of the rule source index.

``/var/lib/suricata/update/sources``
  Configuration direction for sources enabled or added with
  ``enable-source`` or ``add-source``.
