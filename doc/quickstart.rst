Quick Start
###########

Install Suricata Update
=======================

.. note:: If you have already installed Suricata 4.1 you likely
          already have Suricata-Update installed. Please check if the
          ``suricata-update`` command is available to you before
          installing.

Suricata-Update is a tool written in Python and best installed with
the ``pip`` tool for installing Python packages.

Pip can install ``suricata-update`` globally making it available to
all users or it can install ``suricata-update`` into your home
directory for use by your user.

.. note:: At some point ``suricata-update`` should be bundled with
          Suricata avoid the need for a separate installation.

To install ``suricata-update`` globally::

    pip install --upgrade suricata-update

or to install it to your own directory::

    pip install --user --upgrade suricata-update

.. note:: When installing to your home directory the
          ``suricata-update`` program will be installed to
          $HOME/.local/bin, so make sure this directory is in your
          path::

	    export PATH=$HOME/.local/bin:$PATH

Directories and Permissions
===========================

In order for ``suricata-update`` to function, the following
permissions are required:

* Directory /etc/suricata: read access
* Directory /var/lib/suricata/rules: read/write access
* Directory /var/lib/suricata/update: read/write access

One option is to simply run ``suricata-update`` as root or with
``sudo``.

.. note:: It is recommended to create a ``suricata`` group and setup
          the above directories with the correction permissions for
          the ``suricata`` group then add users to the ``suricata``
          group.

	  More documentation will be provided about this, including a
	  tool to verify and maybe setup the permissions.

Update Your Rules
=================

Without doing any configuration the default operation of
``suricata-update`` is use the Emerging Threats Open ruleset.

Example::

  suricata-update

This command will:

* Look for the ``suricata`` program on your path to determine its
  version.

* Look for /etc/suricata/enable.conf, /etc/suricata/disable.conf,
  /etc/suricata/drop.conf, and /etc/suricata/modify.conf to look for
  filters to apply to the downloaded rules. These files are optional
  and do not need to exist.

* Download the Emerging Threats Open ruleset for your version of
  Suricata, defaulting to 4.0.0 if not found.

* Apply enable, disable, drop and modify filters as loaded above.

* Write out the rules to ``/var/lib/suricata/rules/suricata.rules``.

* Run Suricata in test mode on
  ``/var/lib/suricata/rules/suricata.rules``.

.. note:: Suricata-Update is also capable of triggering a rule reload,
          but doing so requires some extra configuration that will be
          covered later.

Configure Suricata to Load Suricata-Update Managed Rules
========================================================

Suricata-Update takes a different convention to rule files than
Suricata traditionally has. The most noticeable difference is that the
rules are stored by default in
``/var/lib/suricata/rules/suricata.rules``.

One way to load the rules is to the the ``-S`` Suricata command line
option. The other is to update your ``suricata.yaml`` to look
something like::

  default-rule-path: /var/lib/suricata/rules
  rule-files:
    - suricata.rules

.. note:: In the future we expect Suricata to use this new convention
          by default.

Discover Other Available Rule Sources
=====================================

First update the rule source index with the ``update-sources`` command,
for example::

  suricata-update update-sources

Then list the sources from the index. Example::

  suricata-update list-sources

Now enable the **ptresearch/attackdetection** ruleset::

  suricata-update enable-source ptresearch/attackdetection

And update your rules again::

  suricata-update

List Enabled Sources
====================

::

   suricata-update list-enabled-sources

Disable a Source
================

::

   suricata-update disable-source et/pro

Disabling a source keeps the source configuration but disables. This
is useful when a source requires parameters such as a code that you
don't want to lose, which would happen if you removed a source.

Enabling a disabled source re-enables without prompting for user
inputs.

Remove a Source
===============

::

   suricata-update remove-source et/pro

This removes the local configuration for this source. Re-enabling
**et/pro** will requiring re-entering your access code.

