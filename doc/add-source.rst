################################
add-source - Add a source by URL
################################

Synopsis
========

::

   suricata-update add-source [--name name] [--url <url>]

Description
===========

The ``add-source`` adds a source to the set of enabled sources by
URL. It is useful to add a source that is not provided in the index.

Options
=======

.. option:: --name <name>

   The name of the source. If not provided on the command line the
   user will be prompted.

.. option:: --url <url>

   The URL of the source. If not provided on the command line the user
   will be prompted.

