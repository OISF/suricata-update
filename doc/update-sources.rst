########################################
update-sources - Update the source index
########################################

Synopsis
========

::

   suricata-update update-sources

Description
===========

The ``update-sources`` command downloads the latest index of available
sources.

Options
=======

.. include:: common-options.rst

Files and Directories
=====================

``/var/lib/suricata/rules/.cache/index.yaml``
  Where the downloaded source index is cached.
  
Environment Variables
=====================

**SOURCE_INDEX_URL**
  This environment variable allows the specification of an alternate
  URL to download the index from.

URLs
====

``https://www.openinfosecfoundation.org/rules/index.yaml``
  The default URL used to download the index from.
