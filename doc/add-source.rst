################################
add-source - Add a source by URL
################################

Synopsis
========

::

   suricata-update add-source <name> <url>

Description
===========

The ``add-source`` adds a source to the set of enabled sources by
URL. It is useful to add a source that is not provided in the index.

Options
=======

.. option:: --http-header "Header: Value"

   Add an additional HTTP header to requests for this rule source such
   as a custom API key. Example::

     add-source --http-header "X-API-Key: 1234"

Common Options
==============

.. include:: ./common-options.rst
