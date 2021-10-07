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
   
   HTTP basic authentication can be achieved by setting the HTTP Basic
   Authentication header with ``base64(user1:password1)``. Example::

      add-source --http-header "Authorization: Basic dXNlcjE6cGFzc3dvcmQx"
   
   HTTP Bearer authentication can be used by setting the HTTP Bearer Authentication header 
   with a OAuth2 token containing printable ASCII characters. Example::

      add-source --http-header "Auhorization: Bearer NjA2MTUOTAx?D+wOm4U/vpXQy0xhl!hSaR7#ENVpK59"

.. option:: --no-checksum

   Skips downloading the checksum URL for the rule source.

Common Options
==============

.. include:: ./common-options.rst
