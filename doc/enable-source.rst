###############################
enable-source - Enable a source
###############################

Synopsis
========

::

   suricata-update enable-source <source-name> [param=val ...]

Description
===========

Enable a source that is listed in the index.

If the index requires user provided parameters the user will be
prompted for them. Alternatively they can be provided on command line
to avoid the prompt.

For example::

  suricata-update enable-source et/pro secret-code=xxxxxxxxxxxxxxxx

This will prevent the prompt for the et/pro secret code using the
value provided on the command line instead.

To update parameters for enabled sources, just re-run the ``enable-source``
command above again with changed parameters. Changed parameters will be
updated in the stored configuration.

Options
=======

.. include:: ./common-options.rst
