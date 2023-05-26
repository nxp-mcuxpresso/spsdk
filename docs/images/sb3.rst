------------------
Secure Binary 3.1
------------------

SB 3.1 is an evolution of the SB 2 format.
The configuration is done in a similar way as a master boot image by configuration file in YAML or JSON. BD files are no longer used, commands are supplied in the configuration file.

Example of use
nxpimage: ``nxpimage sb31 export "sb3_config.yaml``


Supported commands
=============================


.. include:: ../_prebuild/table_sb31.inc
   :parser: myst_parser.sphinx_



Supported configuration options
=================================

.. include:: ../_prebuild/schemas_sb3.inc
   :parser: myst_parser.sphinx_
