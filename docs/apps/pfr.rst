================
User Guide - pfr
================

This user’s guide describes how to use *pfr* application.

PFR application is a command line tool for working with Protected Flash Region (PFR) areas (CMPA, CFPA).
User might use this tool to read, write, parse, erase, and display PFR areas.

Get-template command is used to generate a template file for PFR configuration. Then, user can modify this file and use it for PFR configuration.
Values might be passed as enums or as a hexadecimal number.

.. note::
    Special prefix "RAW:" is used to pass a hexadecimal number that won't be pre-processed.
    For example IPED_CTX0_START_ADDR: "RAW:0x123456"

----------------------
Command line interface
----------------------

.. click:: spsdk.apps.pfr:main
    :prog: pfr
    :nested: full
