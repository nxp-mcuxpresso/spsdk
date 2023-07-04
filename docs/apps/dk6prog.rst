====================
User Guide - dk6prog
====================

.. warning:: *dk6prog* is a prototype application and it is not tested. To be used at the user's own risk.

This user’s guide describes how to use *dk6prog* application.
DK6 Programmer Tools allows reading and programming flash memory of DK6 target devices (JN51xx, QN9090, K32W0xx).
It's a Python port of JN51xx Flash Programmer (https://www.nxp.com/docs/en/user-guide/JN-UG-3099.pdf).

Supported devices
==================
DK6 Board and all compatible modules https://www.nxp.com/products/wireless/multiprotocol-mcus/advanced-development-kit-for-k32w061-and-jn5189-88:IOTZTB-DK006

Backends
=========
*dk6prog* tools support four backends (drivers). PYFTDI backend, pure Python implementation of libFTDI. PYLIBFTDI backend, ctypes wrapper for libFTDI. FTD2XX backend, ctypes wrapper for D2XX. PYSERIAL backend for simple UART communication.


Jupyter example
================
Visit Jupyter example :ref:`DK6 Programming tool` for more information and examples of usage.

----------------------
Command line interface
----------------------

.. click:: spsdk.apps.dk6prog:main
    :prog: dk6prog
    :nested: full
