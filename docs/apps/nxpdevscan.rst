=======================
User Guide - nxpdevscan
=======================

This user’s guide describes how to use *nxpdevscan* application which detects NXP devices connected to the host PC over USB and UART connections.

The "help" guide of *nxpdevscan* lists all of the options supported by the *nxpdevscan* utility with a simple description of how to use them.

-----------------
nxpdevscan - UART
-----------------

*nxpdevscan* lists all devices connected using UART to the host PC in section *Connected NXP UART Devices*

:ref:`UART device identification in SPSDK`

----------------
nxpdevscan - USB
----------------

*nxpdevscan* lists all devices connected using USB to host PC in section *Connected NXP USB Devices*.

:ref:`USB device identification in SPSDK`

--------------------
nxpdevscan - plugins
--------------------

*nxpdevscan* lists devices found by device interface plugins (installed packages registering
the ``spsdk.device.interface`` entry point) in section *Connected Plugin Devices*. Each plugin
interface is scanned by calling its ``scan`` class method without parameters; interfaces whose
``scan`` method requires mandatory parameters are skipped. A failure of one plugin is reported
as a warning and scanning continues with the remaining plugins.

Debug probes are not listed by *nxpdevscan*, use ``nxpdebugmbox tools list-probes`` instead.

----------------------
Command line interface
----------------------

.. click:: spsdk.apps.nxpdevscan:main
    :prog: nxpdevscan
    :nested: none

.. code:: bash

    nxpdevscan


.. figure:: ../_static/images/nxpdevscan_detect_2.png
    :scale: 50 %
    :align: center

    `nxpdevscan` lists NXP devices connected to host PC
