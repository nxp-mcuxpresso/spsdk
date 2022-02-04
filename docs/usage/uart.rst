===================================
UART device identification in SPSDK
===================================

Devices connected to host PC using UART could be identified by *name* identifying serial port COMx
and *speed* defining baud rate, e.g. 9600, 57600, 115200.

.. figure:: ../_static/images/nxpdevscan_uart_detect.png
    :scale: 50 %
    :align: center

    UART detection using `nxpdevscan`

.. note:: For Applications and APIs to use connected devices under Linux, it is necessary to configure them, see :ref:`UART under Linux`.
