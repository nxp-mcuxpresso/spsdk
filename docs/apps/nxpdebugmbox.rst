=========================
User Guide - nxpdebugmbox
=========================

This user’s guide describes how to use *nxpdebugmbox* application.

.. note::
    If you encounter this warning: STLink, CMSIS-DAPv2 and PicoProbe probes are not supported because no libusb library was found. It means that libusb cannot be found on your system.
    Libusb in PyOCD is distributed as python package libusb-package which does not have wheel distribution for Python 3.12 https://github.com/pyocd/libusb-package/issues/16 (October 2024). 
    As a workaround you might copy the libusb-1.0.dll to the root of libusb-package folder in your virtual environment e.g.: venv/Lib/site-packages/libusb_package/libusb-1.0.dll or copy it
    to Windows/System32/. You can get the dll here: https://libusb.info/


----------------------
Command line interface
----------------------

.. click:: spsdk.apps.nxpdebugmbox:main
    :prog: nxpdebugmbox
    :nested: full
