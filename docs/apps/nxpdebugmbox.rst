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

--------------------------------------------------
MCXA287 and MCXA577 commands after authentication
--------------------------------------------------

On MCXA287 and MCXA577 devices, mass erase in the
Develop2 and In-field lifecycles requires a successful debug authentication.
Opening the debug port alone does not grant every mailbox command: the device
configuration and debug credential must permit the requested operation.
For mass erase, check the ``ME_CMD_EN`` permission (bit 8 of ``CC_SOCU``).
Do not change lifecycle or provisioning settings merely to troubleshoot this error.

The authentication must remain active in the ROM mailbox command loop.
Use ``dat auth --no-exit``, then pass the **top-level** ``--no-reset`` option
to the following command. Do not issue ``cmd start``, reset, or power-cycle
the target between authentication and the command; re-entering the mailbox
discards the authenticated state.

.. warning::
    Mass erase destroys the internal flash contents. Depending on the
    ``ME_DEVCFG`` device configuration, it also erases customer IFR0.
    Back up any required data and obtain authorization before executing it.
    The commands below assume an already provisioned target and an existing,
    valid debug authentication configuration; they do not provision a device.

For example, after obtaining approval to erase an MCXA577:

.. code-block:: text

    nxpdebugmbox -i pyocd dat auth -c dat_config.yaml --no-exit
    nxpdebugmbox -i pyocd --no-reset cmd -f mcxa577 erase

The same session-preservation options apply to ``cmd ispmode`` and ``cmd famode``
when those operations require authentication. Each operation has its own
permission and lifecycle requirements; fault analysis can permanently change
the device state.

SPSDK 3.10.0 incorrectly kept mailbox reset enabled even when ``-n`` /
``--no-reset`` was specified. Upgrade to SPSDK 3.11.0 or newer rather than
weakening the device security policy. With debug logging enabled, the second
command above must show ``Reset mode: False``. A response such as
``0x00100002`` (``Command is not supported``, or ``Command not recognized``
in older releases) does not by itself prove an
unsupported command or ROM defect: check the active authenticated session,
lifecycle, and command permissions first.
