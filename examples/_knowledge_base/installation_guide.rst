==================
Installation Guide
==================

------------
Requirements
------------

- Make sure to have `Python 3.9+ <https://www.python.org>`_ installed (old version 2.x is not supported).
- It is recommended to create and activate a virtual environment (``venv``, ``pipenv``, etc.) to avoid conflict with other packages
- Upgrade PyPI to the latest version
- Install SPSDK

.. note::
    For more information about creating of virtual environments go to `the official documentation <https://docs.python.org/3/library/venv.html>`_

.. warning::

    Please note that not all SPSDK dependencies might be distributed as wheels (built package format for Python). In this case please ensure that you have C compiler on your system. In some cases `rust compiler <https://rustup.rs/>`_ is also needed

-------
Windows
-------

To install *SPSDK* under *Windows* follow:

.. code-block:: bat

    python -m venv venv
    venv\Scripts\activate
    python -m pip install --upgrade pip
    pip install spsdk
    spsdk --help

*SPSDK* help for command-line applications should be displayed.

.. note::

    In **Windows OS** you need to install `Microsoft Visual C++ Build Tools <https://www.scivision.dev/python-windows-visual-c-14-required/>`_

-----
Linux
-----

To install *SPSDK* under *Linux* follow:

.. code-block:: bash

    python3 -m venv venv
    source venv/bin/activate
    python -m pip install --upgrade pip
    pip install spsdk
    spsdk --help

*SPSDK* help for command-line applications should be displayed.


UART under Linux
================

Several steps need to be performed before *SPSDK* can list and use NXP devices connected to the host PC under Linux using UART.

By default on *Ubuntu* tty serial devices are only accessible to users in group *dialout*. The permissions for /dev/ttyACM0 can be permanently solved by adding the user to the *dialout* group:

.. code-block:: bash

    sudo usermod -a -G dialout $USER

Then the user has to perform logout and login from the system for the group changes to take effect. Afterward, the UART device could be shown in ``nxpdevscan`` and are ready for use.


USB under Linux
===============

For *SPSDK* to access connected devices using USB, it is necessary to configure ``udev`` rules.

.. note:: NXP VIDs list - :ref:`USB - VID & PID`.

1. Create a file for example ``50-nxp.rules`` containing following rules:

.. code::

    SUBSYSTEM=="hidraw", KERNEL=="hidraw*", ATTRS{idVendor}=="0d28", MODE="0666"
    SUBSYSTEM=="hidraw", KERNEL=="hidraw*", ATTRS{idVendor}=="1fc9", MODE="0666"
    SUBSYSTEM=="hidraw", KERNEL=="hidraw*", ATTRS{idVendor}=="15a2", MODE="0666"

2. To install rules copy the file to ``/etc/udev/rules.d``:

.. code-block:: bash

    sudo cp 50-nxp.rules /etc/udev/rules.d

    sudo udevadm control --reload-rules

    sudo udevadm trigger

3. Plug your NXP device(s) and call ``nxpdevscan``.


NXPUUU under Linux
====================

If you want to use nxpuuu under Linux without sudo. Append these rules to udev rules.

.. code::

    SUBSYSTEM=="usb", ATTRS{idVendor}=="1fc9", ATTRS{idProduct}=="012f", MODE="0666"
    SUBSYSTEM=="usb", ATTRS{idVendor}=="1fc9", ATTRS{idProduct}=="0129", MODE="0666"
    SUBSYSTEM=="usb", ATTRS{idVendor}=="15a2", ATTRS{idProduct}=="0076", MODE="0666"
    SUBSYSTEM=="usb", ATTRS{idVendor}=="15a2", ATTRS{idProduct}=="0054", MODE="0666"
    SUBSYSTEM=="usb", ATTRS{idVendor}=="15a2", ATTRS{idProduct}=="0061", MODE="0666"
    SUBSYSTEM=="usb", ATTRS{idVendor}=="15a2", ATTRS{idProduct}=="0063", MODE="0666"
    SUBSYSTEM=="usb", ATTRS{idVendor}=="15a2", ATTRS{idProduct}=="0071", MODE="0666"
    SUBSYSTEM=="usb", ATTRS{idVendor}=="15a2", ATTRS{idProduct}=="007d", MODE="0666"
    SUBSYSTEM=="usb", ATTRS{idVendor}=="15a2", ATTRS{idProduct}=="0080", MODE="0666"
    SUBSYSTEM=="usb", ATTRS{idVendor}=="1fc9", ATTRS{idProduct}=="0128", MODE="0666"
    SUBSYSTEM=="usb", ATTRS{idVendor}=="1fc9", ATTRS{idProduct}=="0126", MODE="0666"
    SUBSYSTEM=="usb", ATTRS{idVendor}=="1fc9", ATTRS{idProduct}=="0135", MODE="0666"
    SUBSYSTEM=="usb", ATTRS{idVendor}=="1fc9", ATTRS{idProduct}=="0134", MODE="0666"
    SUBSYSTEM=="usb", ATTRS{idVendor}=="1fc9", ATTRS{idProduct}=="012b", MODE="0666"
    SUBSYSTEM=="usb", ATTRS{idVendor}=="0525", ATTRS{idProduct}=="b4a4", MODE="0666"
    SUBSYSTEM=="usb", ATTRS{idVendor}=="0525", ATTRS{idProduct}=="a4a5", MODE="0666"
    SUBSYSTEM=="usb", ATTRS{idVendor}=="066F", ATTRS{idProduct}=="9BFF", MODE="0666"



-------------
macOS
-------------

To install *SPSDK* under *macOS* follow:

.. code-block:: bash

    python3 -m venv venv
    source venv/bin/activate
    python -m pip install --upgrade pip
    pip install spsdk
    spsdk --help

*SPSDK* help for command-line applications should be displayed.

------
GitHub
------

To install *SPSDK* form GitHub follow:

.. code:: bash

    $ pip install -U git+https://github.com/nxp-mcuxpresso/spsdk.git


GitHub - from sources
=====================

To install *SPSDK* from source code follow:

.. code:: bash

    $ git clone https://github.com/nxp-mcuxpresso/spsdk.git
    $ cd spsdk
    $ pip install -U -e .

.. note::

    In case of problems during installation, please make sure that you have the latest pip version.
    You can upgrade pip using this command:

    .. code:: bash

        pip install --upgrade pip

-----------
PyInstaller
-----------

PyInstaller bundles SPSDK applications into executable binaries which might be executed without Python interpreter.

To bundle SPSDK applications into executables run the following line:

.. code:: bash

    $ pyinstaller --clean --noconfirm apps.spec


.. note::
    It is possible to define custom SPSDK_DATA_FOLDER location using environment variable
    with the name SPSDK_DATA_FOLDER or SPSDK_DATA_FOLDER_version.
    Where the version is SPSDK version with underscores.
    SPSDK_DATA_FOLDER_version has priority over SPSDK_DATA_FOLDER.
    E.g.: SPSDK_DATA_FOLDER_2_0_0


-------------------
Trust Provisioning
-------------------

Extra dependencies must be installed in order to use Trust Provisioning.
Also you will need `swig compiler <http://www.swig.org>`_ which is a requirement for pyscard

.. note::

    On **Mac OS** you need to install gcc, swig (http://www.swig.org), and pcsc-lite (https://pcsclite.apdu.fr/).
    (**brew install pcsc-lite swig**)
    On **Linux** you need to install pcscd and libpcsclite-dev. (**sudo apt install pcscd libpcsclite-dev swig**)

.. code:: bash

    $ pip install spsdk[tp]


In case you are installing from local repository.

.. code:: bash

    $ pip install ".[tp]"

This command will install SPSDK with Trust Provisioning support.


-------------------
DK6 Tools
-------------------

The command below install extra dependencies required for DK6 to work.

.. code:: bash

    $ pip install spsdk[dk6]


In case you are installing from local repository.

.. code:: bash

    $ pip install ".[dk6]"


.. note::
    For Pyftdi backend Linux, macOS libusb 1.x is needed.
    Install it with apt-get install libusb-1.0 or brew install libusb on macOS
    On Windows install D2XX drivers https://ftdichip.com/drivers/d2xx-drivers/


-------------------
CAN Support
-------------------

The command below install extra dependencies required for CAN to work.

.. code:: bash

    $ pip install spsdk[can]


In case you are installing from local repository.

.. code:: bash

    $ pip install ".[can]"


.. note::
    Refer to the documentation of `python-can <https://python-can.readthedocs.io>`_  for more information about supported devices.
