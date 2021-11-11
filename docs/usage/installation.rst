==================
Installation Guide
==================

- Make sure to have `Python 3.6+ <https://www.python.org>`_ installed (old version 2.x is not supported).
- Create and activate a virtual environment (``venv``, ``pipenv``, etc.)
- Upgrade PyPI to the latest version
- Install SPSDK

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



-------------
macOS @ Intel
-------------

To install *SPSDK* under *macOS* follow:

.. code-block:: bash

    python3 -m venv venv
    source venv/bin/activate
    python -m pip install --upgrade pip
    pip install spsdk
    spsdk --help

*SPSDK* help for command-line applications should be displayed.

----------
macOS @ M1
----------

It's recommended to use the ``pyenv`` package for Python installation. To install *SPSDK* follow those steps:

1. Install ``homebrew``. *Homebrew* is a package manager for macOS located `here <https://brew.sh>`_

.. code-block:: bash

    $ /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"

2. Install *pyenv*

.. code-block:: bash

    $ brew update
    $ brew install pyenv

3. Enable ``pyenv``, execute the following lines to set environment variables, assuming you are using ``zsh``

.. code-block:: bash

    $ echo 'export PYENV_ROOT="$HOME/.pyenv"' >> ~/.zprofile
    $ echo 'export PATH="$PYENV_ROOT/bin:$PATH"' >> ~/.zprofile

4. Install *Python*

.. code-block:: bash

    $ pyenv install 3.9.5

5. Make ``pyenv`` Python global and rehash

.. code-block:: bash

    $ pyenv global 3.9.5
    $ pyenv rehash

Now you can use ``pip`` for package installation.

6. Install *rust compiler*. To build some *SPSDK* dependencies a *rust compiler* is needed, to install it a *rustup script* could be used: https://rustup.rs.

.. code-block:: bash

    $ curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

7. Install *Python* build dependencies

.. code-block:: bash

    $ brew install openssl readline sqlite3 xz zlib

8. Export compiler flags for ``openssl``

.. code-block:: bash

    $ export LDFLAGS="-L/opt/homebrew/opt/openssl@1.1/lib"
    $ export CPPFLAGS="-I/opt/homebrew/opt/openssl@1.1/include"

9. Install *SPSDK*

.. code-block:: bash

    $ pip install spsdk

------
GitHub
------

To install *SPSDK* form GitHub follow:

.. code:: bash

    $ pip install -U https://github.com/NXPmicro/spsdk/archive/master.zip

GitHub - from sources
=====================

To install *SPSDK* from source code follow:

.. code:: bash

    $ git clone https://github.com/NXPmicro/spsdk.git
    $ cd spsdk
    $ pip install -U -e .

.. note::

    In case of problems during installation, please make sure that you have the latest pip version.
    You can upgrade pip using this command:

    .. code:: bash

        pip install --upgrade pip


