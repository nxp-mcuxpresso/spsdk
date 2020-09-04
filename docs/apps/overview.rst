Overview
========

Applications shipped with SPSDK are available in ``PATH`` after activating a virtual environment with SPSDK installed in it.
If you don't use virtual environments, the availability is not guaranteed (you'd need to add Python's Scripts folder to PATH first)

SPSDK has a special application called ``spsdk``. It holds references to all available applications.
To see the list run: ``spsdk --help``
Each application could be executed separately or via spsdk (e.g. running ``pfr`` is equal to running ``spsdk pfr``)

Options and flags for each application and their respective sub-commands are available using ``--help`` flag.


List of applications
====================

nxpkeygen 
---------

The nxpkeygen application allows user to:

- generate RSA/ECC key pairs (private and public) with various key's attributes
- generate debug credential files based on YAML configuration file

For complete list of operations run: ``nxpkeygen --help``.

nxpdebugmbox
------------

The nxpdebugmbox application allows user to:

- perform the Debug Authentication
- start/stop Debug Mailbox

For complete list of operations run: ``nxpdebugmbox --help``.

pfr
---

The pfr application a utility for generating and parsing Protected Flash Region data (CMPA, CFPA).

It allows user to:

- generate user configuration
- parse binary a extract configuration
- generate binary data.
- generate HTML page with brief descrition of CMPA/CFPA configuration fields

For complete list run: ``pfr --help``.

sdphost
-------

The sdphost application a utility for communication with ROM on i.MX targets.

It allows user to:

- get error code of last operation
- jump to entry point of image with IVT at specified address
- write file at address

For complete list run: ``sdphost --help``.

blhost
------

The blhost application  is  a utility for communication with bootloader on target.\

It allows user to:

- apply configuration block at internal memory address to memory with ID
- program one word of OCOTP Field.
- read one word of OCOTP Field
- erase region of the flash
- fill memory with pattern
- get bootloader-specific property
- write/read memory
- reset the device
- generate the Key Blob for a given DEK

For complete list run: ``blhost --help``.

