Summary
========

Applications shipped with SPSDK are available in ``PATH`` after activating a virtual environment with SPSDK installed in it.
If you don't use virtual environments, the availability is not guaranteed (you'd need to add Python's Scripts folder to PATH first).

SPSDK has a special application called ``spsdk``. It holds references to all available applications.
To see the list run: ``spsdk --help``.
Each application could be executed separately or via spsdk (e.g. running ``pfr`` is equal to running ``spsdk pfr``).

Options and flags for each application and their respective sub-commands are available using ``--help`` flag.


List of applications
====================

blhost
------

The blhost application  is  a utility for communication with bootloader on target.

It allows user to:

- apply configuration block at internal memory address to memory with ID
- program one word of OCOTP Field.
- read one word of OCOTP Field
- erase region of the flash
- erase all flash according to memory id
- fill memory with pattern
- get bootloader-specific property
- write/read memory
- reset the device
- generate the Key Blob for a given DEK
- receive SB file
- load a boot image to the device
- key provisioning
- execute application at address
- apply configuration block at internal memory address
- invoke code

For complete list run: ``blhost --help``


elftosb
---------

The tool for generating TrustZone, MasterBootImage and SecureBinary images.

- generate TrustZone
- generate MasterBootImage
- generate SecureBinary

For complete list run: ``elftosb --help``


nxpcertgen
------------

The nxpcertgen application allows user to generate the self-signed x.509 certificate
with properties given in json configuration file. The certificates are self-signed 
and support only BasicConstrains (ca, path_length).

For complete list of operations run: ``nxpcertgen --help``


nxpdebugmbox
------------

The nxpkeygen application allows user to:

- perform the Debug Authentication
- start/stop Debug Mailbox
- enter ISP mode
- set Fault Analysis Mode

For complete list of operations run: ``nxpdebugmbox --help``


nxpdevscan 
-----------

The nxpdevscan application allows user to list all connected USB and UART devices.

For complete list of operations run: ``nxpdevscan --help``


nxpkeygen 
----------

The nxpkeygen application allows user to:

- generate RSA/ECC key pairs (private and public) with various key's attributes
- generate debug credential files based on YAML configuration file

For complete list of operations run: ``nxpkeygen --help``


pfr
----

The pfr application is  a utility for generating and parsing Protected Flash Region data (CMPA, CFPA).

It allows user to:

- generate user configuration
- parse binary a extract configuration
- generate binary data.
- generate HTML page with brief description of CMPA/CFPA configuration fields
- list supported devices

For complete list of operations run: ``pfr --help``


pfrc
-----

The pfrc application is a utility for searching for brick-conditions in PFR settings.

Note: THIS IS AN EXPERIMENTAL UTILITY! USE WITH CAUTION !!!

For complete list of operations run: ``pfrc --help``


sdphost
--------

The sdphost application is a utility for communication with ROM on i.MX targets.

It allows user to:

- get error code of last operation
- jump to entry point of image with IVT at specified address
- write file at address
- read one or more registers

For complete list of operations run: ``sdphost --help``


sdpshost
---------

The sdpshost application is a utility for communication with ROM on i.MX targets.

It allows user to write boot image data from provided binary file.

Note: THIS IS AN EXPERIMENTAL UTILITY! USE WITH CAUTION !!!

For complete list of operations run: ``sdphosts --help``


shadowregs
-----------
The shadowreg application is a utility for Shadow Registers controlling.

It allows user to:

- save current state of shadow registers to YML file
- load new state of shadow registers from YML file into microcontroller
- print all shadow registers including theirs current values
- print the current value of one shadow register
- set a value of one shadow register defined by parameter
- reset connected device
- print a list of supported devices

For complete list of operations run: ``shadowregs --help``
