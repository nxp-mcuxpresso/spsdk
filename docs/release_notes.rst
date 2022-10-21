.. NXP location

.. _LIBUSBSIO_link: https://www.nxp.com/design/software/development-software/library-for-windows-macos-and-ubuntu-linux:LIBUSBSIO?tid=vanLIBUSBSIO
.. _crypto: api/crypto.html
.. _usb_device_identification: usage/usb.html

=============
Release Notes
=============

-------------------------
1.8.0 (21-October-2022)
-------------------------

**New features**

* :ref:`nxpimage`:
    - add support for BEE
    - enable OTFAD on RT1180
* :ref:`pfr`:
    - move the functionality of pfrc tool into PFR tool
* :ref:`tphost`/:ref:`tpconfig`:
    - implement USB re-enumeration in TPHost after OEM ProvFW is started
    - create command for checking the Chain of Trust used in TP
    - investigate TP performance loss during device reset after TP is completed
    - add possibility to select TP SmartCard via card reader's name
* unify option for getting template across tools
* add API for parsing XMCD
* support cryptography >= 37.0.0
* support bincopy 17.14

**Bugfixes**

* :ref:`nxpdevscan`:
    - fix hanging up for serial communication
* :ref:`tphost`/:ref:`tpconfig`:
    - blhost_port should not be mandatory in TP target settings
    - fix disabling timeout in TP is ignored
* fix documentation regarding SB31 programFuses

-------------------------
1.7.1 (16-September-2022)
-------------------------

**New features**

* :ref:`nxpimage`:
    - add OTFAD support for RT5xx and RT6xx devices
* :ref:`pfr`:
    - read command allows independent binary and yaml exports
* :ref:`shadowregs`:
    - new subcommand: fuses-script
* add OEM cert size check into TPConfig

**Bugfixes**

* :ref:`nxpdebugmbox`:
    - fix debug authentication for RT595
* :ref:`nxpimage`:
    - fix sb21 command line argument in documentation
* fix the use of pyyaml's load in tests (use safe_load())

--------------------
1.7.0 (29-July-2022)
--------------------

**New features**

* :ref:`nxpimage` application as replacement for elftosb
* :ref:`nxpcrypto` application for generating and verifying keys, certificates, hash digest, converting key's format
* trust provisioning applications (:ref:`tphost` and :ref:`tpconfig`)
* :ref:`blhost`:
    - support LifeCycleUpdate command for RT1180
    - add option to specify peripheral index of SPI/I2C for LIBUSBSIO
    - allow lowercase names in the filter for USB mboot devices
* :ref:`nxpdebugmbox`:
    - utility to read/write memory using debug probe
* :ref:`nxpimage`:
    - support of Master Boot Images
    - support AHAB container for RT1180
    - support of Secure Binary 2.1 / 3.1
    - support for TrustZone blocks
    - support for Bootable images for RTxxx devices
    - support for FCB block parsing and exporting for RTxxx and some RTxxxx devices
    - simply binary image support, like create, merge, extract and convert (S19,HEX,ELF and BIN format)
* :ref:`pfr`:
    - load PFR configuration directly from chip using BLHOST
* :ref:`sdphost`:
    - support for SET_BAUDRATE command
    - support for iMX93
* drop support for Python 3.6
* pypemicro dependency update in order to cover latest bug fixes in this package
* libusbsio update to version 2.1.11
* unify debug options within applications
* add API to compute RKTH
* support LPC553x in elftosb/nxpimage
* support dual image boot on RT5xx and RT6xx
* replace click/sys.exit with raising an SPSDKAppError exception
* encryption of remapped images

**Bugfixes**

* :ref:`blhost`:
    - efuse_program_once returns failure message when using 'lock' option but still the fuse is burnt
    - fix in re-scanning LIBUSBSIO devices when target MCU is not connected
    - scan_usb() should return nxp devices
    - read memory command doesn't print read data when mem region is defined
* :ref:`elftosb`:
    - fix trustzone config template for rt5xx and rt6xx
    - fix MBI_PLainRamRTxxx image
    - fix CRC bootable image on RT685 EVK
    - fix image located in FLASH executed in RAM on RT6xx
    - fix burning fuses in BD file
* :ref:`nxpdebugmbox`:
    - fix in Jlink debugger probe initialization
    - fix get-crp command

---------------------
1.6.3 (1-April-2022)
---------------------

**New features**

* pypemicro dependency update in order to cover latest bug fixes in this package
* libusbsio update to version 2.1.11

**Bugfixes**

* fix in rescanning LIBUSBSIO devices when target MCU is not connected
* efuse_program_once returns failure message when using 'lock' option but still the fuse is burnt
* fix memory leaks in elftosb

---------------------
1.6.2 (11-March-2022)
---------------------

**New features**

* bump-up version of bincopy to <17.11
* add plain load image to build example bootable i.MX-RT image
* align docs requirements with project dependencies
* add stability notice to documentation
* speed-up application's start due to move of bincopy import

---------------------
1.6.1 (04-March-2022)
---------------------

**New features**

* :ref:`blhost`:
    - add parameter --no-verify for efuse-program-once
    - add possibility to select USBSIO bridge device via VID:PID, USB path, serial number
    - lower the timeout during MBoot's UART Ping command
    - improve type hints for scan_* functions for detecting devices
* :ref:`elftosb`:
    - dynamically generate config json schema per family
* :ref:`nxpdevscan`:
    - extend scan with device serial number information
    - list all connected USB or UART or SIO devices
    - update device's USB path (`usb_device_identification`_)
* :ref:`sdphost`:
    - improve type hints for scan_* functions for detecting SDP devices
* reduce number of findings from Pylint
* update JINJA2 requirement

**Bugfixes**

* :ref:`blhost`:
    - fix UART open operation for RT1176, RT1050 and LPC55S06 platforms (and probably others)
* :ref:`elftosb`:
    - fix preset data for lpc55s0x, lpc55s1x
* SPI communication failure (changed FRAME_START_NOT_READY to 0xFF for SPI)
* PYI files are not included in the distribution package

------------------------
1.6.0 (04-February-2022)
------------------------

**New features**

* :ref:`blhost`:

  * add experimental batch mode into blhost
  * support command get property 30
  * change output display for blhost get-property 8
  * provide the real exit code (status code) from BLHOST application
  * report progress of data transfer operations in blhost
  * performance boost in receive-sb-file

* :ref:`elftosb`:

  * validation inputs using jsonschemas
  * reorganize and improve elftosb
  * add support for more input file types
  * [RTxxx] HMAC_KEY is now accepted in binary form

* :ref:`nxpdebugmbox`:

  * move gendc into nxpdebugmbox

* :ref:`pfr`:

  * unify CMPA/CFPA fields descriptions and bit-field values within XML registers data
  * implement CMPA data generator and parser

* improve documentation
* remove dependency on munch and construct modules
* add support for reserved bitfields in registers
* support multiple occurrence of certificate attributes for subject/issuer
* remove backward compatibility mode in Registers
* reorganize functions from misc.py
* add support for bumpversion

**Bugfixes**


* :ref:`blhost`:

  * generate-key-blob does not generate blob.bin on RT1176
  * parse_property_tag in blhost_helper converts incorrectly in some cases
  * different return code on Linux/Mac and Windows
  * USBSIO - fixed issue when busy signal on I2C was interpreted as data

* `crypto`_:

  * DER encoded certificates are loaded as PEM
  * fixed dependency on cryptography's internal keys
  * moved to fully typed versions of cryptography

* :ref:`elftosb`:

  * cannot build CRC image into ext flash for lpc55s3x
  * cannot generate signed image with <4 ROT keys
  * fixed some failing cases in regards of TZ
  * [rtxxx] missing plain for load-to-ram image
  * configuration validation failed in some cases

* :ref:`nxpdebugmbox`:

  * return code is 0 in case of fail
  * nxpdebugmbox fails on Linux

* :ref:`nxpdevhsm`:

  * generate ends with general error when no container is provided

* :ref:`pfr`:

  * fix problem in registers class with another size of register than 32 bits

* pfrc:

  * displays false brick conditions
  * wrong validation of CMPA.CC_SOCU_PIN bits

----------------------
1.5.0 (07-August-2021)
----------------------

**New features**

* :ref:`nxpdevhsm` - new application added:

  * The nxpdevhsm is a tool to create initial provisioning SB3 file for LPC55S36 to provision device with SB KEK needed to validate in device all standard SB3 files.

* `LIBUSBSIO <LIBUSBSIO_link_>`__ integration as a replacement for HID_API module:

  * blhost - extend blhost by LPCUSBSIO interface

* :ref:`blhost` - following trust-provisioning  sub-commands added:

  * :ref:`oem_get_cust_cert_dice_puk` - creates the initial trust provisioning keys
  * :ref:`oem_gen_master_share` - creates shares for initial trust provisioning keys
  * :ref:`oem_set_master_share` - takes the entropy seed and the Encrypted OEM Master Share
  * :ref:`hsm_gen_key` - creates OEM common keys, including encryption keys and signing keys
  * :ref:`hsm_store_key` - stores known keys, and generate the corresponding key blob
  * :ref:`hsm_enc_blk` - encrypts the given SB3 data bloc
  * :ref:`hsm_enc_sign` - signs the given data

* :ref:`elftosb`:

  * support for :ref:`SB 2.1 generation using BD file`
  * LPC55S3x - add support for unsigned/plain images
  * SB2.1 - SHA256 digest of all sections included in signed SB2.1 header
  * add supported families listing into elftosb
  * implement chip family option as a click.Choice
  * allow loading certificates for MBI in PEM format

* :ref:`nxpcertgen`:

  * generate the template for yml configuration file containing the parameters for certificate
  * improve yml template description for nxpcertgen
  * add support for generating certificates in DER format

* :ref:`nxpkeygen`:

  * moved option -p from general space to gendc subcommand.
  * add new -k keygen subcommand option to specify key type to generate

* :ref:`nxpdebugmbox`:

  * refactor DebugCredential base class so that it will be possible to pass certificates in yml config file
  * check nxpdebugmbox on LPC55S3x

* :ref:`pfr` - update CMPA/CFPA registers XML data for LPC55S3x with CRR update

* SPSDK :ref:`Applications`:

  * spsdk applications show help message when no parameter on command line provided
  * improved help messages
  * support Ctrl+C in cmd applications

* replace functional asserts with raising a SPSDK-based exception
* replace all general exception with SPSDK-based exceptions

**Bugfixes**

* :ref:`nxpkeygen` - regenerates a key without --force
* :ref:`elftosb` - unclear error message: No such file or directory: 'None'
* :ref:`pfr` - duplicated error message: The silicon revision is not specified
* :ref:`nxpdebugmbox` - fix Retry of AP register reads after Chip reset
* :ref:`nxpdebugmbox` - add timeout to never ending loops in spin_read/write methods in Debug mailbox
* :ref:`blhost` - flash-erase-region command doesn't accept the memory_id argument in hex form
* :ref:`elftosb` - using kdkAccessRigths = 0 in SB31 is throwing an error in KeyDerivator

--------------------
1.4.0 (25-June-2021)
--------------------

**New features**

* version flag added for all command-line application
* support for Python 3.9 added
* :ref:`blhost` - following sub-commands added:
    * list-memory
    * flash-program-once
    * set-property
    * flash-erase-all-unsecure
    * flash-security-disable
    * flash-read-resource
    * reliable-update
    * fuse-program
    * flash-image
    * program-aeskey
* :ref:`blhost` - memoryId calmp-down for mapped external memories added
* :ref:`elftosb` - support for SB 2.1 added
* :ref:`elftosb` - basic support for BD configuration file added
* :ref:`nxpdebugmbox` - debug port enabled check added
* :ref:`nxpkeygen` - new sub-command added to nxpkeygen to create a template for configuration YML file for DC keys
* :ref:`nxpkeygen` - new sub-command added to create a template for configuration YML file for DC keys
* :ref:`pfr` - default JSON config file generation removed, but still accepted as an input. The preferred is the YML configuration format.
* docs - Read The Docs documentation improvements

**Bugfixes**

* wrong DCD size by BootImgRT.parse
* cmdKeyStoreBackupRestore wrong param description
* :ref:`blhost` - typo in McuBootConnectionError exception
* :ref:`blhost` - mcuBoot Uart doesn't close the device after failed ping command
* :ref:`blhost` - assertion error when connection lost during fuses readout
* :ref:`blhost` - sub-command  flash-read-resource fails when the length is not aligned
* :ref:`pfr` - incorrect keys hash computation for LPC55S3x
* :ref:`pfr` - wrong LPC55S69 silicon revision
* :ref:`pfr` - parse does not show PRINCE IV fields
* :ref:`sdphost` - running spdhost --help fails
* :ref:`shadowregs` - bad DEV_TEST_BIT in shadow registers

---------------------
1.3.1 (29-March-2021)
---------------------

* :ref:`pfr` - configuration template supports YAML with description, backward compatibility with JSON ensured
* :ref:`pfr` - API change: "keys" parameter has been moved from __init__ to export
* :ref:`pfr` - sub-commands renamed:
  * user-config -> get-cfg-template
  * parse -> parse-binary
  * generate -> generate-binary
* :ref:`blhost` - allow key names for key-provisioning commands
* :ref:`blhost` - support for RT1170, RT1160
* :ref:`shadowregs` - shadow registers tool is now top-level module
* :ref:`blhost` - fix baud rate parameter
* :ref:`pfr` - fix in data for LPC55S6x, LPC55S1x, LPC55S0x
* :ref:`blhost` - communication stack breaks down on RT1170 after unsuccessful key-prov enroll command

--------------------
1.3.0 (5-March-2021)
--------------------

* support creation of SB version 3.1
* :ref:`elftosb` application based on legacy elf2sb supporting SB 3.1 support
* :ref:`nxpdevscan` - application for connected USB, UART devices discovery
* :ref:`shadowregs` -  application for shadow registers management using DebugProbe
* support USB path argument in blhost/sdphost (all supported OS)
* :ref:`nxpcertgen` CLI application (basicConstrains, self-signed)
* :ref:`blhost` - commands added:
    * flash-erase-all
    * call
    * load-image
    * execute
    * key-provisioning
    * receive-sb-file
* :ref:`blhost` - extend commands' options:
    * configure-memory now allows usage of internal memory
    * extend error code in the output
    * add parameters lock/nolock into efuse-program-once command
    * add key selector option to the generate-key-blob command
    * add nolock/lock selector to efuse-program-once command
    * add hexdata option to the write-memory command

------------------------
1.2.0 (11-December-2020)
------------------------

* support for LPC55S3x devices
* extend support for LPC55S1x, LPC55S0x
* pfrc - console script for searching for brick conditions in pfr settings
* custom HSM support
* sdpshost CLI utility using sdpshost communication protocol
* remote signing for Debug Credential
* added command read-register into sdphost CLI
* dynamic plugin support
* MCU Link Debugger support
* :ref:`pfr` - added CMAC-based seal
* :ref:`pfr` - load Root of Trust from elf2sb configuration file

------------------------
1.1.0 (4-September-2020)
------------------------

* support for i.MX RT1170 device
* support for elliptic-curve cryptography (ECC)
* support for SDPS protocol
* included Debug Authentication functionality
* included support for debuggers
* :ref:`nxpkeygen` - utility for generating debug credential files and corresponding keys

--------------------
1.0.0 (4-April-2020)
--------------------

* support for LPC55S69 and LPC55S16 devices
* support for i.MX RT105x and RT106x devices
* support for i.MX RT595S and RT685S devices
* connectivity to the target via UART, USB-HID.
* support for generating, saving, loading RSA keys with different sizes
* generation and management of certificate
* :ref:`blhost` - CLI utility for communication with boot loader on a target
* :ref:`sdphost` - CLI utility for communication with ROM on a target
* :ref:`pfr` - CLI utility for generating and parsing Protected Flash Regions - CMPA and CFPA regions
