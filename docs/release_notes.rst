.. NXP location

.. _LIBUSBSIO_link: https://www.nxp.com/design/software/development-software/library-for-windows-macos-and-ubuntu-linux:LIBUSBSIO?tid=vanLIBUSBSIO

=============
Release Notes
=============

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
* :ref:`pfrc` - console script for searching for brick conditions in pfr settings
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
