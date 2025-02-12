.. NXP location

.. _LIBUSBSIO_link: https://www.nxp.com/design/software/development-software/library-for-windows-macos-and-ubuntu-linux:LIBUSBSIO?tid=vanLIBUSBSIO
.. _crypto: api/crypto.html
.. _usb_device_identification: usage/usb.html
.. _pfr: apps/pfr.html
.. _migration guide: migration_guide.html

=============
Release Notes
=============

------------------------
3.0.0 - future release
------------------------

**Backwards incompatible**

* BD file support for HAB will be dropped. Only the yaml configuration files will be supported. The conversion from BD file to yaml will be available
* The obscure way of determination of private key file path from certificate in HAB path will be dropped. The public key will need to be specified explicitly
* The family will be mandatory for most tools in SPSDK
* The family option will be moved in most tools to sub-commands
* Complete redesign handling of configuration files through all SPSDK
* All backward compatibility code will be removed (deprecated commands and configurations)
* The definition of signing local key and signature provider definition in configuration will be implemented into one configuration record
* All data in database will be unified under one style (utility/registers.py)
* The configuration option on CLI will be extended by new -oc/--override-config to override any configuration in CLI
* SmartCard Trust Provisioning has been discontinued. Associated aplications (tphost, tpconfig) will be removed.

------------------------
2.6.0 (7-February-2025)
------------------------

**New features**

* :ref:`el2go-host`:
    - support iMX8ULP
    - add possibility to save OEM app config
* :ref:`lpcprog`:
    - support set CRP in lpcprog
    - add optional parameter to repeat the command several times if fails
* :ref:`nxpimage`:
    - support BCA and FCF configuration for mcxcxxx
* support mcxw23x
* support i.MX943
* implement Key Import signed message
* add support for RSA in DAT on RT118x

**Bugfixes**

* :ref:`el2go-host`:
    - fix loading item yaml configuration
* :ref:`nxpimage`:
    - fix XMCD data for mimxrt798s
    - fix invalid scramble mechanism in OTFAD
* :ref:`nxpmemcfg`:
    - fix wrong dict access

------------------------
2.5.0 (20-December-2024)
------------------------

**New features**

* :ref:`nxpdevscan`:
    - add timeout option
* :ref:`el2go-host`:
    - enablement on i.MX 93
* support i.MX RT735S and i.MX RT758S
* support i.MX RT1043 and i.MX RT1046
* support mcxa13x variants
* support Python 3.13
* drop pyocd requirement and replace by spsdk-mcu-link and spsdk-pyocd
* support kw47xx and mcxw72x devices
* add loading of OTPS-encoded public keys
* add nxpfuses tool for handling operations with fuses

**Bugfixes**

* :ref:`nxpimage`:
    - fix encryption in OTFAD
    - fix bootableimage creation with just one bootable image
* :ref:`nxpdevscan`:
    - fix filtering the correct serial port devices on macOS

**Known issues**

* :ref:`nxpdebugmbox`:
    - interface mcu-link is not working on Ubuntu 24.04

------------------------
2.4.0 (15-November-2024)
------------------------

**New features**

* :ref:`el2go-host`:
    - implement parallel download of Secure Objects using database
    - speed up repeated calls to EL2GO server
    - allow to specify scope of Secure Objects to download
* :ref:`nxpdebugmbox`:
    - support halt, resume commands
    - AHB access test address remove as an option and move into database
    - support for block memory transfer over debug probes
* :ref:`nxpmemcfg`:
    - add support for RT700

**Bugfixes**

* :ref:`el2go-host`:
    - fix memory buffer used for data exchange for KW45
* :ref:`nxpimage`:
    - allow to parse AHAB image with empty image hash for rt118x

------------------------
2.3.0 (11-October-2024)
------------------------

**ANNOUNCEMENT**

Current version introduces breaking changes, which are described in details in `migration guide`_.

**New features**

* :ref:`blhost`:
    - support nIRQ pin feature
* :ref:`el2go-host`:
    - unify subcommands for RW61x
    - add get-otp-binary command
    - add UUID harvesting
    - add default handler to unknown errors while assigning device to a group
    - add checker for max amount of Secure Objects and their size
    - add Remote Database for Secure Objects for Azurewave
    - add close_device to blhost; display response of RW TPFW responses
    - implement database storage for UUIDs harvesting
    - erase CMPA in EdgeLock2GO indirect flow
* :ref:`lpcprog`:
    - add programmer for LPC8xx parts
* :ref:`nxpcrypto`:
    - add subcommand for creating PKI tree
* :ref:`nxpdebugmbox`:
    - support for MX95 revision A0/A1/B0 (PQC support)
* :ref:`nxpdevhsm`:
    - add execute command for mcxn9xx
    - allow SB files without loading the wrapped CUST_MK_SK
    - implement oem duk certificate provisioning
* :ref:`nxpdice`:
    - add nxpdice application
* :ref:`nxpele`:
    - support nxpele over fastboot
* :ref:`nxpimage`:
    - support AHAB version 2
    - add verificator to bootable image
    - support linux image in bootable image
    - add ahab sign command for signing existing AHAB images
* :ref:`nxpmemcfg`:
    - add blhost-script option for exporting configuration for secure address
* :ref:`nxpuuu`:
    - new tool based on the UUU (Universal Update Utility), add capability to deploy images to i.MX MPU targets
* :ref:`nxpwpc`:
    - add special handler when pre-CSR are are empty
* :ref:`tphost`/:ref:`tpconfig`:
    - implement lightweight Chain-of-Trust checker for DevCert located in the device
* support MCXC series (blhost)
* support RT7xx
* support MCXN23x, MCXN9xx, KW45xx EL2Go
* support MCXW71 and its variants

**Bugfixes**

* :ref:`el2go-host`:
    - fix general error when database has no blob
    - fix revision in configuration
* :ref:`nxpdebugmbox`:
    - fix get-crp command for mcxa series
    - fix template for famode-image
    - fix dat for RT1180
    - fix template for RT1180
* :ref:`nxpele`:
    - fix get-info details
* :ref:`nxpimage`:
    - fix flag in AHAB
    - fix plain MBI for NHS52sxx
    - fix trustzone for NHS52Sxx
    - remove header form XMCD segment
* `pfr`_:
    - fix erase-cmpa for mcxa series
* :ref:`shadowregs`:
    - fix fuses-script
    - fix loading shadow registers on RW61x

---------------------
2.2.1 (26-July-2024)
---------------------

**Bugfixes**

* :ref:`ifr`:
    - fix read command
* :ref:`nxpimage`:
    - fix parsing bootable image without specified memory type
    - fix plain mbi for NHS52sxx
* :ref:`nxpwpc`:
    - fix unavailable item

--------------------
2.2.0 (7-June-2024)
--------------------

**ANNOUNCEMENT**

Current version introduces breaking changes, which are described in details in `migration guide`_.

**New features**

* :ref:`blhost`:
    - add can interface
* :ref:`el2go-host`:
    - support for mwct2x12, mwct2xd2
* :ref:`ifr`:
    - add option to configure sector 2
* :ref:`nxpdebugmbox`:
    - add family and revision info into DAC config file
* :ref:`nxpdevhsm`:
    - commands limited based on specific devices capabilities
* :ref:`nxpele`:
    - add fuses script
* :ref:`nxpimage`:
    - add support for RAW image
    - add re-sign subcommand to ahab
    - support parsing FCB block with swapped bytes
    - support MBI CRC for mwct2x12, mwct2xd2, mc56f818xx, mc56f817xx
    - support BinaryImage in MBI export
    - support i.MX 95 unsigned build image
* :ref:`nxpwpc`:
    - add correlation-id into REST request
* drop support for Python 3.8
* support NHS52Sxx, mcxw71xx
* support RW61x EL2Go
* P&E Micro and J-Link as separate plugins
* all options in sub-commands case-insensitive

**Bugfixes**

* :ref:`nxpdebugmbox`:
    - fix debug authentication on NHS52Sxx
    - fix generation of DC config file
    - fix dac response length on kw45xx
* :ref:`nxpele`:
    - fix timeout
    - fix verify image for i.mx93
    - fix failure in communication with uboot
* :ref:`nxpimage`:
    - fix signed-msg incorrect signature
    - fix wrong offset in FCB
    - fix xmcd generation
    - fix mbi export
    - fix ahab with invalid SRK
    - fix bootable-image for RW61x
    - fix mbi config for kw45xx
    - fix bootable-image with dynamic offset segments
    - fix inconsistent core ID in parser and export
* `pfr`_:
    - fix generate-binary argument position
    - fix generating cmpa template for mcxa1xx
    - fix default cmpa page for mcxa1xx
* :ref:`shadowregs`:
    - fix shadow registers on RW61x
    - fix loadconfig command

----------------------
2.1.1 (27-March-2024)
----------------------

**New features**

* :ref:`nxpcrypto`:
    - add RSA-PSS support
* :ref:`nxpdevhsm`:
    - support external devhsm provisioning

**Bugfixes**

* :ref:`dk6prog`:
    - fix DK6 operations
* :ref:`nxpdevhsm`:
    - fix buffer address MC56
* :ref:`nxpele`:
    - fix write fuse
* :ref:`nxpimage`:
    - add advanced params setting to configurations (padding, keys, timestamp, etc.)
    - fix manifest hash digest KW45/K32W1

------------------------
2.1.0 (2-February-2024)
------------------------

**New features**

* :ref:`nxpcrypto`:
    - add signing commands (create, verify)
* :ref:`nxpdebugmbox`:
    - add subcommands for Fault Analysis Mode (export, parse, get-templates)
    - add printing the result of auth command
    - add dedicated plugin system
* :ref:`nxpele`:
    - U-BOOT interface
    - add commit command
    - add commands related to release-container
* :ref:`nxpimage`:
    - enable IEE encryption for RT1180
    - add key exchange signed message
    - add signature provider for RT1xxx
* support mcxn23x
* deployment of new database
* EL2GO mockup for S32K WPC
* introduce memory configuration tool

**Bugfixes**

* :ref:`nxpele`:
    - fix get-trng state command
* :ref:`nxpimage`:
    - fix cmpa template
    - fix parsing ahab image for i.MX95
    - fix xmcd export command
    - fix certificate block as binary file
    - fix sb21 get-template command
* :ref:`nxpmemcfg`:
    - fix export command
* `pfr`_:
    - fix pfr generate command
* :ref:`shadowregs`:
    - fix default family parameter

------------------------
2.0.1 (15-December-2023)
------------------------

**Bugfixes**

* :ref:`nxpele`:
    - remove temporary file
* :ref:`nxpdebugmbox`:
    - fix test memory AP address
* :ref:`nxpimage`:
    - fix detection of input file for FCB in bootable image
    - fix IEE encryption for RT1180
    - fix signed MBI for Anguilla Nano
    - fix SB21 export with yaml config
* :ref:`shadowregs`:
    - fix behavior of the RKTH registers
    - fix invalid names of CRC field in database
* fix setting a register value as raw value when loading from configuration

-----------------------
2.0.0 (13-October-2023)
-----------------------

**ANNOUNCEMENT**

Current version introduces breaking changes, which are described in details in `migration guide`_.

**New features**

* :ref:`blhost`:
    - dedicated plugin system
    - check of written data length in USB Interface
* :ref:`nxpcrypto`:
    - remove dependency on PyCryptodome
    - add rot command for calculating RoT hash
* :ref:`nxpimage`:
    - distinguish between fw version and image version
    - support YAML configuration for HAB
    - support build RT11xx image with ECC keys
    - support OSCCA
    - support AHAB NAND
    - implement HTTP Proxy Signature Provider
    - signature provider for OSCCA
    - add validation of signature in AHAB
    - support OTFAD for RT1010
    - export HAB from yaml config in bootable image
    - revision of offsets in AHAB container
    - command filter in SB 2.1 based on family
    - refactor memory types for mbi
    - add to AHAB key identifier for encrypted images
* `pfr`_/:ref:`ifr`:
    - remove devices subcommand
* :ref:`sdpshost`:
    - connection support for iMX91 and iMX95
* :ref:`shadowregs`:
    - unify endianness
* tool for converting JSON configuration into YAML with comments
* support mcxa1xx
* unify naming: RKTH/RKHT
* remove nxpkeygen and nxpcertgen apps, replaced by :ref:`nxpcrypto`
* remove elftosb app, replaced by :ref:`nxpcrypto`
* positional arguments replaced by options for all parameters with an exception to :ref:`blhost`, :ref:`sdphost` and :ref:`dk6prog`
* remove backward compatibility with command get-cfg-template, replaced fully with get-template(s)
* unify family name within all modules
* remove lpc55xx from family names

**Bugfixes**

* :ref:`blhost`:
    - fix error of SPI connection
* :ref:`nxpdevhsm`:
    - add missing sdio in generate command
* :ref:`nxpele`:
    - fix generate-keyblob IEE
    - fix issue with get-info command
* :ref:`nxpimage`:
    - fix certificate block in AHAB
    - fix signature in AHAB
    - fix some commands for SB21
    - fix non generated keys for AHAB parse
    - fix RAM images for LPC55Sxx
    - fix MBI signed for xip for MCXN9xx
    - fix sb21 export yaml errors
    - fix OTFAD with DUK
    - fix wrong core ID in parse for iMX93
    - fix binary certificate block for MBI
    - fix manifest for mcxn9xx
    - fix bootable image merge
    - fix in MBI configurations
    - fix missing parameters in MBI config in bootable-image parse
    - fix sb21 file generation without SBKEK
    - update list of supported MBI images for mcxn9xx

---------------------
1.11.0 (7-July-2023)
---------------------

**ANNOUNCEMENT**

Next version of spsdk (2.0) will introduce breaking changes:

* elftosb will be replaced by nxpimage
* nxpcertgen and nxpkeygen will be replaced by nxpcrypto
* select appropriate family will be done using: -f/--family parameter
* move towards options for all parameters with an exception to BLHost
* removal of crypto backends
* extend dedicated spsdk.crypto module - serve as the de-facto backend of SPSDK
* module level imports via init files

**New features**

* :ref:`nxpimage`:
    - enable signature providers for AHAB image and signed messages
    - add support for rt104x in bootable-image
* :ref:`tphost`/:ref:`tpconfig`:
    - add possibility to check TP_RESPONSE only with NXP_PROD raw binary key
* add support for mcxn9xx
* add API for FuseLockedStatus
* possibility to declare private keys with passphrase in signature provider config
* add checking of written data length in usb interface
* add support for dk6 tools

**Bugfixes**

* :ref:`nxpimage`:
* nxpimage:
    - fix offset on NAND memory in AHAB image
* fix plugin error for signature Provider for sb21

---------------------
1.10.2 (7-July-2023)
---------------------

**New features**

* :ref:`tphost`/:ref:`tpconfig`:
    - add support for LPC55S3x
* :ref:`nxpimage`:
    - add possibility to define multiple regions in OTFAD in one data blob

---------------------
1.10.1 (26-May-2023)
---------------------

**New features**

* :ref:`nxpimage`:
    - support encrypted image hab
    - support for RT11xx and RT10xx
    - improve OTFAD/IEE names generation
* add API to retrieve info about fuses

**Bugfixes**

* :ref:`nxpimage`:
    - fix XMCD load_from_config
    - fix IEE template
* fix circular dependency in signature provider import
* fix issue with loading keys as INT
* not enable logging when spsdk is used as a library

-----------------------
1.10.0 (5-April-2023)
-----------------------

**New features**

* :ref:`blhost`:
    - add new command: ele_message
* :ref:`nxpdebugmbox`:
    - add command: read UUID from device
    - update PyOCD to latest version to support MCU LINK FW v3, implementing CMSIS-DAP v2.1
* :ref:`nxpdevhsm`:
    - USER_PCK rename to CUST_MK_SK
* :ref:`nxpimage`:
    - add subcommand group for generate and parse certificate block
    - replace private key to signature provider in master boot image
    - OTFAD support for RT1170
* :ref:`ifr`:
    -  add commands read/write
* `pfr`_:
    - add CMPA erase command

**Bugfixes**

* :ref:`nxpdebugmbox`:
    - fix AP selection issue for PyOCD and PEMICRO
    - fix DAC verification when there is only 1 root key
* :ref:`nxpimage`:
    - fix MBI issue with HMAC
* :ref:`shadowregs`:
    - fix endianness for OTP MASTER KEY
* drop support for Python 3.7

-----------------------
1.9.1 (17-March-2023)
-----------------------

**New features**

* :ref:`nxpdevhsm`:
    - split reset option in nxpdevhsm into two; disable init reset by default

**Bugfixes**

* :ref:`nxpdebugmbox`:
    - fix Linux error on PyOCD
    - fix PyOCD and PEmicro connection for kw45xx and k32w1xx
* :ref:`nxpdevhsm`:
    - fix buffer base address for DevHSM operations
* :ref:`nxpimage`:
    - fix handling exception when the root cert index is wrong
* :ref:`tphost`/:ref:`tpconfig`:
    - Incorrect output in TP PG command in case of an failure

-------------------------
1.9.0 (30-January-2023)
-------------------------

**New features**

* :ref:`nxpdebugmbox`:
    - add check of root of trust hash in dat authentication
    - enable debug authentication protocol on RT1180
* :ref:`nxpdevhsm`:
    - reset target before and after DevHSM SB3 file creation
* :ref:`nxpimage`:
    - XMCD support
    - signed messages support for RT1180
    - add bootable image for RT10xx, RT1180, RT1170, LPC55S3x
    - implement IEE encryption
    - support Memory ID for erase in sb21
    - support Memory ID for enable and load in sb21
    - implement JUMP and JUMP_SP commands in BD file  for SB2.1
    - enable encryption in AHAB container
* :ref:`tphost`/:ref:`tpconfig`:
    - create command for loading ProvFW
    - add command for retrieving TP_RESPONSE without models or smart card
    - smart card reader name hash identification
* debug authentication improvements
* unify memory access cross all debuggers
* replace json file with yml file for TZ
* support for k32w1xx, kw45xx
* improve format of debugging logger


**Bugfixes**

* :ref:`nxpdebugmbox`:
    - remove duplicated option --protocol for gendc command
* :ref:`nxpdevhsm`:
    - fix skipping commands from config file
* :ref:`nxpimage`:
    - fix non working 384/521 ECC keys for signature in AHAB container
    - fix CRC mode in external flash for lpc55s3x
    - failure on start due to boot_image hook definition
* `pfr`_:
    - command line parameter '-t' is duplicated
* :ref:`tphost`/:ref:`tpconfig`:
    - TPhost load-tpfw requires TP device definition
    - OEM ProvFW boot-check incorrectly fails with non-verbose flavor

**Known issues**

* :ref:`nxpdebugmbox`:
    - we do not support CMSIS-DAP version 2 (bulk pipes, https://arm-software.github.io/CMSIS_5/DAP/html/group__DAP__ConfigUSB__gr.html)
      This means sw debuggers such as MCU-Link v3 will not work (nxpdebugmbox will not detect the debugger probe)
      This issue will be resolved in next version of SPSDK

-------------------------
1.8.0 (21-October-2022)
-------------------------

**New features**

* :ref:`nxpimage`:
    - add support for BEE
    - enable OTFAD on RT1180
* `pfr`_:
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
* `pfr`_:
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
* `pfr`_:
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

* `pfr`_:

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

* `pfr`_:

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

  * support for SB 2.1 generation using BD file
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

* `pfr`_: - update CMPA/CFPA registers XML data for LPC55S3x with CRR update

* SPSDK :ref:`Applications`:

  * spsdk applications show help message when no parameter on command line provided
  * improved help messages
  * support Ctrl+C in cmd applications

* replace functional asserts with raising a SPSDK-based exception
* replace all general exception with SPSDK-based exceptions

**Bugfixes**

* :ref:`nxpkeygen` - regenerates a key without --force
* :ref:`elftosb` - unclear error message: No such file or directory: 'None'
* `pfr`_: - duplicated error message: The silicon revision is not specified
* :ref:`nxpdebugmbox` - fix Retry of AP register reads after Chip reset
* :ref:`nxpdebugmbox` - add timeout to never ending loops in spin_read/write methods in Debug mailbox
* :ref:`blhost` - flash-erase-region command doesn't accept the memory_id argument in hex form
* :ref:`elftosb` - using kdkAccessRights = 0 in SB31 is throwing an error in KeyDerivator

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
* :ref:`blhost` - memoryId clamp-down for mapped external memories added
* :ref:`elftosb` - support for SB 2.1 added
* :ref:`elftosb` - basic support for BD configuration file added
* :ref:`nxpdebugmbox` - debug port enabled check added
* :ref:`nxpkeygen` - new sub-command added to nxpkeygen to create a template for configuration YML file for DC keys
* :ref:`nxpkeygen` - new sub-command added to create a template for configuration YML file for DC keys
* `pfr`_: - default JSON config file generation removed, but still accepted as an input. The preferred is the YML configuration format.
* docs - Read The Docs documentation improvements

**Bugfixes**

* wrong DCD size by BootImgRT.parse
* cmdKeyStoreBackupRestore wrong param description
* :ref:`blhost` - typo in McuBootConnectionError exception
* :ref:`blhost` - mcuBoot Uart doesn't close the device after failed ping command
* :ref:`blhost` - assertion error when connection lost during fuses readout
* :ref:`blhost` - sub-command  flash-read-resource fails when the length is not aligned
* `pfr`_: - incorrect keys hash computation for LPC55S3x
* `pfr`_: - wrong LPC55S69 silicon revision
* `pfr`_: - parse does not show PRINCE IV fields
* :ref:`sdphost` - running spdhost --help fails
* :ref:`shadowregs` - bad DEV_TEST_BIT in shadow registers

---------------------
1.3.1 (29-March-2021)
---------------------

* `pfr`_: - configuration template supports YAML with description, backward compatibility with JSON ensured
* `pfr`_: - API change: "keys" parameter has been moved from __init__ to export
* `pfr`_: - sub-commands renamed:
  * user-config -> get-cfg-template
  * parse -> parse-binary
  * generate -> generate-binary
* :ref:`blhost` - allow key names for key-provisioning commands
* :ref:`blhost` - support for RT1170, RT1160
* :ref:`shadowregs` - shadow registers tool is now top-level module
* :ref:`blhost` - fix baud rate parameter
* `pfr`_: - fix in data for LPC55S6x, LPC55S1x, LPC55S0x
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
* `pfr`_: - added CMAC-based seal
* `pfr`_: - load Root of Trust from elf2sb configuration file

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
* `pfr`_: - CLI utility for generating and parsing Protected Flash Regions - CMPA and CFPA regions
