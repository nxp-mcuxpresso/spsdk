===============
Migration guide
===============

Changes in SPSDK 2.2
====================

CLI changes
------------

* Codecheck was moved to separate repository and is now installed as part of developers requirements.


API changes
------------

* Dropped support for Python 3.8

* AHAB container module (ahab/ahab_container.py) was refactored. Concept of parent classes was removed and the module was split into several smaller modules containing classes for each AHAB subimage type.

* AHAB extended image array entries were introduced. This helps with creating specific AHAB images like U-Boot. See the examples for more information.

* MBI manifest mixin class was redesigned and renamed to reflect the actual purpose.

* All XML data in database were converted to JSON format. This change is transparent for the user.

* J-Link and PE Micro debugger interfaces support were moved to SPSDK plugins repository. J-Link is still supported by PyOCD in base installation.

* List of VID/PIDs of devices were moved to database from the code.

* Fuses definition was moved to database from the code. New format of fuse definition in DB was introduced.

* Naming of MCX families was clarified - mcxn94x and mcxn54x

* MBI is now using BinaryImage class for image representation, this allow better visualization and verification of image.

Changes in SPSDK 2.0
====================

This guide details the changes and how to change your CLI and code to migrate to SPSDK 2.0.
See the full changelog for more information.

CLI changes
------------


* elftosb replaced by :ref:`nxpimage`

* nxpcertgen and nxpkeygen replaced by :ref:`nxpcrypto`

* The option -d/--device/-dev replaced by -f/--family in order to select appropriate family

* Positional arguments replaced by options for all parameters with an exception to :ref:`blhost`, sdphost and dk6prog. Positional argument for configuration file was replaced by *-c/--configuration* option and unified in all applications. Also output argument was replaced by *-o/--output*. Input binaries in *parse* subcommands are accepted with *-b/--binary* options

* Remove backward compatibility with command get-cfg-template, replaced fully with get-template(s)

* Added possibility to use YAML configurations for SB 2.1 and HAB this is a step towards unified interface for all nxpimage applications.

* Added possibility to choose between value and bitfield in bootable-image sub applications (XMCD, FCB)

* Firmware version and Image version in MBI were clarified. This might break compatibility, because in SPSDK 1.x these values were treated as equal. Image version is used for dual boot feature and firmware version is used for rollback protection.

* The option --use-pkcs8/--no-pkcs8 was removed from :ref:`nxpcrypto` key convert application

Certificate Blocks
-------------------
One of the major changes were done in certificate blocks. Previously the *nxpimage cert-blocks* was intended only for generation of
binary certificate blocks. With SPSDK 2.0 the *nxpimage cert-blocks* must be used with signed Master Boot Images and Secure Binary.
The motivation behind this change is to make one unified way of certificate blocks configuration that could be shared among MBI and Secure Binary and make interfacing with HSM easier.


**Signed MBI and SB 3.1 changes**

* *certBlock*: new property, path to cert-block YAML configuration or binary. Mandatory for signed MBI.

* *Root Keys Settings*: Block has been moved to cert-block configuration.

* *ISK Certificate Settings*:  Block has been moved to cert-block configuration.

* *mainRootCertPrivateKeyFile*, *signingCertificatePrivateKeyFile*: unified to *signPrivateKey* (not compatible change)

* *signProvide*, *iskSignProvider*: unified to signPrivateKey (not compatible change)

In case the ISK is used, the MBI is signed by ISK key, otherwise root key is used.

**Cert Block configuration changes**

* *binaryCertificateBlock*: Removed, user might provide binary to *certBlock* property.

* *signingCertificateFile*: Renamed to iskPublicKey (not compatible change)

* *signingCertificateConstraint*: Renamed to iskCertificateConstraint (not compatible change)

* *signCertData*: Renamed to iskCertData (not compatible change)

* *mainRootCertPrivateKeyFile*, *signingCertificatePrivateKeyFile*: Unified to signPrivateKey (not compatible change)

* *signProvider*, *iskSignProvider*: Unified to signProvider (not compatible change)

ISK certificate is signed by "root" key.


API changes
------------

* Crypto backend was refactored. See the API documentation and examples for more information :ref:`nxpimage`.

* Registers backend was refactored to reflect the actual binary representation and correct endianness.

* Types of XMCD members `mem_type` and `config_type` have changed from string to Enum

* Mboot and SDP interfaces were refactored. Scan functionality was moved to the interface class. See the examples for more details.

* The hash algorithm type is now EnumHashAlgorithm instead of string literal (ie "sha256")

* Deterministic ECC signatures are no longer used.
