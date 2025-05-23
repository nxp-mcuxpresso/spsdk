===============
Migration guide
===============

Changes in SPSDK 3.0
====================


CLI Changes
-----------

general
^^^^^^^
* The ``--plugin`` command line option has been removed from all CLI tools. If you were using the ``--plugin`` option with any SPSDK command line tools, you need to properly install your plugin as a Python package with proper entry points.
* Obsolete device names have been kept in the code as abbreviation names
* All applications that support the ``--config`` option now also support the ``-oc/--override-config`` option. This allows you to override specific values from the configuration file via command line without modifying the original file. For example: ``-oc key1=value1 -oc key2=value2``

nxpcrypto
^^^^^^^^^
* Removed ``nxpcertgen`` application (all functionality is now available in ``nxpcrypto`` application)
* The legacy options ``-k/--private-key`` and ``-sp/--signature-provider`` have been consolidated and replaced with a single, unified option ``-s/--signer`` to simplify the signature configuration interface

nxpdebugmbox
^^^^^^^^^^^^
* All commands have been moved to separated groups with clearer organization:
  * ``cmd`` - For basic debug mailbox commands (start, exit, erase, etc.)
  * ``dat`` - For debug authentication related commands
  * ``mem-tool`` - For memory operations (read-memory, write-memory, test-connection)
  * ``tool`` - For utility commands (reset, get-uuid, halt, resume)
  * ``famode-image`` - For fault analysis mode image operations

* The ``--family`` parameter has been moved from the root command to individual command groups:
  * Each command group now requires specifying the family parameter at the appropriate level
  * The family parameter is now handled through the ``FamilyRevision`` class for better device control

* The test address is now automatically derived from the family parameter

nxpimage
^^^^^^^^
* In ``nxpimage ahab`` configuration, the deprecated 'image_type' key has been removed and replaced by 'target_memory'
* The ``nxpimage bee`` now supports multiple input data blobs, removed ``input_binary`` and ``base_address`` parameters
* The ``merge`` commands in ``nxpimage bootable-image`` and ``nxpimage binary-image`` have been renamed to ``export``
* In ``nxpimage cert-block`` configuration, the deprecated key 'mainCertChainId' has been removed, replaced by 'mainRootCertId'
* The ``nxpimage hab export`` command changed its parameter structure: ``-c/--command`` option and ``external`` arguments have been replaced with ``--config`` option using the standard config approach
* The ``nxpimage hab parse`` command now requires a mandatory ``--family`` parameter to correctly interpret HAB container binary data
* In ``nxpimage sb31``, the Load command configuration has been simplified. The key authentication has been removed (instead, use already implemented commands: LoadhashLocking and LoadCmac)
* In ``nxpimage sb31``, the input data values have been simplified from value/values/file into one data parameter (data accepts all previously used ways of data definition)

pfr/ifr
^^^^^^^
* In ``ifr`` application, the unused ``--full`` option is removed from the ``get-template`` command
* The unused options ``--show-calc`` have been removed from Parse/Read command
* The unused options ``--calc-inverse`` have been removed from Generate binary command
* The ``generate-binary`` command has been renamed to ``export`` to unify interface with rest of SPSDK
* The ``parse-binary`` command has been renamed to ``parse`` to unify interface with rest of SPSDK
* The ``ifr`` application has been moved into ``pfr``
* In ``pfr`` and ``ifr``, backward compatibility for very old configuration files with 'description:' section has been removed, replaced by simple family/revision/type header keys
* The BD file for SB2.1 must now contain 'family' and optionally 'revision' in the 'options' block


Removed Applications
--------------------

The following Trust Provisioning applications have been removed in SPSDK 3.0:

* **tphost** - Trust Provisioning host application that was used for secure provisioning of target MCUs
* **tpconfig** - Trust Provisioning configuration application for configuring trusted devices

These applications previously provided functionality for:

* Provisioning target MCUs
* Loading provisioning firmware
* Verifying audit logs and certificates
* Chain-of-Trust validation
* Smart card configuration and sealing

If you were using these applications, consult the SPSDK documentation for information about alternative approaches or replacement functionality.

API changes
-----------

general
^^^^^^^
* ``serialize`` and ``de-serialize`` methods have been renamed to ``export`` and ``parse``
* ``to-bytes`` has been renamed to ``export``
* Added ``post_export`` method to base class to handle exporting of fuse scripts, keyblobs, and other files (used in AHAB, Bootable Image, IEE, and OTFAD)
* In ``SignatureProvider``, the ``try_to_verify_public_key`` method has been removed, as the same functionality is available in the ``SignatureProvider`` class
* Introduction of a single standardized signer key for all signature-related configurations

   +--------------------------+-----------------------------------------------+---------------+
   | Component                | Legacy Options Removed                        | Replaced With |
   +==========================+===============================================+===============+
   | **Certificate Block V1** | ``mainRootCertPrivateKeyFile``                | ``signer``    |
   |                          | ``signPrivateKey``                            |               |
   |                          | ``signProvider``                              |               |
   +--------------------------+-----------------------------------------------+---------------+
   | **Certificate Block V21**| ``signPrivateKey``                            | ``signer``    |
   |                          | ``mainRootCertPrivateKeyFile``                |               |
   |                          | ``signProvider``                              |               |
   +--------------------------+-----------------------------------------------+---------------+
   | **Certificate Block Vx** | ``signPrivateKey``                            | ``signer``    |
   |                          | ``mainRootCertPrivateKeyFile``                |               |
   |                          | ``signProvider``                              |               |
   +--------------------------+-----------------------------------------------+---------------+
   | **Masterboot image**     | ``signPrivateKey``                            | ``signer``    |
   |                          | ``mainRootCertPrivateKeyFile``                |               |
   |                          | ``signProvider``                              |               |
   +--------------------------+-----------------------------------------------+---------------+
   | **DAR packet**           | ``sign_provider``                             | ``signer``    |
   |                          | ``dck_private_key``                           |               |
   +--------------------------+-----------------------------------------------+---------------+
   | **Debug Credentials**    | ``sign_provider``                             | ``signer``    |
   |                          | ``rotk``                                      |               |
   +--------------------------+-----------------------------------------------+---------------+
   | **HAB Commands**         | ``AuthenticateCsf_SignProvider``              | ``Signer``    |
   |                          | ``AuthenticateCsf_PrivateKeyFile``            |               |
   |                          | ``AuthenticateData_SignProvider``             |               |
   |                          | ``AuthenticateData_PrivateKeyFile``           |               |
   +--------------------------+-----------------------------------------------+---------------+
   | **AHAB**                 | ``signing_key``                               | ``signer``    |
   |                          | ``signature_provider``                        |               |
   |                          | ``signing_key_0``                             | ``signer_0``  |
   |                          | ``signature_provider_0``                      |               |
   |                          | ``signing_key_1``                             | ``signer_1``  |
   |                          | ``signature_provider_1``                      |               |
   |                          | ``signing_key_#2``                            | ``signer_#2`` |
   |                          | ``signature_provider_#2``                     |               |
   +--------------------------+-----------------------------------------------+---------------+
   | **SB2 Images**           | ``signPrivateKey``                            | ``signer``    |
   |                          | ``mainCertPrivateKeyFile``                    |               |
   |                          | ``signProvider``                              |               |
   +--------------------------+-----------------------------------------------+---------------+
   | **SB31 Images**          | ``signPrivateKey``                            | ``signer``    |
   |                          | ``mainRootCertPrivateKeyFile``                |               |
   |                          | ``signProvider``                              |               |
   +--------------------------+-----------------------------------------------+---------------+
   | **SBx Images**           | ``signingCertificatePrivateKeyFile``          | ``signer``    |
   |                          | ``signProvider``                              |               |
   +--------------------------+-----------------------------------------------+---------------+

blhost
^^^^^^^^
* Removed ``decode_status_code`` method, replaced by ``stringify_status_code``

debug probes
^^^^^^^^^^^^
* Renamed ``DebugProbeLocal`` class to ``DebugProbeCoreSightOnly``

nxpimage
^^^^^^^^
* The `nxpimage.py` file has been split into smaller, more maintainable application files under the `spsdk/apps/nxpimage/` directory. Each image type functionality has been moved to its own dedicated module.

nxpimage hab
^^^^^^^^^^^^
* Replaced ``HabContainer`` class with new ``HabImage`` class throughout the codebase
* Completely changed how segments are processed and exported, no longer uses ``SEGMENTS_MAPPING`` to look up segments by name
* The new HAB implementation uses a standardized configuration system that requires explicit specification of key locations(or signature providers). The private key path determination based on certificate file paths is not possible anymore.
* The generic segment implementations previously contained in ``spsdk/image/segments.py`` have been split into dedicated, purpose-specific modules in the ``spsdk/image/hab`` package.
* The ``spsdk/image/commands.py`` file has been significantly refactored with it's functionality distributed across multiple specialized modules in the ``spsdk/image/hab/commands`` package


Changes in SPSDK 2.5
====================

API changes
-----------

* SPSDK will no longer contain code for specific debuggers (spsdk/debuggers) Debuggers will be installed via plugins

  * the default installation of SPSDK will install PyOCD and MCU-Link
  * user may install/uninstall support for additional debuggers. (NXP offers some debugger plugins via `spsdk plugins <https://github.com/nxp-mcuxpresso/spsdk_plugins>`_)



Changes in SPSDK 2.3
====================

CLI changes
------------

* The option -f/--family was added to nxpdebugmbox main menu.

* Created group of commands for working with raw Debug MailBox commands: erase, erase-one-sector, exit, famode, get-crp, ispmode, start, start-debug-session, token-auth, write-to-flash commands.

* Created group of commands for working with Debug Authentication Procedure: auth, dc.

* Created command get-families, which shows the full families information for nxpdebugmbox and and its obsolete predecessor families names.

* Created group of commands for working with target memory over debug probe: read-memory, test-connection, write-memory.

* Created group of commands for working with various tools over debug probe: get-uuid, reset.

* Refactored device database to make it compatible across the whole MCUXpresso ecosystem (SDK, IDE, SEC tool, Config Tools, etc.). New family (device) names was introduced for example mx93 -> mimx9352.

* Renamed el2go application to el2go-host

API changes
------------

* Introduced new format of AHAB container version 2 that is default on i.MX95 B0 when the chip revision "latest" is selected.
  To use the AHAB version 1, you can either specify it in the configuration file as "container_version" field, which is hidden in template or you can specify the chip revision as A0 or A1.

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
