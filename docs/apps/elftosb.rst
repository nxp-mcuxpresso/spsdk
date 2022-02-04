====================
User Guide - elftosb
====================

This user guide describes how to use *elftosb* application. *elftosb* is a tool for generating TrustZone,
Master Boot Image and Secure Binary images.

-----------------------
Master Boot Image (MBI)
-----------------------
Master Boot Image can be used directly (e.g. by using *blhost write-memory* command) or it can be used for further processing  (e.g. used as input to Secure Binary image container).
Image is created based on a supplied configuration file, either JSON or YAML is supported.

Example of use
``elftosb –J <path to config file>``

Sample configuration for LPC55s6x plain signed XIP image. Other sample configurations might be obtained with the *-Y* option.

.. code-block:: yaml

    # ===========  Master Boot Image Configuration template for lpc55s6x, Plain Signed XIP Image.  ===========
    #
    #  == Basic Settings ==
    #
    family: lpc55s6x  # MCU family., MCU family name.
    outputImageExecutionTarget: Internal flash (XIP) # Application target., Definition if application is Execute in Place(XiP) or loaded to RAM during reset sequence.
    outputImageAuthenticationType: Signed # Type of boot image authentication., Specification of final master boot image authentication.
    masterBootOutputFile: my_mbi.bin # Master Boot Image name., The file for Master Boot Image result file.
    inputImageFile: my_application.bin # Plain application image., The input application image to by modified to Master Boot Image.
    #
    #  == Trust Zone Settings ==
    #
    enableTrustZone: false # TrustZone enable option, If not specified, the Trust zone is disabled.
    trustZonePresetFile: my_tz_custom.yml # TrustZone Customization file, If not specified, but TrustZone is enabled(enableTrustZone) the default values are used.
    #
    #  == Certificate V2 Settings ==
    #
    mainCertPrivateKeyFile: my_prv_key.pem # Main Certificate private key, Main Certificate private key used to sign certificate
    imageBuildNumber: 0 # Image Build Number, If it's omitted, it will be used 0 as default value.
    rootCertificate0File: my_certificate0.pem # Root Certificate File 0, Root certificate file index 0.
    rootCertificate1File: my_certificate1.pem # Root Certificate File 1, Root certificate file index 1.
    rootCertificate2File: my_certificate2.pem # Root Certificate File 2, Root certificate file index 2.
    rootCertificate3File: my_certificate3.pem # Root Certificate File 3, Root certificate file index 3.
    mainCertChainId: 0 # Main Certificate Index, Index of certificate that is used as a main.
    chainCertificate0File0: chain_certificate0_depth0.pem # Chain certificate 0 for root 0, Chain certificate 0 for root certificate 0
    chainCertificate0File1: chain_certificate0_depth1.pem # Chain certificate 1 for root 0, Chain certificate 1 for root certificate 0
    chainCertificate0File2: chain_certificate0_depth2.pem # Chain certificate 2 for root 0, Chain certificate 2 for root certificate 0
    chainCertificate0File3: chain_certificate0_depth3.pem # Chain certificate 3 for root 0, Chain certificate 3 for root certificate 0
    chainCertificate1File0: chain_certificate1_depth0.pem # Chain certificate 0 for root 1, Chain certificate 0 for root certificate 1
    chainCertificate1File1: chain_certificate1_depth1.pem # Chain certificate 1 for root 1, Chain certificate 1 for root certificate 1
    chainCertificate1File2: chain_certificate1_depth2.pem # Chain certificate 2 for root 1, Chain certificate 2 for root certificate 1
    chainCertificate1File3: chain_certificate1_depth3.pem # Chain certificate 3 for root 1, Chain certificate 3 for root certificate 1
    chainCertificate2File0: chain_certificate2_depth0.pem # Chain certificate 0 for root 2, Chain certificate 0 for root certificate 2
    chainCertificate2File1: chain_certificate2_depth1.pem # Chain certificate 1 for root 2, Chain certificate 1 for root certificate 2
    chainCertificate2File2: chain_certificate2_depth2.pem # Chain certificate 2 for root 2, Chain certificate 2 for root certificate 2
    chainCertificate2File3: chain_certificate2_depth3.pem # Chain certificate 3 for root 2, Chain certificate 3 for root certificate 2
    chainCertificate3File0: chain_certificate3_depth0.pem # Chain certificate 0 for root 3, Chain certificate 0 for root certificate 3
    chainCertificate3File1: chain_certificate3_depth1.pem # Chain certificate 1 for root 3, Chain certificate 1 for root certificate 3
    chainCertificate3File2: chain_certificate3_depth2.pem # Chain certificate 2 for root 3, Chain certificate 2 for root certificate 3
    chainCertificate3File3: chain_certificate3_depth3.pem # Chain certificate 3 for root 3, Chain certificate 3 for root certificate 3

---------------------------------
Supported devices for MBI
---------------------------------
Elftosb support devices from LPC55xx family (*LPC55S0x, LPC55S1x, LPC55S2x, LPC552x, LPC55S6x*), *RT5xx*, *RT6xx* and *LPC55S3x*.
Supported execution targets are: *Internal flash (XIP), External Flash (XIP) and RAM* and image authentication types: *Plain, CRC, Signed and Encrypted*.

The following table shows the supported image types for each device,
it either shows "N/A" if the configuration is not available or respective class that will be used for image creation.

*Target* in the table represents *outputImageExecutionTarget* in the configuration file and *authentication* in the table represents *outputImageAuthenticationType*.

.. include:: table.inc

--------------------------------
Supported configuration options
--------------------------------

Refer to the documentation below for the supported configuration options for each image type.
Please note that the *outputImageExecutionTarget* and *outputImageAuthenticationType* must be filled in addition to the basic settings according to the table with supported devices.


.. code-block:: yaml

    outputImageExecutionTarget: Internal flash (XIP) # Application target., Definition if application is Execute in Place(XiP) or loaded to RAM during reset sequence.
    outputImageAuthenticationType: Signed # Type of boot image authentication., Specification of final master boot image authentication.


.. include:: schemas.inc
   :parser: myst_parser.sphinx_


---------------------------
Secure binary
---------------------------

Secure binary is a binary output file that contains the user's application image along with a series of bootloader commands.
The output file is known as a "Secure Binary" or SB file for short.
These files typically have a .sb extension.

This format has a long history, the latest version is 3.1. (2022).
SPSDK elftosb tool supports SB 2.1 (2.0) and SB 3.1.

Version 2.1 added support for digital signatures.

The SB 2.0 and 2.1 file format also uses AES encryption for confidentiality and HMAC for
extending trust from the signed part of the SB file to the command and data part of the SB
file. These two keys (AES decrypt key and HMAC key) are wrapped in the RFC3394 key
blob, for which the key wrapping key is the SBKEK key


SB2 generation using BD file
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

The tool uses an input command file to control the sequence of bootloader commands present in the output file. This command file is called a "boot descriptor file" or BD file for short.

The image location is stated in the "sources" section of the .bd file. The SB key in the text file is used for encryption with the elftosb command line tool.

Description of how to use BD file is in bellow chapter.

.. toctree::
    :maxdepth: 1

    ../usage/elf2sb

For more information about the Secure boot setup for LPC55Sxx family follow the `AN12283
<https://www.nxp.com/docs/en/application-note/AN12283.pdf>`_.

Example of SB2 generation for 4 root keys

``elftosb -f lpc55xx -k "sbkek.txt" -c "commandFile.bd" -o "output.sb2" -s private_key_1_2048.pem
-S certificate_1_2048.der.crt -R certificate_1_2048.der.crt -R
certificate_2_2048.der.crt -R certificate_3_2048.der.crt -R certificate_4_2048.der.crt -h "RHKT.bin"
"input.bin"``

Created SB2 file can be loaded into the device using blhost *receive-sb-file* command.
``blhost -p COMxx receive-sb-file <path to the secured binary(.sb2)>``

SB 3.1
^^^^^^
SB 3.1 is an evolution of the SB 2 format.
The configuration is done in a similar way as a master boot image by configuration file in YAML or JSON. BD files are no longer used, commands are supplied in the configuration file.

Example of use
``elftosb.exe -j "sb3_config.yaml``

----------------------------
Legacy elftosb documentation
----------------------------

It is possible to use NXP elftosb tool user guide located `here <https://www.nxp.com/docs/en/user-guide/MBOOTELFTOSBUG.pdf>`_.

.. note:: Please note that some functionality described in the UG may not be supported in SPSDK elftosb application.


-----------------------
Command line interface
-----------------------

.. click:: spsdk.apps.elftosb:main
    :prog: elftosb
    :nested: full


