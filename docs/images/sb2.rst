------------------
Secure Binary 2.1
------------------

Version 2.1 added support for digital signatures.

The SB 2.0 and 2.1 file format also uses AES encryption for confidentiality and HMAC for
extending trust from the signed part of the SB file to the command and data part of the SB
file. These two keys (AES decrypt key and HMAC key) are wrapped in the RFC3394 key
blob, for which the key wrapping key is the SBKEK key

SB2 generation using YAML file
================================

Since version 2.0 it is possible to generate SB file using the YAML configuration in the similar manner as SB 3.1.

Example of use:

1. Generate template first

``nxpimage sb21 get-template -o "sb2_config.yaml``

2. Fill the configuration and export to binary

``nxpimage sb21 export-yaml "sb2_config.yaml``


SB2 generation using BD file
=============================

The tool uses an input command file to control the sequence of bootloader commands present in the output file.
This command file is called a "boot descriptor file" or BD file for short.
The image location is stated in the "sources" section of the .bd file.
The SB key in the text file is used for encryption with the *nxpimage* command line tool.

It is possible to use NXP elftosb tool user guide located `here <https://www.nxp.com/docs/en/user-guide/MBOOTELFTOSBUG.pdf>`_.

.. note:: Please note that some functionality described in the UG may not be supported in SPSDK SB2 parser.

For more information about the Secure boot setup for LPC55Sxx family follow the `AN12283
<https://www.nxp.com/docs/en/application-note/AN12283.pdf>`_.

Supported Commands

.. include:: ../_prebuild/table_sb21.inc
   :parser: myst_parser.sphinx_


Example of SB2 generation for 4 root keys

nxpimage: ``nxpimage sb21 export -k "sbkek.txt" -c "commandFile.bd" -o "output.sb2" -s private_key_1_2048.pem
-S certificate_1_2048.der.crt -R certificate_1_2048.der.crt -R
certificate_2_2048.der.crt -R certificate_3_2048.der.crt -R certificate_4_2048.der.crt -h "RHKT.bin"
"input.bin"``


Created SB2 file can be loaded into the device using blhost *receive-sb-file* command.
``blhost -p COMxx receive-sb-file <path to the secured binary(.sb2)>``


Description of how to use BD file is in bellow chapter.

.. include:: ../usage/elf2sb.md
   :parser: myst_parser.sphinx_
