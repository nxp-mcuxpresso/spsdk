
-------------------------
Master Boot Image (MBI)
-------------------------

Master Boot Image can be used directly (e.g. by using *blhost write-memory* command) or it can be used for further processing  (e.g. used as input to Secure Binary image container).
Image is created based on a supplied configuration file, either JSON or YAML is supported.

We can divide divide into two categories based on layout.

* eXecute-In-Place (XIP) images
    * Plain
    * CRC
    * Signed

* Load-to-RAM images
    * Plain
    * CRC
    * Signed images with HMAC signed header. Since load-to-RAM copies the image from untrusted media to on-chip RAM, the length field in header should be authenticated before copy. Hence HMAC signed headers are used.
    * Encrypted (plain header with HMAC + AES-CBC encrypted).

Example of use

nxpimage: ``nxpimage mbi export -c <path to config file>``


Supported devices for MBI
==========================

Supported execution targets are: *XIP (Execute in place) and Load to RAM* and image authentication types: *Plain, CRC, Signed, Encrypted and NXP Signed*.

The following table shows the supported image types for each device.

*Target* in the table represents *outputImageExecutionTarget* in the configuration file and *authentication* in the table represents *outputImageAuthenticationType*.

.. include:: ../_prebuild/mbi_table.inc

.. note:: For LPC55xx (except for the LPC55S36 with external flash), MCXN9xx and MCXN23x the load-to-RAM images are intended only for recovery boot from 1-bit SPI flash.


Supported configuration options
================================

Refer to the documentation below for the supported configuration options for each image type.
Please note that the *outputImageExecutionTarget* and *outputImageAuthenticationType* must be filled in addition to the basic settings according to the table with supported devices.


.. code-block:: yaml

    outputImageExecutionTarget: xip # Application target., Definition if application is Execute in Place(XiP) or loaded to RAM during reset sequence.
    outputImageAuthenticationType: signed # Type of boot image authentication., Specification of final master boot image authentication.


.. include:: ../_prebuild/schemas.inc
   :parser: myst_parser.sphinx_

