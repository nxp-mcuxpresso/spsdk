
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

nxpimage: ``nxpimage mbi export <path to config file>``

Sample configuration for LPC55s6x plain signed XIP image. Other sample configurations might be obtained with the *get-templates* sub-command.

.. code-block:: yaml

    # ===========  Master Boot Image Configuration template for lpc55s6x, Plain Signed XIP Image.  ===========
    #
    #  == Basic Settings ==
    #
    family: lpc55s6x  # MCU family., MCU family name.
    outputImageExecutionTarget: xip # Application target., Definition if application is Execute in Place(XiP) or loaded to RAM during reset sequence.
    outputImageAuthenticationType: signed # Type of boot image authentication., Specification of final master boot image authentication.
    masterBootOutputFile: my_mbi.bin # Master Boot Image name., The file for Master Boot Image result file.
    inputImageFile: my_application.bin # Plain application image., The input application image to by modified to Master Boot Image.
    #
    #  == Trust Zone Settings ==
    #
    enableTrustZone: false # TrustZone enable option, If not specified, the Trust zone is disabled.
    trustZonePresetFile: my_tz_custom.yaml # TrustZone Customization file, If not specified, but TrustZone is enabled(enableTrustZone) the default values are used.
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


Supported devices for MBI
==========================

NXPIMAGE support devices from LPC55xx family (*LPC55S0x, LPC55S1x, LPC55S2x, LPC552x, LPC55S6x*), *RT5xx*, *RT6xx*, *LPC55S3x*, *MCXN9xx* and *RW61x*.
Supported execution targets are: *XIP (Execute in place) and Load to RAM* and image authentication types: *Plain, CRC, Signed, Encrypted and NXP Signed*.

The following table shows the supported image types for each device,
it either shows "N/A" if the configuration is not available or respective class that will be used for image creation.

*Target* in the table represents *outputImageExecutionTarget* in the configuration file and *authentication* in the table represents *outputImageAuthenticationType*.

.. include:: ../_prebuild/table.inc

.. note:: For LPC55xx (except for the LPC55S36 with external flash) the load-to-RAM images are intended only for recovery boot from 1-bit SPI flash.


Supported configuration options
================================

Refer to the documentation below for the supported configuration options for each image type.
Please note that the *outputImageExecutionTarget* and *outputImageAuthenticationType* must be filled in addition to the basic settings according to the table with supported devices.


.. code-block:: yaml

    outputImageExecutionTarget: xip # Application target., Definition if application is Execute in Place(XiP) or loaded to RAM during reset sequence.
    outputImageAuthenticationType: signed # Type of boot image authentication., Specification of final master boot image authentication.


.. include:: ../_prebuild/schemas.inc
   :parser: myst_parser.sphinx_
