Supported devices for MBI
==========================

Supported execution targets are: *XIP (Execute in place) and Load to RAM* and image authentication types: *Plain, CRC, Signed, Encrypted and NXP Signed*.

The following table shows the supported image types for each device.

*Target* in the table represents *outputImageExecutionTarget* in the configuration file and *authentication* in the table represents *outputImageAuthenticationType*.

.. include:: ../_prebuild/mbi_table.inc

.. note:: For LPC55xx (except for the LPC55S36 with external flash), MCXN9xx and MCXN23x the load-to-RAM images are intended only for recovery boot from 1-bit SPI flash.


Implementation details
======================

To handle the small differences between the MBI types. Mixin classes were used to define the common parts of the MBI.
This definition of required mixins is stored in database for each family of devices. When you click on the supported MBI type in the table above, you will be pointed to the documentation of the specific MBI type.
Naming convention for each MBI type is used here just for documentation purposes. For example: "MBI-A-IV-I-TZM-LA-EATZ-ECS" contains first letters of mixins used in the MBI, like App, ImageVersion, IVT, TrustZoneMandatory and others...

If you want to create MBI class directly you might use *create_mbi_class* function. The function takes two arguments, the first one is the MBI type and the second one is the device family. The method returns the class that can be used to create MBI image.

.. code-block:: python

    from spsdk.image.mbi.mbi import create_mbi_class

    MbiClass = create_mbi_class("plain", "k32w1xx")


Exporting the image is done in six steps.

- Validating the input data by calling the *validate* method.
- Collecting the data by calling the *collect_data* method.
- Optionally encrypting the image by calling the *encrypt* method.
- Optionally do post encrypt update by calling the *post_encrypt* method.
- Optionally sign the image by calling the *sign* method.
- Finalize the image by calling the *finalize* method.


Supported configuration options
================================

Refer to the documentation below for the supported configuration options for each image type.
Please note that the *outputImageExecutionTarget* and *outputImageAuthenticationType* must be filled in addition to the basic settings according to the table with supported devices.


.. code-block:: yaml

    outputImageExecutionTarget: xip # Application target., Definition if application is Execute in Place(XiP) or loaded to RAM during reset sequence.
    outputImageAuthenticationType: signed # Type of boot image authentication., Specification of final master boot image authentication.


.. include:: ../_prebuild/schemas.inc
   :parser: myst_parser.sphinx_
