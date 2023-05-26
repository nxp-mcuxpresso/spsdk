===============
Bootable Image
===============

Bootable image encapsulates the executable application images and adds additional data processed by the bootROM that are needed for boot, like for example configuration of the flash memories.
The bootable image might consists of:

- Keyblob for data decryption
- Keystore
- FlexSPI Configuration Block (FCB)
- External Memory Configuration Data (XMCD)
- Device Configuration Data (DCD) -  The DCD contains configuration data to configure any peripherals.
- Application Image - It might contain plain application image or HAB or AHAB image.


.. toctree::
    :caption: Sub images
    :maxdepth: 1

    fcb
    xmcd

-------------------------------------------
List of supported devices and memory types
-------------------------------------------

.. include:: ../_prebuild/table_bootable.inc
   :parser: myst_parser.sphinx_

.. include:: ../_prebuild/bootable_schemas.inc
   :parser: myst_parser.sphinx_
