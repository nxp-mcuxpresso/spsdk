===============
Bootable Image
===============

Bootable image is primarily intended for booting from the external memories, for other use cases refer to the :ref:`Executable Images`.
Bootable image encapsulates the executable application images and adds additional data processed by the bootROM that are needed for boot, like for example configuration of the flash memories.
The bootable image might consists of:

- Keyblob for data decryption
- Keystore
- FlexSPI Configuration Block (FCB)
- External Memory Configuration Data (XMCD)
- Device Configuration Data (DCD) -  The DCD contains configuration data to configure any peripherals.
- Application Image - It might contain plain application image, HAB, AHAB image or MBI.


.. toctree::
    :caption: Sub images
    :maxdepth: 1

    fcb
    xmcd