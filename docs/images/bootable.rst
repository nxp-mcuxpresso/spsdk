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

Generating Templates
====================

The bootable image configuration template can be generated using the nxpimage tool's ``get-template`` command:

``nxpimage bootable-image get-template -f <family> -m <memory_type> -o bootable_template.yaml``

Generating Multiple Templates
==============================

The ``get-templates`` command (note the plural) allows you to generate multiple template configurations at once:

``nxpimage bootable-image get-templates -f <family> -o <output_directory>``

When used without the ``--template`` option, this command generates:
- Standard templates for all memory types (legacy behavior)
- All extra templates in sub-folders, with board-specific variants

You can generate a specific template structure using the ``--template`` option:

``nxpimage bootable-image get-templates -f <family> -o <output_directory> --template imx_boot_flash_all``

Available template names include: ``imx_boot_flash_all`` and others depending on the family.

For board-specific configurations, use the ``--board`` option:

``nxpimage bootable-image get-templates -f <family> -o <output_directory> --board imx95-19x19-lpddr5-evk``

Use the ``list-boards`` command to see available boards for your family:

``nxpimage bootable-image list-boards -f <family>``


.. toctree::
    :caption: Sub images
    :maxdepth: 1

    fcb
    xmcd
