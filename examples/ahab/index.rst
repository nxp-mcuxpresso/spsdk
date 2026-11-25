================
AHAB
================

AHAB (Advanced High Assurance Boot) is used by i.MX 8ULP, i.MX 8QM/8QXP/8DXL,
i.MX 9x and i.MX RT118x devices. For an overview of the other mechanisms and device
families, see :doc:`/secure_boot`.

Choose the workflow matching your starting point:

* **Signing existing images:** use an already-built AHAB boot image, including an
    ``imx-boot`` image from the Yocto BSP. See the
    :doc:`i.MX95 signing example </examples/ahab/imx95/imx95_ahab_sign>`.
* **Building and signing:** assemble containers from individual bootloader and firmware
    binaries. See :ref:`Mapping Yocto BSP Output Files to SPSDK Inputs` for their Yocto names
    and locations, then choose a device-specific example below.

.. note::
    **Important: File Availability and Requirements**

    Due to licensing restrictions and export control regulations, not all firmware files required for AHAB examples are directly available for download from NXP's public repositories. Many of the necessary binaries (such as ELE firmware, DDR training firmware, and other proprietary components) must be obtained through the official i.MX Yocto BSP build process.

    **Recommended Approach:**

    - Set up and build the complete i.MX Yocto BSP for your target platform
    - Extract the required firmware binaries from the Yocto build artifacts
    - Refer to the current `i.MX Linux Release Notes <https://www.nxp.com/docs/en/release-note/IMX_LINUX_RELEASE_NOTES.pdf>`_ for the most up-to-date information on file availability and BSP versions
    - Consult the `i.MX Linux User's Guide <https://www.nxp.com/docs/en/user-guide/UG10163.pdf>`_ for detailed build instructions

    This approach ensures you have access to all necessary proprietary firmware components while complying with licensing requirements.

Unsigned
========

.. toctree::
    :maxdepth: 1

    imx8ulp/imx8ulp_ahab_uboot
    imx93/imx93_ahab_uboot
    imx95/imx95_ahab_uboot

Signed
======

.. toctree::
    :maxdepth: 1

    i.MX95: Signing an Existing Boot Image (ML-DSA and ECC) <imx95/imx95_ahab_sign>
    imx93/imx93_signed_kernel
    imx95/imx95_signed_ahab_uboot
    imx95/imx95_signed_kernel
    rt118x_signed_flashloader/rt118x_signed_flashloader
    rt118x_secure_boot/rt118x_secure_boot
    imx943/imx943_srk_revocation
    imx95/imx95_ahab_load_tcm
    imx95/imx95_anti_rollback_protection
    srk_table/srk_table

Signed+Encrypted
================

.. toctree::
    :maxdepth: 1

    imx93/imx93_signed_ahab_uboot
    imx95/imx95_encrypted_signed_ahab_uboot
