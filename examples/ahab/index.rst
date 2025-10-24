================
AHAB
================
.. note::
    **Important: File Availability and Requirements**

    Due to licensing restrictions and export control regulations, not all firmware files required for AHAB examples are directly available for download from NXP's public repositories. Many of the necessary binaries (such as ELE firmware, DDR training firmware, and other proprietary components) must be obtained through the official i.MX Yocto BSP build process.

    **Recommended Approach:**

    - Set up and build the complete i.MX Yocto BSP for your target platform
    - Extract the required firmware binaries from the Yocto build artifacts
    - Refer to the current `i.MX Linux Release Notes <https://www.nxp.com/docs/en/release-note/IMX_LINUX_RELEASE_NOTES.pdf>`_ for the most up-to-date information on file availability and BSP versions
    - Consult the `i.MX Linux User's Guide <https://www.nxp.com/doc/IMX_LINUX_USERS_GUIDE>`_ for detailed build instructions

    This approach ensures you have access to all necessary proprietary firmware components while complying with licensing requirements.

.. toctree::
    :maxdepth: 1

    rt118x_signed_flashloader/rt118x_signed_flashloader
    rt118x_secure_boot/rt118x_secure_boot
    imx93/imx93_ahab_uboot
    imx93/imx93_signed_ahab_uboot
    imx93/imx93_signed_kernel
    imx943/imx943_srk_revocation
    imx95/imx95_ahab_uboot
    imx95/imx95_ahab_load_tcm
    imx95/imx95_signed_ahab_uboot
    imx95/imx95_ahab_sign
    imx95/imx95_encrypted_signed_ahab_uboot
    imx95/imx95_anti_rollback_protection
    srk_table/srk_table
    imx8ulp/imx8ulp_ahab_uboot
