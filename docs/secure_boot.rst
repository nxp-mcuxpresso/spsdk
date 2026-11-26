===========
Secure Boot
===========

Secure boot ensures that a device executes only software that is authenticated (and optionally
decrypted) by the boot ROM using keys provisioned by the device owner (OEM). If the
authentication fails on a device in the OEM closed lifecycle, the boot is stopped.

NXP devices implement secure boot with different mechanisms depending on the device family.
SPSDK creates, signs and encrypts the boot images for all of them with the ``nxpimage``
application.

Secure Boot Mechanisms
======================

.. list-table::
   :header-rows: 1
   :widths: 15 35 50

   * - Mechanism
     - Devices supported in SPSDK
     - Description
   * - :doc:`HAB </images/hab>`
     - i.MX RT10xx, i.MX RT115x/RT116x/RT117x
     - High Assurance Boot. The image is signed by Command Sequence File (CSF) data appended
       to the image and verified by the boot ROM. SPSDK uses BD configuration files, compatible
       with the legacy ``elftosb`` and CST tools.
   * - :doc:`AHAB </images/ahab>`
     - i.MX 8ULP, i.MX 8QM/8QXP/8DXL, i.MX 91/93/94/95, i.MX RT118x, i.MX RT2660
     - Advanced High Assurance Boot. The image is composed of signed AHAB containers that are
       verified by the boot ROM together with the security subsystem of the device (e.g.
       SECO on i.MX 8QM/8QXP/8DXL, EdgeLock Enclave on newer devices). SPSDK uses YAML
       configuration files.
   * - :doc:`MBI </images/mbi>`
     - LPC55xx, MCX, KW45/KW47, RW61x, i.MX RT5xx/RT7xx
     - Master Boot Image. The image is signed with a certificate block (and optionally
       encrypted) and verified by the boot ROM. SPSDK uses YAML configuration files.

All three formats are described in :doc:`/images/executable`. The exact list of devices and
features is in the :doc:`/devices_list`.

Typical Use Cases
=================

* **Building and signing a boot image** — SPSDK builds the containers from individual binaries
  (bootloader, firmware, application) and signs them. For i.MX MPUs, start with the
  :doc:`AHAB examples </examples/ahab/index>` and the
  :ref:`Mapping Yocto BSP Output Files to SPSDK Inputs` section.
* **Signing an existing image** — SPSDK signs an AHAB image that was built by another tool,
  including the ``imx-boot`` image from the i.MX Linux Yocto BSP. See the
  :doc:`i.MX95 signing example </examples/ahab/imx95/imx95_ahab_sign>`; individual firmware
  binaries are not needed for this workflow.

