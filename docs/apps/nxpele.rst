===================
User Guide - nxpele
===================

This user guide describes how to use *nxpele* application. *nxpele* is a tool to communicate with
EdgeLock Enclave hardware on target where it is used, for example: i.MX RT1180 or i.MX 93.

Nxpele supports three modes of communication:

- *mboot* mode - nxpele communicates with EdgeLock Enclave using mboot commands (i.MX RT1180).

  In order to use the nxpele in mboot mode, flashloader must be loaded to target memory. It relies on mboot
  commands (write-memory, read-memory and ele-message), so it contains standard *blhost* options to establish connection
  with ISP mboot.

- *uboot_serial* mode - nxpele communicates with EdgeLock Enclave using u-boot serial console.

  In order to use the nxpele in uboot mode, u-boot serial console must be enabled.
  This implementation relies on "ele_message" command in U-Boot console, see :ref:`nxpele_uboot_requirements`.

- *uboot_fastboot* mode - nxpele communicates with EdgeLock Enclave using u-boot fastboot.

  In order to use the nxpele in uboot_fastboot mode, u-boot fastboot must be enabled and the "ele_message"
  command must be available, see :ref:`nxpele_uboot_requirements`. This is the fastest method to communicate with EdgeLock Enclave.

.. _nxpele_uboot_requirements:

-------------------
U-Boot requirements
-------------------

Both U-Boot modes send the ELE messages through the ``ele_message`` U-Boot command. The *uboot_fastboot*
mode in addition needs the console output to be multiplexed to fastboot (``CONFIG_CONSOLE_MUX=y``) to read
the response.

- NXP U-Boot (`nxp-imx/uboot-imx <https://github.com/nxp-imx/uboot-imx>`_) from release ``lf-6.18.20-2.0.0``
  builds the ``ele_message`` command by default for i.MX 8ULP and i.MX 9 devices. ``CONFIG_CONSOLE_MUX`` is
  selected by ``CONFIG_FASTBOOT_UUU_SUPPORT``, which is enabled in the default configurations of the NXP
  evaluation boards. The U-Boot from the prebuilt i.MX Linux BSP images of this release or newer can be used
  without any change.
- Older NXP U-Boot releases (for example ``lf_v2025.04``, i.MX Linux 6.12.x) contain the ``ele_message`` command
  only when U-Boot is built with AHAB support (``CONFIG_AHAB_BOOT=y``). This option is not enabled in the
  default configurations, so the U-Boot preinstalled on the boards usually does not support nxpele.
  Either use a newer U-Boot, or rebuild U-Boot with ``CONFIG_AHAB_BOOT=y`` and ``CONFIG_CONSOLE_MUX=y``.

The U-Boot does not have to be written to the boot memory. The bootloader (``imx-boot-<board>.bin-flash_all``
from the BSP) can be loaded to RAM with the board in serial download mode and nxpele can be used right after:

.. code-block:: bash

    nxpuuu write -f mimx9596 imx-boot-imx95-15x15-frdm.bin-flash_all
    nxpele -f mimx9596 -d uboot_fastboot get-info

The same can be done with the UUU tool: ``uuu -b spl imx-boot-imx95-15x15-frdm.bin-flash_all``.

If nxpele fails and the U-Boot console (or the fastboot response) reports ``Unknown command 'ele_message'``,
the running U-Boot does not contain the ``ele_message`` command. Use a U-Boot that meets the requirements above.
You can check it in the U-Boot console with ``help ele_message``.

For more information about building the u-boot, please refer to the U-Boot documentation. https://docs.u-boot.org/en/latest/build/gcc.html

Nxpele supports following commands:

.. include:: ../_prebuild/nxpele_commands_table.inc

-------------------
Forward boot crypto
-------------------

The *forward-boot-crypto* command sends the EdgeLock Enclave FORWARD BOOT CRYPTO (0x93) request. It moves the
secure boot crypto state of the device from one value to another. The state selects which signatures secure boot
verifies:

- *CLASSIC* - only the classic (ECDSA/RSA) signature is verified. This is the initial state, so it can't be
  selected as a target.
- *HYBRID* (``hybrid``) - both the PQC and the classic signatures are verified.
- *PQC* (``pqc``) - only the PQC signature is verified.
- *RETURN TO CLASSIC* (``return_to_classic``) - go back from hybrid or PQC to classic verification. This is a final
  state, after which no further transition is possible.

.. warning::

    The command burns a fuse when it succeeds, so it can't be reverted.

.. note::

    The request is handled by the EdgeLock Enclave firmware, not by the ROM. The ELE firmware must be loaded on the
    target before the command is sent. Check the EdgeLock Enclave firmware documentation of your device to see if the
    command is supported.

Whether a signed message is needed depends on the current state and on the SRK hash fuses (SRKH) that are programmed:

.. list-table:: Secure boot crypto forward policy
    :header-rows: 1

    * - Current state
      - Classic SRKH programmed
      - PQC SRKH programmed
      - Transition
    * - classic, hybrid, pqc
      - NO
      - NO
      - Allowed without a signed message
    * - classic, hybrid
      - YES
      - NO
      - Refused, PQC SRKH must be programmed first
    * - pqc
      - YES
      - NO
      - Allowed without a signed message
    * - classic
      - NO
      - YES
      - Allowed without a signed message
    * - hybrid, pqc
      - NO
      - YES
      - Refused, classic SRKH must be programmed first
    * - classic, hybrid, pqc
      - YES
      - YES
      - Allowed only with a signed message signed by both the classic and the PQC key
    * - return to classic
      - any
      - any
      - Not possible (final state)

Going from classic to return to classic is always allowed and never needs a signed message.

When a signed message is needed, create it with ``nxpimage signed-msg``:

- Use the ``FORWARD_BOOT_CRYPTO_REQ`` command. Set it to the same mode that you pass to ``nxpele`` with ``--mode``.
- Sign the message with both key types: the classic key in ``signer`` and ``srk_table``, and the PQC key in
  ``signer_#2`` and ``srk_table_#2``.
- Set ``check_all_signatures: check_all_signatures``.

The Device UUID (``uuid``) of the message is optional for this command.

Get the template with:

.. code-block:: bash

    nxpimage signed-msg get-template -f mimx9596 -m forward_boot_crypto_req -o fwd_boot_crypto.yaml

Example of a configuration that moves the device to the hybrid mode:

.. code-block:: yaml

    family: mimx9596
    revision: b0
    output: fwd_boot_crypto_hybrid.bin
    srk_set: oem
    used_srk_id: 0
    srk_revoke_mask: 0
    fuse_version: 0
    sw_version: 0
    check_all_signatures: check_all_signatures  # Mandatory for FORWARD_BOOT_CRYPTO_REQ
    signer: keys/srk0_ecc384.pem                # Classic key
    signer_#2: keys/srk0_mldsa87.pem            # PQC key
    srk_table:
      srk_array:
        - keys/srk0_ecc384.pub
        - keys/srk1_ecc384.pub
        - keys/srk2_ecc384.pub
        - keys/srk3_ecc384.pub
      srk_table_#2:
        srk_array:
          - keys/srk0_mldsa87.pub
          - keys/srk1_mldsa87.pub
          - keys/srk2_mldsa87.pub
          - keys/srk3_mldsa87.pub
    message:
      command:
        FORWARD_BOOT_CRYPTO_REQ: HYBRID  # HYBRID, PQC or RETURN_TO_CLASSIC

Export the signed message and send it with the forward boot crypto request:

.. code-block:: bash

    nxpimage signed-msg export -c fwd_boot_crypto.yaml
    nxpele -f mimx9596 -d uboot_fastboot forward-boot-crypto -m hybrid -b fwd_boot_crypto_hybrid.bin

If no signed message is needed (see the table above), leave out the ``-b/--signed-msg`` option:

.. code-block:: bash

    nxpele -f mimx9596 -d uboot_fastboot forward-boot-crypto -m hybrid

Common error indicators returned by the EdgeLock Enclave:

- ``0xC029`` - the transition isn't allowed by the state machine.
- ``0xEF29`` - bad SRKH set. The SRK hashes that the policy table requires aren't programmed.
- ``0xBC29`` - the mode in the signed message doesn't match the ``--mode`` option.
- ``0xE029`` - invalid signed message type. ``check_all_signatures`` isn't set in the signed message.

----------------------
Command line interface
----------------------

.. click:: spsdk.apps.nxpele:main
    :prog: nxpele
    :nested: full
