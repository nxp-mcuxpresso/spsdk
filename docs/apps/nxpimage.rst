=====================
User Guide - nxpimage
=====================

*nxpimage* is an SPSDK tool for creating and manipulating NXP secure firmware images.
It supports a wide range of image formats, security containers, and device-specific configurations
across the NXP MCU/MPU portfolio.

.. contents:: Supported image types and features
    :local:
    :depth: 1

------------------------------
Master Boot Image (MBI)
------------------------------

Master Boot Image (MBI) is used for devices that boot from internal or external flash.
For full details see :ref:`Executable Images`.

Key commands:

- ``nxpimage mbi get-templates -f <family> -o <output_dir>`` — generate configuration templates
- ``nxpimage mbi export -c <config.yaml>`` — build the MBI image
- ``nxpimage mbi parse -b <image.bin> -f <family>`` — parse an existing image
- ``nxpimage mbi verify -b <image.bin> -f <family>`` — verify an existing image

---------------------------------------------
AHAB (Advanced High Assurance Boot)
---------------------------------------------

AHAB is the secure boot architecture for i.MX 8, i.MX 9, and related families.
For full details see :ref:`AHAB`.

Key commands:

- ``nxpimage ahab get-template -f <family> -o template.yaml`` — generate template
- ``nxpimage ahab export -c <config.yaml>`` — build AHAB container
- ``nxpimage ahab parse -b <container.bin> -o <output_dir>`` — parse container
- ``nxpimage ahab sign -c <config.yaml>`` — sign an existing container
- ``nxpimage ahab verify -b <container.bin>`` — verify a container
- ``nxpimage ahab re-sign -b <container.bin>`` — re-sign a container
- ``nxpimage ahab certificate`` — manage AHAB certificates
- ``nxpimage ahab update-keyblob -b <container.bin>`` — update the key blob in a container

RT2660 ELE firmware signed with ICCS keys can contain encrypted images without an
OEM key blob. SPSDK preserves these containers and verifies their signatures and
encrypted-image hashes, but reports a warning that plaintext verification is
unavailable without the encryption key. This does not relax the key-blob requirement
for encrypted OEM images. When parsing, ICCS containers are extracted as
``binary_container`` entries by default, like NXP-signed firmware; use ``--parse-nxp``
to request their full configuration instead.

------------------------------
Signed Messages
------------------------------

The ``signed-msg`` subgroup handles AHAB signed messages used for OEM lifecycle transitions,
key revocation, and other authenticated device commands sent via the bootloader.

Key commands:

- ``nxpimage signed-msg get-template -f <family> -o template.yaml`` — generate template
- ``nxpimage signed-msg export -c <config.yaml>`` — build signed message container
- ``nxpimage signed-msg parse -b <msg.bin> -o <output_dir>`` — parse a signed message
- ``nxpimage signed-msg verify -b <msg.bin>`` — verify a signed message

.. _tlv_blob:

TLV Blob
~~~~~~~~~

TLV (Type-Length-Value) Blob is a data structure used for storing and transmitting data in a
flexible and extensible format within AHAB signed messages and other secure containers.
Each entry consists of:

- **Type**: Identifies the kind of data
- **Length**: Specifies the size of the value field in bytes
- **Value**: Contains the actual data payload

TLV blobs are created and managed via the ``signed-msg tlv`` subcommand:

- ``nxpimage signed-msg tlv export -c <config.yaml>`` — build a TLV blob

---------------------------------------------
Secure Binary (SB 2.1 / SB 3.1 / SB 4.0)
---------------------------------------------

Secure Binary images carry authenticated and optionally encrypted firmware update commands
for the ROM bootloader. For full details see :ref:`Secure Update`.

Key commands:

- ``nxpimage sb21 get-template -o template.yaml`` — SB 2.1 template
- ``nxpimage sb21 export -c <config.yaml>`` — build SB 2.1 image
- ``nxpimage sb21 parse -b <sb.bin> -o <output_dir>`` — parse SB 2.1 image
- ``nxpimage sb31 get-template -f <family> -o template.yaml`` — SB 3.1 template
- ``nxpimage sb31 export -c <config.yaml>`` — build SB 3.1 image
- ``nxpimage sb31 parse -b <sb.bin> -o <output_dir>`` — parse SB 3.1 image
- ``nxpimage sb40 get-template -f <family> -o template.yaml`` — SB 4.0 template
- ``nxpimage sb40 export -c <config.yaml>`` — build SB 4.0 image
- ``nxpimage sb40 parse -b <sb.bin> -o <output_dir>`` — parse SB 4.0 image

------------------------------
Bootable Image
------------------------------

Bootable images combine a boot firmware component with the required configuration blocks
(FCB, XMCD, etc.) for a specific memory type. For full details see :ref:`Bootable Image`.

Key commands:

- ``nxpimage bootable-image get-templates -f <family> -o <output_dir>`` — generate all templates
- ``nxpimage bootable-image export -c <config.yaml>`` — build bootable image
- ``nxpimage bootable-image parse -b <image.bin> -f <family> -o <output_dir>`` — parse image
- ``nxpimage bootable-image verify -b <image.bin> -f <family>`` — verify image
- ``nxpimage bootable-image list-boards -f <family>`` — list supported boards for a family

RT266x SD/eMMC redundant boot
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

For ``mimxrt2660``, ``mimxrt2661``, ``mimxrt2662``, and ``mimxrt2663``,
the ``sd`` and ``emmc`` layouts support an optional secondary-image table:

.. code-block:: yaml

   family: mimxrt2660
   memory_type: sd
   init_offset: 0
   secondary_image_table:
     first_sector_number: 0x1000
   ahab_container: primary_ahab.yaml

Use ``target_memory: sd_emmc`` in the AHAB configuration. This example places the
table at primary-image offset ``0x200``, with tag ``0x00112233`` and a pointer
to media byte offset ``0x1000 * 512 = 0x200000``. XMCD, when configured, remains at
``0x400`` and the primary AHAB container at ``0x800``.

Program the complete primary bootable image at raw media offset zero. Build the
secondary bootable image separately using the same memory type and
``init_offset: 0``, normally without its own secondary-image table, and program
it at ``0x200000``. Its AHAB container will be at media offset ``0x200800``.
Choose a sector number that leaves enough space for the complete primary image;
the table does not combine images, check media capacity, or program the secondary
image. Do not confuse it with a second AHAB container inside a single boot image.

Omit ``secondary_image_table`` or set it to an empty string to preserve the
primary-only layout. A path to an exact 20-byte binary table is also accepted.
New tables contain three zero reserved words. Parsing preserves imported
reserved words; tables with nonzero reserved words are extracted as binary files
for a lossless configuration round-trip. Invalid tags, truncated tables, and zero
sector pointers are rejected. Uniform zero or erased padding in a full image
means the optional table is absent.

With a nonzero ``init_offset``, program the exported bytes at that offset relative
to the selected boot image's start. Segments preceding it are excluded, so an
export beginning at the AHAB container does not include the secondary-image table.

ROM selects the secondary SD/eMMC image using SRC ``GPR5[26]``. Do not modify this
register during ROM execution. See RT2660 Reference Manual sections 11.5.4.5
(*Redundant Boot Support for eMMC/SD*), 11.4.6 (*Persistent Bits*), and 11.6.2
(*Container Format*). Generating the table does not itself force secondary boot.

---------------------------------------------
HAB (High Assurance Boot)
---------------------------------------------

HAB is the secure boot mechanism for i.MX RT 1xxx and related families.

Key commands:

- ``nxpimage hab get-template -o template.yaml`` — generate template
- ``nxpimage hab export -c <config.yaml>`` — build HAB image
- ``nxpimage hab parse -b <image.bin> -o <output_dir>`` — parse image
- ``nxpimage hab convert -b <image.bd>`` — convert BD-format configuration

------------------------------
Trust Zone (TZ)
------------------------------

TrustZone configuration provides ARM TrustZone preset register values for Cortex-M33 based
devices. The exported binary is embedded in the MBI or bootable image.

Key commands:

- ``nxpimage tz get-template -f <family> -o template.yaml`` — generate template
- ``nxpimage tz export -c <config.yaml>`` — build TrustZone preset record
- ``nxpimage tz parse -b <tz.bin> -f <family>`` — parse TrustZone record

------------------------------
Certificate Block
------------------------------

Certificate blocks carry root-of-trust keys and the ISK (Image Signing Key) certificate
for MBI and other signed images.

Key commands:

- ``nxpimage cert-block get-template -f <family> -o template.yaml`` — generate template
- ``nxpimage cert-block export -c <config.yaml>`` — build certificate block
- ``nxpimage cert-block parse -b <cert.bin> -f <family>`` — parse certificate block
- ``nxpimage cert-block get-isk-tbs -c <config.yaml>`` — extract ISK TBS data for external signing

---------------------------------------------
BCA (Boot Configuration Area)
---------------------------------------------

Boot Configuration Area provides device boot configuration.

Key commands:

- ``nxpimage bca get-template -f <family> -o template.yaml`` — generate template
- ``nxpimage bca export -c <config.yaml>`` — build BCA block
- ``nxpimage bca parse -b <bca.bin> -f <family>`` — parse BCA block

---------------------------------------------
Flash Encryption (IEE / IPED / BEE / OTFAD)
---------------------------------------------

On-the-fly encryption engines protect firmware stored in external flash.
For full details see the flash encryption documentation.

Key commands:

- ``nxpimage iee get-template -f <family> -o template.yaml`` — IEE template
- ``nxpimage iee export -c <config.yaml>`` — build IEE keyblob image
- ``nxpimage iped get-template -f <family> -o template.yaml`` — IPED table template
- ``nxpimage iped export -c <config.yaml>`` — build IPED table/keyblob and optional encrypted data image
- ``nxpimage iped parse -f <family> -b <iped_table.bin> -o config.yaml`` — parse IPED table/keyblob
- ``nxpimage bee get-template -f <family> -o template.yaml`` — BEE template
- ``nxpimage bee export -c <config.yaml>`` — build BEE image
- ``nxpimage otfad get-template -f <family> -o template.yaml`` — OTFAD template
- ``nxpimage otfad export -c <config.yaml>`` — build OTFAD image
- ``nxpimage otfad get-kek -f <family>`` — retrieve OTFAD KEK

---------------------------------------------
HSE (Hardware Security Engine)
---------------------------------------------

HSE integration supports NXP's Hardware Security Engine used on automotive and industrial
devices (e.g. MCXE family). The subcommands allow building HSE key catalogs and configuration
entries required during device provisioning.

Key commands:

- ``nxpimage hse key-info`` — display HSE key slot information
- ``nxpimage hse key-catalog`` — generate HSE key catalog
- ``nxpimage hse smr-entry`` — configure Secure Memory Region (SMR) entries
- ``nxpimage hse cr-entry`` — configure Core Reset (CR) entries

------------------------------
Utilities
------------------------------

General-purpose binary image utilities.

Key commands:

- ``nxpimage utils binary-image`` — inspect and manipulate binary image files
- ``nxpimage utils convert`` — convert between image formats

----------------------
Command line interface
----------------------

.. click:: spsdk.apps.nxpimage:main
    :prog: nxpimage
    :nested: full
