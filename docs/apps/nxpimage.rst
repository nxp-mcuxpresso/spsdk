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
Flash Encryption (IEE / BEE / OTFAD)
---------------------------------------------

On-the-fly encryption engines protect firmware stored in external flash.
For full details see the flash encryption documentation.

Key commands:

- ``nxpimage iee get-template -f <family> -o template.yaml`` — IEE template
- ``nxpimage iee export -c <config.yaml>`` — build IEE keyblob image
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
