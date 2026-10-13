------------------
Secure Binary 3.1
------------------

SB 3.1 is an evolution of the SB 2 format.
The configuration is done in a similar way as a master boot image by configuration file in YAML or JSON. BD files are no longer used, commands are supplied in the configuration file.

Example of use
nxpimage: ``nxpimage sb31 export "sb3_config.yaml``


Structure of the SB 3.1 file
=============================

The SB 3.1 container is organized as a chain of blocks. The first block (Block 0) carries all
authentication data, while the following blocks carry the actual bootloader commands and data.

* **Block 0 (header block)** is the signed part of the container and consists of:

  * **Header** - starts with the ``sbv3`` magic and holds the format version (3.1), flags,
    block count, firmware (anti-rollback) version, image type, timestamp, a 16-byte description
    and the offset to the certificate block.
  * **Hash of the next block** - SHA-256 (32 bytes) or SHA-384 (48 bytes) digest of Block 1,
    which links Block 0 to the rest of the container.
  * **Certificate block v2.1** - holds the Root of Trust keys and the optional ISK certificate
    used to authenticate the container (see `Certificate block`_ below).
  * **Signature** - ECDSA signature over the whole Block 0, created by the selected root key or
    by the ISK. It is 64 bytes for NIST P-256 / SHA-256 or 96 bytes for NIST P-384 / SHA-384.

* **Data blocks (Block 1..N)** each contain the block number, the hash of the following block and
  a chunk of command data. Because every block stores the hash of the next one, the blocks form a
  hash chain that is anchored by the signed Block 0. The command data can optionally be encrypted
  with AES.

The hash type (SHA-256 or SHA-384) is derived from the elliptic curve of the signing keys and
determines the block size (292 bytes for SHA-256, 308 bytes for SHA-384).


Certificate block
=============================

The authentication of the SB 3.1 file relies on the certificate block v2.1, which is embedded in
Block 0. The same certificate block is also used by the signed master boot image. It establishes
the Root of Trust and, optionally, an intermediate signing key used to sign the container.

.. figure:: ../examples/_knowledge_base/img/cert_block_v2_1.png
   :width: 400px
   :align: center

   Certificate block v2.1 structure (embedded in Block 0 of the SB 3.1 file)

The certificate block v2.1 is composed of the following parts:

* **Header** - starts with the ``chdr`` magic and stores the certificate block format version and
  the total certificate block size.
* **Root of Trust (RoT) record** - the anchor of trust for the container:

  * **flags** - encode whether the root certificate signs the ISK or the image directly, which of
    the root certificates is used (0-3) and the elliptic curve type (secp256r1 or secp384r1).
  * **RoTKT** (Root of Trust Keys Table) - 1 to 4 Root of Trust Key Hash (RoTKH) records. Each hash
    is 32 bytes (SHA-256 for secp256r1) or 48 bytes (SHA-384 for secp384r1). The digest of this
    table is provisioned into the device non-volatile memory (fuses or PFR).
  * **RoTKpublic** - the X and Y coordinates of the selected root public key, used to verify the
    signature of the block.
* **Optional ISK certificate** - present only when an intermediate signing key is used. When it is
  omitted, one of the root keys signs Block 0 directly. It contains:

  * **signatureOffset** - offset from the start of the ISK certificate to its signature.
  * **constraint** - certificate version compared against a monotonic counter in fuses.
  * **flags** - the user-data flag (bit 31) and the ISK elliptic curve type (bits 3:0).
  * **ISKpublic** - the X and Y coordinates of the ISK public key.
  * **userData** - optional application-specific data.
  * **Signature** - ECDSA signature over the RoT record and the ISK certificate, created with the
    selected root key.

The ISK elliptic curve can be the same as, or smaller than, the root key curve: if the root keys are
secp256r1 the ISK must also be secp256r1, while secp384r1 root keys allow either secp256r1 or
secp384r1 for the ISK.


Supported commands
=============================


.. include:: ../_prebuild/table_sb31.inc
   :parser: myst_parser.sphinx_



Supported configuration options
=================================

.. include:: ../_prebuild/schemas_sb31.inc
   :parser: myst_parser.sphinx_
