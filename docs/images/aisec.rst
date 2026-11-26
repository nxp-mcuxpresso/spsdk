===================================
AISEC protected-directory container
===================================

The AISEC protected-directory container (``dir-v5``) packs a directory of AI/ML model
files (weights, configuration, tokenizers, ...) into a single binary that is authenticated
and optionally encrypted by a model master key (MMK). The container is consumed on the
device by the AISEC model loader, which verifies it with the help of the EdgeLock Secure
Enclave (ELE), OP-TEE or a software backend.

Supported families are i.MX93 (``mimx9352`` and its aliases) and i.MX95 (``mimx9596``
and its aliases). Both use the same AISEC dir-v5 format, not an AHAB image container.
The device must provide a compatible AISEC loader and the selected backend.

*nxpimage* generates the host-buildable provisioning containers:

- **discrete** (flag ``0x12``) -- the MMK is provisioned to the device separately, the
  container refers to it only by its ``mmk_id``.
- **integrated** (flag ``0x11``) -- the container carries an MMK provisioning blob
  (``mmk_block``) prepared by the provisioning flow.

The sealed on-device container (flag ``0x91``) is created by the device; *nxpimage* can
parse and verify it, but it cannot be generated or converted back to a configuration.

Every member is protected with one of the protection levels:

- ``enc_auth`` -- AES-CTR encrypted and AES-CMAC authenticated,
- ``auth_only`` -- stored in plaintext and AES-CMAC authenticated,
- ``none`` -- stored in plaintext without any protection. It is refused for the
  load-influencing members (weights, model configuration, tokenizers, manifests).

The encryption and authentication keys are derived from the MMK (SP 800-108 CMAC or HKDF
SHA-256), optionally bound to the device by the SRK hash (SRKH). The container header is
authenticated by an AES-CMAC computed over the descriptor and the metadata, every member
block and every member is authenticated by its own MAC.

.. note:: The MMK is a secret. It is required to build a container and to decrypt the
   encrypted members; it is never stored in the container nor in the configuration created
   by the ``parse`` command.

*Generation of the container*

Get a configuration template, fill it in and export the container:

.. code-block:: bash

    nxpimage aisec get-template -f mimx9596 -o aisec_config.yaml
    nxpimage aisec export -c aisec_config.yaml

For i.MX93, use ``-f mimx9352`` instead.

*Secure-boot binding on i.MX93 and i.MX95*

``keys/srkh`` (and the ``--srkh`` option of ``parse`` and ``verify``) always accepts
exactly **32 bytes**, matching the binding root reported by the device backend.
The secure-boot hash must be calculated for the actual family and silicon revision:

- **i.MX93, AHAB v1:** use the complete 32-byte SHA-256 hash of the AHAB v1 SRK table.
- **i.MX95 B0, AHAB v2:** use the first 32 bytes of the 64-byte SHA-512 SRK table hash.
  i.MX95 A0/A1 uses AHAB v1 instead.

The AHAB v1 and v2 SRK tables have different representations, so using the same public
keys does **not** produce the same binding root. Do not calculate an i.MX93 binding root
using the i.MX95 B0 family/revision, or pad the i.MX93 hash to 64 bytes. AISEC performs
the additional SHA-256 step required by its KDF internally; do not pre-hash the binding
root yourself.

For example, calculate the i.MX93 hash using the same four SRKs, in the same order and
with the same SRK record hash algorithm as the secure-boot image:

.. code-block:: bash

    nxpcrypto rot calculate-hash -f mimx9352 -r a1 -k srk0.pem -k srk1.pem -k srk2.pem -k srk3.pem -o srkh.bin

The resulting 32-byte binary can be used directly as ``keys/srkh: srkh.bin``. For i.MX95
B0, calculate with ``-f mimx9596 -r b0`` and supply only the first 32 bytes (the first
64 hex characters of the printed hash), not the full 64-byte output file. Alternatively,
use the first 32 bytes of OEM SRKH reported by ``nxpele get-info`` on the target.
A wrong but correctly sized SRKH cannot be detected during export without the device's
binding root; the resulting container will fail authentication on that device.

*Selection of the members*

The ``members`` section of the configuration defines the container members in two ways that
can be combined:

- ``src_dir`` -- every file of the directory (recursively) becomes a member; no file is
  skipped, including hidden files such as ``.DS_Store`` or ``.git`` content (a warning is
  printed for them), so use a clean directory. Symbolic links to files are packed with the
  content of the target, symbolic links to directories are not followed. The member name is
  the relative path. The protection and block size of each
  member are selected by the first matching glob pattern in ``rules``; members matching no
  rule use ``default``. Rules only change the settings, they do not add or remove members.
- ``files`` -- additional members listed one by one, placed after the ``src_dir`` members.
  It is meant for files outside ``src_dir``. An entry does not override a ``src_dir`` member;
  a name present in both is rejected as a duplicate.

.. code-block:: yaml

    members:
      src_dir: model_dir
      default:
        protection: enc_auth
        block_size: b1m
      rules:
        - match: "tokenizer/*"
          protection: auth_only
          block_size: b64k
      files:
        - name: LICENSE
          file: ../LICENSE
          protection: none

*Verification and parsing of the container*

The structure of a container is verified without any key. With the MMK (and the SRKH for a
device-bound container) the MACs are verified as well and the encrypted members are
decrypted. The keys are given as a binary file, a HEX text file or a HEX string.

.. code-block:: bash

    nxpimage aisec verify -b aisec_container.bin
    nxpimage aisec verify -b aisec_container.bin -k mmk.bin --srkh srkh.bin

The ``parse`` command stores the members and the configuration (``aisec_config.yaml``)
into the output directory. Without the MMK the encrypted members cannot be decrypted: they
are listed in the configuration without the ``file`` key, no data file is stored for them
and the command prints their names. Such a configuration describes the container structure
but cannot be used to rebuild it; parse the container with the MMK to recover the members.
To rebuild the container, provide the MMK as ``mmk.bin`` next to the configuration. The
rebuilt container always uses a fresh container salt, so it is not byte-identical to the
parsed binary.

.. code-block:: bash

    nxpimage aisec parse -f mimx9596 -b aisec_container.bin -k mmk.bin --srkh srkh.bin -o parsed

.. include:: ../_prebuild/aisec_schemas.inc
   :parser: myst_parser.sphinx_
