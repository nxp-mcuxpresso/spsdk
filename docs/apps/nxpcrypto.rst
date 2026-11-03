=======================
User Guide - nxpcrypto
=======================

This user’s guide describes how to use *nxpcrypto* application.

-----------------
PQC key handling
-----------------

SPSDK supports two post-quantum signature families:

* ``ML-DSA`` is handled directly by SPSDK through the native
  ``cryptography`` implementation.
* ``Dilithium`` remains available through the optional ``spsdk_pqc`` plugin.

For ML-DSA keys, SPSDK accepts native ``cryptography`` keys, raw NXP exports,
and PEM files that use the ``BEGIN ML-DSA-*`` / ``END ML-DSA-*`` labels.
When SPSDK encounters older ML-DSA public keys or seed-based private keys from
the legacy plugin encoding, it converts them internally to the native
``cryptography`` representation.

The oldest legacy ML-DSA private keys use an expanded-secret format that cannot
be reconstructed as a native ``cryptography`` private key. SPSDK can still load
those keys through the compatibility path provided by ``spsdk_pqc`` and logs a
warning when that happens. If you still use such keys, migrate them with the
plugin migration command or regenerate them in native ML-DSA format.

Composite (hybrid) keys and certificates
========================================

A composite (hybrid) key stores a classic and a post-quantum key together under
a single ``SubjectPublicKeyInfo``, using an algorithm OID such as
``1.3.9999.7.7`` (p384_mldsa65). SPSDK has no representation for such a
two-in-one key, so it cannot load composite keys or certificates. Attempting to
do so reports an error naming the offending algorithm OID.

This is not a limitation in practice, because the NXP boot ROMs do not use
composite keys either. Dual (hybrid) signing is done with two *separate* keys:
for example AHAB uses two SRK tables, ``srk_table`` plus ``srk_table_#2``, with
two signers, ``signer`` plus ``signer_#2``.

If you already have a composite private key, split it into its two parts with
the ``pqctool`` utility from the ``spsdk_pqc`` plugin and use the parts
separately::

    pqctool split --hybrid hybrid_key.pem --classic classic.der --pqc pqc.der

The reverse operation, ``pqctool combine``, builds a composite key from a
classic and a post-quantum key.

Note that ``pqctool split`` works on *keys*, not on certificates. A composite
certificate cannot be converted; the SRK certificates have to be reissued from
the split keys, one certificate per key.

----------------------
Command line interface
----------------------

.. click:: spsdk.apps.nxpcrypto:main
    :prog: nxpcrypto
    :nested: full
