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

----------------------
Command line interface
----------------------

.. click:: spsdk.apps.nxpcrypto:main
    :prog: nxpcrypto
    :nested: full
