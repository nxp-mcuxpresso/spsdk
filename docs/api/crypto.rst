Crypto Module API
=================
.. automodule:: spsdk.crypto

PQC key support
----------------

SPSDK uses different backends for the two supported post-quantum signature
families:

* ``ML-DSA`` is implemented in the core ``spsdk.crypto.keys`` module on top of
  ``cryptography``.
* ``Dilithium`` is still provided by the optional ``spsdk_pqc`` plugin.

ML-DSA loading in SPSDK follows this compatibility order:

#. native ``cryptography`` ML-DSA key material, including normalized
   ``BEGIN ML-DSA-*`` PEM labels,
#. built-in conversion of legacy ML-DSA public keys,
#. built-in conversion of legacy seed-based ML-DSA private keys,
#. compatibility fallback to ``spsdk_pqc`` for legacy expanded-secret ML-DSA
   private keys.

The last case is kept only for backward compatibility with older key material.
Those expanded-secret private keys are not convertible to native
``cryptography`` private keys inside SPSDK, so SPSDK warns when it has to use
that fallback path.

Crypto module key generation
------------------------------

.. automodule:: spsdk.crypto.keys
   :members:
   :undoc-members:
   :show-inheritance:

Crypto module certificate generation
--------------------------------------

.. automodule:: spsdk.crypto.certificate
   :members:
   :undoc-members:
   :show-inheritance:


Crypto module symmetric encryption/decryption
----------------------------------------------

.. automodule:: spsdk.crypto.symmetric
   :members:
   :undoc-members:
   :show-inheritance:

Crypto module CMS
--------------------------------------

.. automodule:: spsdk.crypto.cms
   :members:
   :undoc-members:
   :show-inheritance:

Crypto module CMAC
--------------------------------------

.. automodule:: spsdk.crypto.cmac
   :members:
   :undoc-members:
   :show-inheritance:

Crypto module HMAC
--------------------------------------

.. automodule:: spsdk.crypto.spsdk_hmac
   :members:
   :undoc-members:
   :show-inheritance:


Crypto module hash
--------------------------------------

.. automodule:: spsdk.crypto.hash
   :members:
   :undoc-members:
   :show-inheritance:


Crypto module utils
--------------------------------------

.. automodule:: spsdk.crypto.utils
   :members:
   :undoc-members:
   :show-inheritance:


Interface for all potential signature providers
------------------------------------------------
.. automodule:: spsdk.crypto.signature_provider
   :members: SignatureProvider, PlainFileSP, InteractivePlainFileSP
   :undoc-members:
   :show-inheritance:

Crypto module OSCCA
--------------------------------------

.. automodule:: spsdk.crypto.oscca
   :members:
   :undoc-members:
   :show-inheritance:

Crypto module types
--------------------------------------

.. automodule:: spsdk.crypto.crypto_types
   :members:
   :undoc-members:
   :show-inheritance:

Crypto module RNG
--------------------------------------

.. automodule:: spsdk.crypto.rng
   :members:
   :undoc-members:
   :show-inheritance:

Crypto exceptions
--------------------------------------

.. automodule:: spsdk.crypto.exceptions
   :members:
   :undoc-members:
   :show-inheritance:
