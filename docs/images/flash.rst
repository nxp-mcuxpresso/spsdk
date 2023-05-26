
=========================
Flash encryption engines
=========================

*nxpimage* currently supports generation of bootable images and keyblobs for NXP bus encryption engines -- OTFAD (On-the-fly AES decryption engines), BEE (Bus encryption engine) and IEE (Inline encryption engine).

.. note:: For Prince algorithm based inline encryption & decryption engines (IPED, Prince & NPX) we don't support offline image creation.

----
IEE
----

*nxpimage* supports generation of bootable image for MIMXRT117x. More details can be found in the security reference manual: https://www.nxp.com/webapp/sps/download/mod_download.jsp?colCode=IMXRT1170SRM&appType=moderated or in the Secure Boot modes application note https://www.nxp.com/webapp/Download?colCode=AN13250

IEE engine provides means to perform inline encryption and decryption. Following algorithms are supported AES-128/256-CTR and AES-256/512-XTS.
The IEE key blob containing keys and context structures is encrypted by a KEK according to the RFC3394 key-wrapping algorithm, because the key blob resides in the external memory along with the image and it must be protected

*Generation of bootable image*
First step is to get a template for configuration. The template might look like the file below.
``nxpimage iee get-template -f rt1170 iee_template.yaml``


.. include:: ../_prebuild/iee_schemas.inc
   :parser: myst_parser.sphinx_

.. code-block:: yaml

    # ===========  IEE: Inline Encryption Engine Configuration template for rt1170.  ===========
    # ----------------------------------------------------------------------------------------------------
    #                                         == Basic Settings ==
    # ----------------------------------------------------------------------------------------------------
    family: rt1170  # [Required], MCU family, MCU family name., Possible options:['rt1170']
    output_folder: iee_output # [Required], IEE output directory, Path to directory where the IEE output will be generated
    output_name: encrypted.bin # [Optional], Output binary image file name, File name of the output image containing keyblobs and encrypted data blobs
    keyblob_name: iee_keyblob.bin # [Optional], Keyblob file name, File name of the keyblob, output_folder/keyblob_name
    encrypted_name: encrypted_blob.bin # [Optional], Encrypted name, filename of the encrypted datablobs
    # ----------------------------------------------------------------------------------------------------
    #                                          == IEE Settings ==
    # ----------------------------------------------------------------------------------------------------
    ibkek1: '0x000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F' # [Required], IBKEK1 AES-XTS 256-bit key, IBKEK1 AES-XTS key for keyblob encryption
    ibkek2: '0x202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F' # [Required], IBKEK2 AES-XTS 256-bit key, IBKEK2 AES-XTS key for keyblob encryption
    keyblob_address: '0x30000000' # [Required], Base address of the IEE keyblob, Should be aligned to 1 kB
    data_blobs: # [Optional], Data blobs list, List of all data blobs that will be encrypted
    - data: my_data.bin  # [Required], Binary data blob, Path to binary file with plain text data to be encrypted
        address: '0x03001000' # [Optional], Data blob address, Data blob address, it doesn't have to be specified for S-REC
    key_blobs: # [Required], List of Key Blobs used by IEE, The list of definition of individual key blobs including plain data. Add other array items as you need and device allows
    - region_lock: false  # [Optional], Keyblob lock attribute, Determines if the ROM will lock the IEE configuration to prevent later changes.
        aes_mode: AesXTS # [Required], AES mode, AES mode, Encryption bypass, AES-XTS, AES-CTR (with or without address binding) or AES-CTR keystream only, Possible options:['Bypass', 'AesXTS', 'AesCTRWAddress', 'AesCTRWOAddress', 'AesCTRkeystream']
        key_size: CTR256XTS512 # [Required], AES key size, 128/256 for AES-CTR or 256/512 for AES-XTS, AES mode, AES-XTS or AES-CTR, Possible options:['CTR256XTS512', 'CTR128XTS256']
        page_offset: 0 # [Optional], Page offset, Page offset, IEE_REG0PO value
        key1: '0x000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F' # [Required], AES-XTS key1 / AES-CTR key, AES key for the key blob, size depends on key_size
        key2: '0x202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F' # [Required], AES-CTR Counter value or AES-XTS key2, AES key for the key blob, size depends on key_size
        start_address: '0x30001000' # [Required], Start address of key blob data, Start address of key blob data, it should be aligned to 1 KB (1024 B)
        end_address: '0x30008000' # [Required], End address of key blob data, End address of key blob data, it should be aligned to 1 KB (1024 B)

Fill the configuration file and export the image.
``nxpimage iee export iee_template.yaml``

------
OTFAD
------

The On-The-Fly AES Decryption (OTFAD) module provides an advanced hardware implementation that minimizes any incremental cycles of latency introduced by the decryption in the overall external memory-access time.
It implements a block cipher mode of operation supporting the counter mode (CTR).
The CTR mode provides a confidentiality mode that features the application of the forward cipher to a set of input blocks (called counters) to produce a sequence of output blocks that are exclusive-ORed with the plaintext to produce the ciphertext and vice versa.
The OTFAD engine includes complete hardware support for a standard AES key unwrap mechanism to decrypt a key BLOB data instruction containing the parameters needed for up to 4 unique AES contexts. Each context has a unique 128-bit key, a 64-bit counter, and a 64-bit memory region descriptor.

.. include:: ../_prebuild/otfad_schemas.inc
   :parser: myst_parser.sphinx_


------
BEE
------

i.MX RT10xx, except i.MX1010, provides an on-the-fly encryption engine called Bus Encryption Engine(BEE)
Refer to this application note for more info:
`AN12852 <https://www.nxp.com/docs/en/application-note/AN12852.pdf>`_.

.. include:: ../_prebuild/bee_schemas.inc
   :parser: myst_parser.sphinx_
