=======================
Supported binary images
=======================



----------------------------------
Master Boot Image (MBI)
----------------------------------
Master Boot Image can be used directly (e.g. by using *blhost write-memory* command) or it can be used for further processing  (e.g. used as input to Secure Binary image container).
Image is created based on a supplied configuration file, either JSON or YAML is supported.

Example of use

nxpimage: ``nxpimage mbi export <path to config file>``

elftosb: ``elftosb –J <path to config file>``

Sample configuration for LPC55s6x plain signed XIP image. Other sample configurations might be obtained with the *get-templates* sub-command.

.. code-block:: yaml

    # ===========  Master Boot Image Configuration template for lpc55s6x, Plain Signed XIP Image.  ===========
    #
    #  == Basic Settings ==
    #
    family: lpc55s6x  # MCU family., MCU family name.
    outputImageExecutionTarget: Internal flash (XIP) # Application target., Definition if application is Execute in Place(XiP) or loaded to RAM during reset sequence.
    outputImageAuthenticationType: Signed # Type of boot image authentication., Specification of final master boot image authentication.
    masterBootOutputFile: my_mbi.bin # Master Boot Image name., The file for Master Boot Image result file.
    inputImageFile: my_application.bin # Plain application image., The input application image to by modified to Master Boot Image.
    #
    #  == Trust Zone Settings ==
    #
    enableTrustZone: false # TrustZone enable option, If not specified, the Trust zone is disabled.
    trustZonePresetFile: my_tz_custom.yaml # TrustZone Customization file, If not specified, but TrustZone is enabled(enableTrustZone) the default values are used.
    #
    #  == Certificate V2 Settings ==
    #
    mainCertPrivateKeyFile: my_prv_key.pem # Main Certificate private key, Main Certificate private key used to sign certificate
    imageBuildNumber: 0 # Image Build Number, If it's omitted, it will be used 0 as default value.
    rootCertificate0File: my_certificate0.pem # Root Certificate File 0, Root certificate file index 0.
    rootCertificate1File: my_certificate1.pem # Root Certificate File 1, Root certificate file index 1.
    rootCertificate2File: my_certificate2.pem # Root Certificate File 2, Root certificate file index 2.
    rootCertificate3File: my_certificate3.pem # Root Certificate File 3, Root certificate file index 3.
    mainCertChainId: 0 # Main Certificate Index, Index of certificate that is used as a main.
    chainCertificate0File0: chain_certificate0_depth0.pem # Chain certificate 0 for root 0, Chain certificate 0 for root certificate 0
    chainCertificate0File1: chain_certificate0_depth1.pem # Chain certificate 1 for root 0, Chain certificate 1 for root certificate 0
    chainCertificate0File2: chain_certificate0_depth2.pem # Chain certificate 2 for root 0, Chain certificate 2 for root certificate 0
    chainCertificate0File3: chain_certificate0_depth3.pem # Chain certificate 3 for root 0, Chain certificate 3 for root certificate 0
    chainCertificate1File0: chain_certificate1_depth0.pem # Chain certificate 0 for root 1, Chain certificate 0 for root certificate 1
    chainCertificate1File1: chain_certificate1_depth1.pem # Chain certificate 1 for root 1, Chain certificate 1 for root certificate 1
    chainCertificate1File2: chain_certificate1_depth2.pem # Chain certificate 2 for root 1, Chain certificate 2 for root certificate 1
    chainCertificate1File3: chain_certificate1_depth3.pem # Chain certificate 3 for root 1, Chain certificate 3 for root certificate 1
    chainCertificate2File0: chain_certificate2_depth0.pem # Chain certificate 0 for root 2, Chain certificate 0 for root certificate 2
    chainCertificate2File1: chain_certificate2_depth1.pem # Chain certificate 1 for root 2, Chain certificate 1 for root certificate 2
    chainCertificate2File2: chain_certificate2_depth2.pem # Chain certificate 2 for root 2, Chain certificate 2 for root certificate 2
    chainCertificate2File3: chain_certificate2_depth3.pem # Chain certificate 3 for root 2, Chain certificate 3 for root certificate 2
    chainCertificate3File0: chain_certificate3_depth0.pem # Chain certificate 0 for root 3, Chain certificate 0 for root certificate 3
    chainCertificate3File1: chain_certificate3_depth1.pem # Chain certificate 1 for root 3, Chain certificate 1 for root certificate 3
    chainCertificate3File2: chain_certificate3_depth2.pem # Chain certificate 2 for root 3, Chain certificate 2 for root certificate 3
    chainCertificate3File3: chain_certificate3_depth3.pem # Chain certificate 3 for root 3, Chain certificate 3 for root certificate 3

------------------------------------
Supported devices for MBI
------------------------------------
NXPIMAGE support devices from LPC55xx family (*LPC55S0x, LPC55S1x, LPC55S2x, LPC552x, LPC55S6x*), *RT5xx*, *RT6xx* and *LPC55S3x*.
Supported execution targets are: *Internal flash (XIP), External Flash (XIP) and RAM* and image authentication types: *Plain, CRC, Signed and Encrypted*.

The following table shows the supported image types for each device,
it either shows "N/A" if the configuration is not available or respective class that will be used for image creation.

*Target* in the table represents *outputImageExecutionTarget* in the configuration file and *authentication* in the table represents *outputImageAuthenticationType*.

.. include:: ../_prebuild/table.inc

------------------------------------------
Supported configuration options
------------------------------------------

Refer to the documentation below for the supported configuration options for each image type.
Please note that the *outputImageExecutionTarget* and *outputImageAuthenticationType* must be filled in addition to the basic settings according to the table with supported devices.


.. code-block:: yaml

    outputImageExecutionTarget: Internal flash (XIP) # Application target., Definition if application is Execute in Place(XiP) or loaded to RAM during reset sequence.
    outputImageAuthenticationType: Signed # Type of boot image authentication., Specification of final master boot image authentication.


.. include:: ../_prebuild/schemas.inc
   :parser: myst_parser.sphinx_


---------------------------
Secure binary
---------------------------

Secure binary is a binary output file that contains the user's application image along with a series of bootloader commands.
The output file is known as a "Secure Binary" or SB file for short.
These files typically have a .sb extension.

This format has a long history, the latest version is 3.1. (2022).
SPSDK elftosb tool supports SB 2.1 (2.0) and SB 3.1.

Version 2.1 added support for digital signatures.

The SB 2.0 and 2.1 file format also uses AES encryption for confidentiality and HMAC for
extending trust from the signed part of the SB file to the command and data part of the SB
file. These two keys (AES decrypt key and HMAC key) are wrapped in the RFC3394 key
blob, for which the key wrapping key is the SBKEK key


SB2 generation using BD file
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

The tool uses an input command file to control the sequence of bootloader commands present in the output file. This command file is called a "boot descriptor file" or BD file for short.

The image location is stated in the "sources" section of the .bd file. The SB key in the text file is used for encryption with the *nxpimage* command line tool.

Description of how to use BD file is in bellow chapter.

.. toctree::
    :maxdepth: 1

    ../usage/elf2sb

For more information about the Secure boot setup for LPC55Sxx family follow the `AN12283
<https://www.nxp.com/docs/en/application-note/AN12283.pdf>`_.

Example of SB2 generation for 4 root keys

nxpimage: ``nxpimage sb21 export -k "sbkek.txt" -c "commandFile.bd" -o "output.sb2" -s private_key_1_2048.pem
-S certificate_1_2048.der.crt -R certificate_1_2048.der.crt -R
certificate_2_2048.der.crt -R certificate_3_2048.der.crt -R certificate_4_2048.der.crt -h "RHKT.bin"
"input.bin"``

elftosb: ``elftosb -f lpc55xx -k "sbkek.txt" -c "commandFile.bd" -o "output.sb2" -s private_key_1_2048.pem
-S certificate_1_2048.der.crt -R certificate_1_2048.der.crt -R
certificate_2_2048.der.crt -R certificate_3_2048.der.crt -R certificate_4_2048.der.crt -h "RHKT.bin"
"input.bin"``

Created SB2 file can be loaded into the device using blhost *receive-sb-file* command.
``blhost -p COMxx receive-sb-file <path to the secured binary(.sb2)>``

SB 3.1
^^^^^^^^^^^^^^^^^
SB 3.1 is an evolution of the SB 2 format.
The configuration is done in a similar way as a master boot image by configuration file in YAML or JSON. BD files are no longer used, commands are supplied in the configuration file.

Example of use
nxpimage: ``nxpimage sb31 export "sb3_config.yaml``
elftosb: ``elftosb -j "sb3_config.yaml``

-------------------------
AHAB
-------------------------
AHAB (Advanced High Assurance Boot) is a container format supported on some devices. A configuration file in YAML or
JSON is used to instruct nxpimage how the output should look like.

AHAB container is not supported by elftosb tool.

Example of use for export
``nxpimage ahab export "path\to\config\file.yaml"``

Example of use for parse binary AHAB container
``nxpimage ahab parse -b "my_ahab_container.bin" "path\to_parsed_data"``

.. code-block:: yaml

    # ===========  Advanced High-Assurance Boot Configuration template for rt118x.  ===========
    # ----------------------------------------------------------------------------------------------------
    #                                        == General Options ==
    # ----------------------------------------------------------------------------------------------------
    family: rt118x  # [Required], MCU family, Family identifier including the chip revision. If revision is not present, latest revision is used as default., Possible options:['rt118x']
    revision: a0 # [Optional], MCU revision, Revision of silicon, Possible options:['a0']
    output: generated_ahab.bin # [Required], Output AHAB file name, Revision of silicon
    containers: # [Required], List of containers present in AHAB., The order of containers in the list defines the order in AHAB.
    -
        # ----------------------------------------------------------------------------------------------------
        #                     == Optional Binary Container format to add to AHAB image ==
        # ----------------------------------------------------------------------------------------------------
        binary_container:  # [Required], Binary AHAB container
        path: my_ahab_container.bin  # [Required], The AHAB container binary file, The binary file that contains AHAB "my_binary_container.bin
    -
        # ----------------------------------------------------------------------------------------------------
        #                  == Optional Configuration Container format to add to AHAB image ==
        # ----------------------------------------------------------------------------------------------------
        container:  # [Required], AHAB Container
        srk_set: oem  # [Required], Super Root Key (SRK) set, Defines which set is used to authenticate the container., Possible options:['none', 'oem', 'nxp']
        used_srk_id: 0 # [Conditionally required], Used SRK, Which key from SRK set is being used.
        srk_revoke_mask: 0 # [Optional], SRK revoke mask, Bitmask to indicate which SRKs to revoke. Bit set to 1 means revoke key. Bit 0 = revoke SRK_0, bit 1 = revoke SRK_1 etc.
        fuse_version: 0 # [Required], Fuse version, The value must be equal or greater than the version stored in fuses to allow loading this container.
        sw_version: 0 # [Required], Software version, Number used by Privileged Host Boot Companion (PHBC) to select between multiple images with same Fuse version field.
        signing_key: my_signing_key.pem # [Conditionally required], AHAB container signing key, Private key used for sign the container header. Header can be signed by SRK or by image key that was signed by SRK. If an image key is used, it must be the same algorithm and key size as the SRK. In both cases, the referenced SRK must not have been revoked.
        # ----------------------------------------------------------------------------------------------------
        #               == Configuration of AHAB Container images (array of multiple images) ==
        # ----------------------------------------------------------------------------------------------------
        images: # [Required], Image array, Array of image entries.
            - image_path: my_image.bin  # [Required], Image path, Path to image binary (absolute/relative).
            image_offset: '0x4000' # [Required], Image offset in AHAB container, Relative address for start of AHAB image (can contain multiple AHAB containers). In case of XiP type of AHAB image, the load_address and entry_point must correspond to this values. Example of setting of load_address - AHAB_IMAGE_ADDRESS+IMAGE_OFFSET=LOAD_ADDRESS
            load_address: '0x5000' # [Required], Image destination address, Address the image is written to in memory (absolute address in system memory).
            entry_point: '0x5000' # [Required], Image entry point, Image entry point (absolute address). Valid only for executable image types.
            image_type: executable # [Required], Image type, Kind of image., Possible options:['executable', 'data', 'dcd_image', 'seco', 'provisioning_image', 'provisioning_data']
            core_id: cortex-m33 # [Required], Core ID, Defines the core the image is dedicated for., Possible options:['cortex-m33', 'cortex-m7']
            is_encrypted: false # [Required], Image encryption, Determines, whether image is encrypted or not.
            boot_flags: 0 # [Optional], Boot flags, Boot flags controlling SCFW boot.
            meta_data_start_cpu_id: 0 # [Optional], Start CPU ID, Resource ID of CPU to be started
            meta_data_mu_cpu_id: 0 # [Optional], CPU memory unit start ID, Resource ID of the MU associated with the CPU
            meta_data_start_partition_id: 0 # [Optional], Start partition ID, Partition ID of the partition to start
            hash_type: sha256 # [Optional], Images HASH type, HASH type of image. All images in the container must have the same HASH type., Possible options:['sha256', 'sha384', 'sha512']
            iv_path: my_IV.bin # [Optional], IV file path, Used only for encrypted images (zero otherwise); SHA256 of the plain text image. Fixed size at 256 bits. The lower 128-bit part of the SHA256 value will be retained as IV in the encryption/decryption process.
        # ----------------------------------------------------------------------------------------------------
        #                                == Configuration of AHAB SRK table ==
        # ----------------------------------------------------------------------------------------------------
        srk_table: # [Conditionally required], SRK Table, SRK (Super Root key) table definition.
            hash_type: sha256  # [Required], SRK HASH type, HASH type of image. All images in the container must have the same HASH type., Possible options:['sha256', 'sha384', 'sha512']
            srk_array: # [Required], Super Root Key (SRK) table, Table containing the used SRK records. All SRKs must be of the same type. Supported signing algorithms are; RSASSA-PSS or ECDSA. Supported hash algorithms; sha256, sha384, sha512. Supported key sizes/curves; prime256v1, sec384r1, sec512r1, rsa2048, rsa4096. Certificate may be of Certificate Authority.
            - my_srk_public_key0.pem
            - my_srk_public_key1.pem
            - my_srk_public_key2.pem
            - my_srk_public_key3.pem
        # ----------------------------------------------------------------------------------------------------
        #     == Optional configuration of AHAB Container Certificate (if not used, erase the section) ==
        # ----------------------------------------------------------------------------------------------------
        certificate: # [Optional], Certificate container, Optional certificate container definition."
            permissions:  # [Optional], Certificate permissions, Permissions used to indicate what a certificate can be used for
            - container
            - secure_enclave_debug
            - phbc_debug
            - hdmi_debug
            - soc_debug_domain_1
            - soc_debug_domain_2
            - life_cycle
            - hdcp_fuses
            - monotonic_counter
            uuid: 00001111aaaabbbb22223333ccccdddd # [Optional], UUID, (Optional) 128-bit unique identifier
            public_key: my_cert_public_key.pem # [Required], Certificate public key, Path to Public key file (RSA and ECDSA).
            hash_type: sha256 # [Required], Certificate HASH type, HASH type of public key. The hash type should correspond to SRK keys., Possible options:['sha256', 'sha384', 'sha512']
            signing_key: my_cert_signing_key.pem # [Required], Certificate container signing key, Private key used for sign the certificate container.
        # ----------------------------------------------------------------------------------------------------
        #   == Optional configuration of AHAB Container Encryption blob (if not used, erase the section) ==
        # ----------------------------------------------------------------------------------------------------
        blob: # [Optional], Encryption blob, Encryption blob container definition
            wrapped_key_path: my_wrapped_key.pem  # [Required], KEK blob wrapped key, Wrapped Data Encryption key. Used for AES CBC-MAC (128/192/256 size).


The full AHAB configuration template could be generated by nxpimage tool "get_template" sub-command for family that supports AHAB, example:
``nxpimage ahab get-template -f rt118x ./my_config_templates``

------------------------------------------
Flash encryption engines
------------------------------------------

*nxpimage* currently supports generation of bootable images and keyblobs for NXP bus encryption engines -- OTFAD (On-the-fly AES decryption engines), BEE (Bus encryption engine) and IEE (Inline encryption engine).

IEE
^^^^^
*nxpimage* supports generation of bootable image for MIMXRT117x. More details can be found in the security reference manual: https://www.nxp.com/webapp/sps/download/mod_download.jsp?colCode=IMXRT1170SRM&appType=moderated or in the Secure Boot modes application note https://www.nxp.com/webapp/Download?colCode=AN13250

IEE engine provides means to perform inline encryption and decryption. Following algorithms are supported AES-128/256-CTR and AES-256/512-XTS.
The IEE key blob containing keys and context structures is encrypted by a KEK according to the RFC3394 key-wrapping algorithm, because the key blob resides in the external memory along with the image and it must be protected

*Generation of bootable image*
First step is to get a template for configuration. The template might look like the file below.
``nxpimage iee get-template -f rt1170 iee_template.yaml``

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
