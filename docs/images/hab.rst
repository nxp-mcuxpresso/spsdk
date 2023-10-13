------
HAB
------

HAB (High Assurance Boot) provides a mechanism to ensure that the running software can be trusted.
Nxpimage application is used for generation of HAB container including CSF data and image encryption(if applicable).
It is an actual successor of legacy elftosb and CST tools.

Compared to other SPSDK image types, the HAB container configuration is stored in BD configuration files.
The main reason for it is keeping the backwards compatibility with legacy elftosb and CST tools.
BD configuration file instructs nxpimage how the image and CSF data will look like.

There are three supported types of images:

* plain
* authenticated
* encrypted


Examples
================================
| HAB Export
| ``nxpimage hab export --command "path\to\config\file.bd" --output path\to\output.bin``

| HAB Parse
| ``nxpimage hab parse --binary "path\to\output.bin" path\to\output\dir``


Configuration file types
================================


.. code-block::
   :caption: Example of Plain BD config

    options {
        flags = 0x00;
        startAddress = 0x2024ff00;
        ivtOffset = 0x0;
        initialLoadSize = 0x100;

        entryPointAddress = 0x202629e1;
    }

    sources {
        elfFile = extern(0);
    }

    section (0) {
    }


.. code-block::
   :caption: Example of Authenticated BD config

    options {
        flags = 0x08;
        startAddress = 0x1000;
        ivtOffset = 0x1000;
        initialLoadSize = 0x2000;
        entryPointAddress = 0x34e1;
    }

    sources {
        elfFile = extern(0);
    }

    constants {
        SEC_CSF_HEADER              = 20;
        SEC_CSF_INSTALL_SRK         = 21;
        SEC_CSF_INSTALL_CSFK        = 22;
        SEC_CSF_INSTALL_NOCAK       = 23;
        SEC_CSF_AUTHENTICATE_CSF    = 24;
        SEC_CSF_INSTALL_KEY         = 25;
        SEC_CSF_AUTHENTICATE_DATA   = 26;
        SEC_CSF_INSTALL_SECRET_KEY  = 27;
        SEC_CSF_DECRYPT_DATA        = 28;
        SEC_NOP                     = 29;
        SEC_SET_MID                 = 30;
        SEC_SET_ENGINE              = 31;
        SEC_INIT                    = 32;
        SEC_UNLOCK                  = 33;
    }

    section (SEC_CSF_HEADER;
        Header_Version="4.2",
        Header_HashAlgorithm="sha256",
        Header_Engine="ANY",
        Header_EngineConfiguration=0,
        Header_CertificateFormat="x509",
        Header_SignatureFormat="CMS"
        )
    {
    }

    section (SEC_CSF_INSTALL_SRK;
        InstallSRK_Table="gen_hab_certs\SRK_hash.bin",
        InstallSRK_SourceIndex=0
        )
    {
    }

    section (SEC_CSF_INSTALL_CSFK;
        InstallCSFK_File="crts\CSF1_1_sha256_2048_65537_v3_usr_crt.pem",
        InstallCSFK_CertificateFormat="x509"
        )
    {
    }

    section (SEC_CSF_AUTHENTICATE_CSF)
    {
    }

    section (SEC_CSF_INSTALL_KEY;
        InstallKey_File="crts\IMG1_1_sha256_2048_65537_v3_usr_crt.pem",
        InstallKey_VerificationIndex=0,
        InstallKey_TargetIndex=2)
    {
    }

    section (SEC_CSF_AUTHENTICATE_DATA;
        AuthenticateData_VerificationIndex=2,
        AuthenticateData_Engine="ANY",
        AuthenticateData_EngineConfiguration=0)
    {
    }

    section (SEC_SET_ENGINE;
        SetEngine_HashAlgorithm = "sha256",
        SetEngine_Engine = "ANY",
        SetEngine_EngineConfiguration = "0")
    {
    }

    section (SEC_UNLOCK;
        Unlock_Engine = "SNVS",
        Unlock_Features = "ZMK WRITE"
        )
    {
    }

.. code-block::
   :caption: Example of Encrypted BD config

    options {
        flags = 0x0c;
        startAddress = 0x80001000;
        ivtOffset = 0x400;
        initialLoadSize = 0x1000;
        DCDFilePath = "dcd_files\evkmimxrt1166_SDRAM_dcd.bin";
        entryPointAddress = 0x800041f5;
    }

    sources {
        elfFile = extern(0);
    }

    constants {
        SEC_CSF_HEADER              = 20;
        SEC_CSF_INSTALL_SRK         = 21;
        SEC_CSF_INSTALL_CSFK        = 22;
        SEC_CSF_INSTALL_NOCAK       = 23;
        SEC_CSF_AUTHENTICATE_CSF    = 24;
        SEC_CSF_INSTALL_KEY         = 25;
        SEC_CSF_AUTHENTICATE_DATA   = 26;
        SEC_CSF_INSTALL_SECRET_KEY  = 27;
        SEC_CSF_DECRYPT_DATA        = 28;
        SEC_NOP                     = 29;
        SEC_SET_MID                 = 30;
        SEC_SET_ENGINE              = 31;
        SEC_INIT                    = 32;
        SEC_UNLOCK                  = 33;
    }

    section (SEC_CSF_HEADER;
        Header_Version="4.2",
        Header_HashAlgorithm="sha256",
        Header_Engine="ANY",
        Header_EngineConfiguration=0,
        Header_CertificateFormat="x509",
        Header_SignatureFormat="CMS"
        )
    {
    }

    section (SEC_CSF_INSTALL_SRK;
        InstallSRK_Table="gen_hab_certs\SRK_hash.bin",
        InstallSRK_SourceIndex=0
        )
    {
    }

    section (SEC_CSF_INSTALL_CSFK;
        InstallCSFK_File="crts\CSF1_1_sha256_2048_65537_v3_usr_crt.pem",
        InstallCSFK_CertificateFormat="x509"
        )
    {
    }

    section (SEC_CSF_AUTHENTICATE_CSF)
    {
    }

    section (SEC_CSF_INSTALL_KEY;
        InstallKey_File="crts\IMG1_1_sha256_2048_65537_v3_usr_crt.pem",
        InstallKey_VerificationIndex=0,
        InstallKey_TargetIndex=2)
    {
    }

    section (SEC_CSF_AUTHENTICATE_DATA;
        AuthenticateData_VerificationIndex=2,
        AuthenticateData_Engine="ANY",
        AuthenticateData_EngineConfiguration=0)
    {
    }

    section (SEC_CSF_INSTALL_SECRET_KEY;
        SecretKey_Name="gen_hab_encrypt\evkmimxrt1064_iled_blinky_SDRAM_hab_dek.bin",
        SecretKey_Length=256,
        SecretKey_VerifyIndex=0,
        SecretKey_TargetIndex=0)
    {
    }

    section (SEC_CSF_DECRYPT_DATA;
        Decrypt_Engine="ANY",
        Decrypt_EngineConfiguration="0",
        Decrypt_VerifyIndex=0,
        Decrypt_MacBytes=16)
    {
    }


Additional configuration parameters
====================================

| Although the nxpimage application fully supports legacy elftosb configuration files, the support of some new optional parameters has been added.
| Newly added BD configuration parameters:


+---------------------------------+----------------------------+--------------------------------------------------------------------------------+-----------------------------------------------------------------------------------------------------------------------+
| Name                            | BD Section                 | Example                                                                        | Description                                                                                                           |
+=================================+============================+================================================================================+=======================================================================================================================+
| signatureTimestamp              | options                    | signatureTimestamp = "11/05/2023 11:58:00";                                    | Timestamp of generated signature                                                                                      |
+---------------------------------+----------------------------+--------------------------------------------------------------------------------+-----------------------------------------------------------------------------------------------------------------------+
| AuthenticateCsf_PrivateKeyFile  | SEC_CSF_AUTHENTICATE_CSF   | AuthenticateCsf_PrivateKeyFile="keys/CSF1_1_sha256_2048_65537_v3_usr_key.pem"  | Path to authenticate CSF private key file. If not set, the file will be determined from InstallCSFK_File parameter    |
+---------------------------------+----------------------------+--------------------------------------------------------------------------------+-----------------------------------------------------------------------------------------------------------------------+
| AuthenticateData_PrivateKeyFile | SEC_CSF_AUTHENTICATE_DATA  | AuthenticateData_PrivateKeyFile="keys/IMG1_1_sha256_2048_65537_v3_usr_key.pem" | Path to authenticate IMG private key file. If not set, the file will be determined from InstallKey_File parameter     |
+---------------------------------+----------------------------+--------------------------------------------------------------------------------+-----------------------------------------------------------------------------------------------------------------------+
| SecretKey_ReuseDek              | SEC_CSF_INSTALL_SECRET_KEY | SecretKey_ReuseDek=true                                                        | If set, the secret key from SecretKey_Name parameter will be used. If not, a random key will be generated and stored. |
+---------------------------------+----------------------------+--------------------------------------------------------------------------------+-----------------------------------------------------------------------------------------------------------------------+
| Decrypt_Nonce                   | SEC_CSF_DECRYPT_DATA       | Decrypt_Nonce="gen_hab_encrypt/nonce.bin"                                      | If set, the nonce from the given file will be used. If not, a random nonce will be generated.                         |
+---------------------------------+----------------------------+--------------------------------------------------------------------------------+-----------------------------------------------------------------------------------------------------------------------+

YAML Configurations
================================

It is also possible to use YAML configuration instead of legacy BD format.

Example of use for export
``nxpimage hab export -c "path\to\config\file.yaml" -o "hab.bin"``

The full HAB configuration template could be generated by nxpimage tool "get_template".
``nxpimage hab get-template -o hab_template.yaml``


Supported configuration options
================================

.. include:: ../_prebuild/hab_schemas.inc
   :parser: myst_parser.sphinx_
