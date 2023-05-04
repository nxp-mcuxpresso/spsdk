# Signature Provider Integration

This example demonstrates how to use a custom remote signing service for signing data such as Debug Credential file or Masterboot image.

## 1. Content
This chapter describes the content of this directory

### 1.1 Signature Provider
Content of the `hsm` directory represents the remote side of things

`hsm/sahsm.py` represents a remote signing service

`hsm/sasp.py` is the custom Signature Provider, an interface to the signing service.
It contains a class derived from `spsdk.crypto.SignatureProvider`

- the derived class has to implement:
  - `sp_type: str`: class attribute that identifies the concrete implementation of SignatureProvider
  - `sign(bytes) -> bytes`: method which performs the actual signing
  - `signature_length -> str`: property which returns a length of a signature
- the derived class can also optionally implement:
  - `info() -> str`: method which returns information about the signature provider (for debugging purposes). The default implementation returns a class name as a string
  - `verify_public_key(bytes) -> bool`: method which verifies if a given public key matches a private key. If not implemented, the `SPSDKUnsupportedOperation` exceptipon is raised.

> Omitting the implementation of optional methods such as `info()` or `verify(bytes)` does not break the functionality of application.

### 1.2 Debug Credentials
Content of the `dat` directory holds the files required for running the example for Debug Credentials application

 `dat/dck_rsa_2048.yml`
- configuration file for `nxpdebugmbox gendc` command
- new configuration field `sign_provider`/`signProvider`(both accepted) has been introduced
- new configuration field `rot_id`:
  - due to the nature of creating Debug Credential file we need to know in advance which of the private keys will be used to perform the actual signing
  - `rot_id` is a 0-based index representing the private key that will be used with respect to `rot_meta`
  - e.g.: if we want to use a private key that corresponds to the public key `p1_cert0_2048.pub`, `rot_id` has to be set to `1`

### 1.3 Masterboot Image
Content of the `mbimg` directory holds the files required for running the example for Masterboot Image application

 `mbimg/mbimg_rsa_2048.yml`
 - configuration file for `nxpimage mbi export` command
 - new configuration field `sign_provider`/`signProvider`(both accepted) has been introduced
 - the `sign_provider`/`signProvider` and `mainCertPrivateKeyFile` configuration fields are mutually exclusive as they have the same purpose


## 2. How to run this example
### 2.1 Remote signature service

- install two additional dependencies:
   - `pip install flask requests`
- run the custom HSM (a flask application) in a separate shell:
   - `python hsm\sahsm.py`

### 2.2 Debug Cedentials
The steps required for signing generated debug certificate with remote signing service:

  - Check the configuration file
    - `dat/dck_rsa_2048.yml` config file is preconfigured to use `sasp` signature provider
    - see the [next chapter](#3-signature-provider-config-values) for better understanding of the configuration values
    >  For comparison, you may try to use signing a local file, to do so, comment out line 115 in `dat/dck_rsa_2048.yml` file and uncomment line 114 or 118 (the have the same effect)
  - Generate signed debug certificate
    - `nxpdebugmbox gendc --config dat/dck_rsa_2048.yml --plugin hsm/sasp.py my.dc`

    > Use `--plugin` parameter in order to integrate custom signature provider

    > Use `--force` flag if you run the example multiple times


### 2.2 Masterboot image
The steps required for signing generated masteboot image with remote signing service:

  - Check the configuration file
    - `mbimg/mbimg_rsa_2048.yml` config file is preconfigured to use `sasp` signature provider
    - see the [next chapter](#3-signature-provider-config-values) for better understanding of the configuration values
    >  For comparison, you may try to use signing a local file, to do so, comment out line 34 in `mbimg/mbimg_rsa_2048.yml` file and uncomment line 32 or 33 (the have the same effect)
  - Generate signed masterboot image
    - `nxpimage mbi export --plugin hsm/sasp.py mbimg/mbimg_rsa_2048.yml`

    > Use `--plugin` parameter in order to integrate custom signature provider


## 3 Signature provider config values
The signature provider configuration must meet following rules:
  - Configuration key
    - key names `sign_provider` or `signProvider` are allowed

  - Configuration value
    - format `"type=<sp_type>;<key1>=<value1>;<key2>=<value2>;..."`
    - the `sp_type` has to match the sp_type class attribute defined in the custom signature provider(`hsm/sasp.py`)
    - the remaining key-value pairs are passed to the `__init__` method of the concrete Signature Provider
    - e.g.: `"type=file;file_path=private_key.pem"` will instantiate `spsdk.crypto.PlainFileSP(file_path='private_key.pem')`

