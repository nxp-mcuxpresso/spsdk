Creating Debug Credential with remote signing
=============================================

This example demonstrates how to use custom remote signing service to sign Debug Credential file

**How to run this example**:
1) install two additional dependencies:
   - `pip install flask requests`
2) run the custom HSM (a flask application) in a separate shell:
   - `python hsm\sahsm.py`
3) generate the Debug Credential file
   - `nxpkeygen gendc --config dck_rsa_2048.yml --plugin hsm/sasp.py my.dc`
   - you may need to add the `--force` flag it you are running the example multiple times
4) for comparison, you may try to use signing local file, to do so, comment out line 11 in yaml file and uncomment line 14 or 15 (the have the same effect)


**Under the hood**

Content of the `hsm` represents the remote side of things

`hsm/sahsm.py` represents a remote signing service \
`hsm/sasp.py` is the custom Signature Provider, a interface to the signing service:
- contains a class derived from `spsdk.crypto.SignatureProvider`
- the class has to implement:
  - `sign(bytes) -> bytes` function which performs the actual signing
  - `info() -> str` function returning some information about the signature provider (for debugging purposes)
  - `sp_type (str)` class attribute that identifies the concrete implementation of SignatureProvider

`dck_rsa_2048.yml`
- configuration file for `nxpkeygen gendc` command
- new configuration field `sign_provider`:
  - format `"type=<sp_type>;<key1>=<value1>;<key2>=<value2>;..."`
  - the `sp_type` has to match the sp_type class attribute defined earlier
  - the remaining key-value pairs are passed to the `__init__` method of concrete Signature Provider
  - e.g.: `"type=file;file_path=private_key.pem"` will instantiate `spsdk.crypto.PlainFileSP(file_path='private_key.pem')`
- new configuration field `rot_id`:
  - due to nature of creating Debug Credential file we need to know in advance which of the private keys will be used to perform the actual signing
  - `rot_id` is a 0-based index representing the private key that will be used with respect to `rot_meta`
  - e.g.: if we want to use a private key that corresponds to public key `p1_cert0_2048.pub`, `rot_id` has to be set to `1`

