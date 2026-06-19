# Keys directory

Place your signing keys here before building the bootable image.

## Required files

- `signing_key.pem`  — Private key used to sign the AHAB container header.
  The corresponding public key must be included in the SRK table below.

## SRK table (Super Root Keys)

Provide exactly four public keys (all must be of the same type and curve):

- `srk_0.pem`
- `srk_1.pem`
- `srk_2.pem`
- `srk_3.pem`

Refer to the SPSDK documentation for more details on key generation and management.
