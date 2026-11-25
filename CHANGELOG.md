# Changelog

All notable changes to SPSDK are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).
Breaking changes between major versions are described in the
[migration guide](https://spsdk.readthedocs.io/en/latest/migration_guide.html).

## [3.14.0] - 2026-11-27

### Added

- add support for mimx93w52 and mimx93w32 (i.MX 93W), based on mimx9352 without FlexSPI boot, with bootable image boards `imx93w-14x12-lpddr4x-evk` and `imx93w-14x12-lpddr4x-frdm`
- add the i.MX 95 family alias mimx9556 (HMI segment, 6x Cortex-A55), based on mimx9596
- documentation: the [nxpdebugmbox](https://spsdk.readthedocs.io/en/latest/apps/nxpdebugmbox.html) user guide describes MCXA287 and MCXA577 authenticated mass erase, preserving the mailbox session with `dat auth --no-exit` and the top-level `--no-reset` option, command permissions, and the SPSDK 3.10.0 reset-option issue already corrected in 3.11.0
- [nxpdevhsm](https://spsdk.readthedocs.io/en/latest/apps/nxpdevhsm.html):
  - the `loadKeyBlob` command with `plainInput` supports additional user keys (HKDF, HMAC, CMAC, AES and key unwrap only keys), not just CUST_MK_SK; the new `keyType` and `keyProperties` fields define the key type, size and PPROT restrictions used by the device to wrap the key
- [nxpdevscan](https://spsdk.readthedocs.io/en/latest/apps/nxpdevscan.html):
  - list devices found by device interface plugins (`spsdk.device.interface` entry point) in the new *Connected Plugin Devices* section; use `--plugin` to scan plugin interfaces only
- [nxpele](https://spsdk.readthedocs.io/en/latest/apps/nxpele.html):
  - ELE command failures now report the decoded reason (label, code and description) of the response indication in the error message; the missing baseline indications from the ELE firmware API, the HSM (SAB) rating codes of the session and key store commands and command specific root causes are now decoded instead of being shown as unknown raw numbers
- [nxpcrypto](https://spsdk.readthedocs.io/en/latest/apps/nxpcrypto.html):
  - add `--ca-key`, `--ca-cert` and `--ca-password` options to `pki-tree ahab` and `pki-tree hab` to build the PKI tree on top of an existing root CA instead of generating a new one; the key is checked to match the CA certificate and a copy of the CA is stored in the tree, so it can be extended later
- documentation: the list of supported devices is split into groups by product line (e.g. MCX Series, i.MX RT Crossover MCUs), each group on its own page, with an overview of all groups and their devices
- documentation: the [nxpele](https://spsdk.readthedocs.io/en/latest/apps/nxpele.html) user guide describes the U-Boot requirements of the `uboot_serial` and `uboot_fastboot` modes: the NXP U-Boot release that contains the `ele_message` command by default, the configuration needed for older releases, loading U-Boot to RAM for nxpele and the `Unknown command 'ele_message'` error
- documentation: add the FRDM-MCXN236 secure boot Jupyter notebook example (`examples/mbi/mcxn236_secure_boot`); it enables secure boot with a signed image and the CMPA, contains a checklist to go through before the CMPA is written, explains why an unsigned image loaded from an IDE does not start, and describes how to recover the device, from writing a signed image or resetting the CMPA to Mass Erase
- `spsdk utils families` lists the families grouped by product line, in the same way as the `get-families` command of other tools
- [nxpimage](https://spsdk.readthedocs.io/en/latest/apps/nxpimage.html):
  - `bootable-image export` accepts OTFAD, IEE and IPED YAML/JSON configurations in `keyblob`, builds the decryption table and encrypts the assembled application segments using the configured address ranges; binary keyblobs retain the existing assembly-only behavior
  - add FCB presets of standard memories for mimx9596 (Micron MT35X Octal DDR at 200 MHz and 133 MHz, Winbond W25Q512NW single pad at 133 MHz); the FCB configuration accepts a `preset` with optional `fcb_settings` applied on top of it, and `bootable-image fcb get-templates --presets` creates the configuration files filled by the presets
  - add XSPI NAND FCB support for RT266x (`bootable-image fcb` with memory type `xspi_nand`); the NAND FCB embeds the Serial NAND configuration block and its CRC32 checksum is calculated on export and verified on parse
  - `mbi` for MCX E3 supports the extended fields of the HSE Image Vector Table: the XRDC MDAC configuration address and the recovery application start address and length (all MCX E31x and MCX E32x devices), and the start address and boot enable bit of the Cortex-M7_1 core (`cm7_1StartAddress`, `cm7_1Enable`, mcxe327 and mcxe32b); the `appSwtInit` option is now applied to the boot configuration word and all IVT fields are restored by `mbi parse`
  - `bootable-image xmcd crc-fuses-script` supports RT266x; the script enables the XMCD CRC32 check (`BOOT_CFG8` `XMC_CRC32_CHECK_EN`) and programs the expected CRC32 into `BOOT_CFG11`
  - `otfad export` and `iee export` respect an image file extension (`.bin`, `.hex`, `.srec`, `.s19`, `.simg`, ...) given in `output_name`, `keyblob_name` and `encrypted_name`; the extension selects the format of that file, so `keyblob_name: otfad_keyblobs.bin` with `output_format: srec` now creates a binary `otfad_keyblobs.bin` instead of an S-record `otfad_keyblobs.bin.srec`. Names without an image file extension still get the extension and format of `output_format`
  - `ahab sign` reports a warning, visible without the verbose option, when the signing configuration changes the flags (used SRK ID, SRK revoke mask, check all signatures, fast boot, etc.), fuse version or SW version of a container in the signed image
  - `bootable-image` supports the LPSPI NOR recovery boot memory types `recovery_spi_mbi` and `recovery_spi_sb31` on mimxrt798s, mimxrt758s and mimxrt735s (image at offset 0x1000)
  - add support for the AISEC protected-directory (dir-v5) container used to securely package AI/ML model directories (weights, configuration, tokenizer) for mimx9596; the new `aisec` command group provides `export`, `parse`, `verify` and `get-template` commands, supports the discrete (keystore MMK) and integrated (ELE/EL2GO provisioning blob) flows and per-member `enc_auth`/`auth_only`/`none` protection, see [AISEC protected-directory container](https://spsdk.readthedocs.io/en/latest/images/aisec.html)
  - extend AISEC dir-v5 support to i.MX93 (mimx9352 and aliases), using its complete 32-byte AHAB v1 SRK table hash for device binding rather than the truncated AHAB v2 hash used on i.MX95 B0
- [nxpmemcfg](https://spsdk.readthedocs.io/en/latest/apps/nxpmemcfg.html):
  - `spi_nor` option words on mimxrt798s, mimxrt758s and mimxrt735s now follow the ROM layout: LPSPI0-13 instances, manual/auto memory type and both option words (bits [27:24] of option0 are reserved), so `parse` no longer fails on these devices
- [blhost](https://spsdk.readthedocs.io/en/latest/apps/blhost.html):
  - add `--erase-only` option to `flash-image` to erase just the flash blocks covered by the given image (sparse/bin/s19/hex/elf) without writing any data, so the flash can be erased by one tool and programmed without erase by another one
  - `flash-image` now aligns the erase region to the erase block size reported by the target (`FlashSectorSize` for internal flash, the sector size from `ExternalMemoryAttributes` for external memories) instead of a fixed 1 kiB alignment; the alignment can be forced with the new `--erase-alignment` option
  - `flash-image` automatically increases the communication timeout based on the amount of data to be erased or written, so a long lasting operation on a large image is no longer reported as a missing response; an explicitly given `--timeout` is never lowered
  - `flash-image` now reports the progress of the erase phase as well; a large region is erased by several `flash-erase-region` commands operating on whole erase blocks, as the bootloader does not report any progress during a single erase command
- [nxpuuu](https://spsdk.readthedocs.io/en/latest/apps/nxpuuu.html):
  - `write` without `-b` now loads a bootloader image using the `spl` script, so both SPL and U-Boot are loaded; previously the download finished after the ROM stage. On i.MX 8ULP, 91 and 93, whose SPL loads U-Boot from the ROM download stream, the `spl` script finishes after the ROM stage. UUU scripts, directories and ZIP/SDCARD archives are still passed to the UUU auto-detection

### Fixed

- [nxpimage](https://spsdk.readthedocs.io/en/latest/apps/nxpimage.html):
  - `mbi get-templates` for the MCX E3 signed XIP image no longer shows the `Application Boot Header Settings` section header in the middle of the HSE IVT settings; the template has the same sections as the plain and SMR image templates
  - fix bootable-image OTFAD, IEE and IPED encryption range handling, keyblob sizing and export
    behavior, including byte swapping, bypass contexts, boot-header overlap checks and parsed IEE
    tables
  - `utils binary-image convert` no longer reports a misleading "base offset was trimmed" warning when converting to BIN or SPARSE; omitting the leading padding before the first data is the default behavior and no data is lost, so it is now logged as info with the omitted address range (which failed the conversion with `SPSDK_WARNING_STRICT` enabled). Conversion to HEX/S19/SREC now keeps the original addresses instead of relocating the data to address 0
  - fix `bootable-image parse` silently dropping the FCB segment when the MBI image declares a bigger length than the data really present in the image (typically an image built from an ELF/AXF file, where the trailing padding is not materialized). Such an image was reinterpreted as starting at the MBI offset, which hid the FCB bytes inside the MBI segment. A segment identified by a magic tag is now trusted and no interpretation placed behind it is used
  - for XIP images, an IVT total length bigger than the available data is now reported as a warning instead of an error, because the declared length is only the area reserved by the linker and the missing padding is never executed; for load-to-RAM images it stays an error, as the length drives how many bytes the boot ROM copies into RAM
  - fix AHAB double authentication images rejected by ELE on i.MX943 and i.MX95 with `DOUBLE_AUTH_EN` fused: the ELE and V2X container images had load address 0; they now get separate load addresses (MCU TCM for ELE, DDR for V2X), which can be overridden by the hidden `ele_load_address` and `v2x_load_address` options, and the V2X container is placed after the OEI DDR image
  - fix `ahab sign` leaving the OEM container of a double authentication image unsigned on i.MX943 and i.MX95: the embedded V2X container image caused the container to be treated as a V2X container, which `ahab sign` skips; only containers with the V2X firmware are skipped now
  - fix `ahab sign` (and every other command that parses and exports an AHAB image again) zeroing the data stored in the gaps between the images, e.g. the content prefilled by `gap_after_image_file`: the parsed AHAB image now keeps the content of the gap behind each image, so the exported image is identical to the parsed one; `ahab parse` also stores the gaps in the generated configuration (`gap_after_image` and `gap_after_image_file`)
  - fix `ahab sign` of i.MX943 and i.MX95 FlexSPI NOR images built by imx-mkimage, which did not boot in OEM closed lifecycle: the parsed bootable image kept only the 512 bytes of the FCB, so the rest of the FCB area up to the container set (the FlexSPI NOR extension and padding, authenticated against the FCB copy in the AHAB container) and the unused key blob area were replaced by the image pattern; the data stored between the bootable image segments is now kept, so the exported image is identical to the parsed one
  - fix `ahab sign` and other commands that parse a bootable image without the memory type silently using the first matching memory type, e.g. Serial downloader for i.MX943 FlexSPI NOR images, which dropped the FCB and the secondary container set; the memory type proven by a segment with a unique identifier (e.g. FCB) and describing the largest part of the input is used now, and `ahab sign` warns when part of the input image is dropped
- [nxpele](https://spsdk.readthedocs.io/en/latest/apps/nxpele.html):
  - `get-events` now prints the raw hex value next to each decoded event field and classifies every event as a failure, a warning (successful request with an indication) or a success; unknown values are reported as e.g. `0xEE - Unknown command` instead of a "non-existing tag" message, and the misleading "No authentication failure" description of indication 0xEE now states that the container was not authenticated (accepted in open lifecycle only)
  - add missing EdgeLock Enclave command IDs to the event decoding
  - `reset` exits with a non-zero code when the reset request cannot be delivered to the EdgeLock Enclave; previously it printed `ELE reset failed` and exited with 0
  - `session-open`, `keystore-open`, `public-key-export` and `export-nxp-prod-ka-puk` exit with a non-zero code when no valid handle or key data is returned instead of printing a warning and exiting with 0
  - ELE commands over U-Boot no longer fail when U-Boot prints an unrelated console message (e.g. a USB gadget warning) right after the response, as seen with repeated `dump-debug-buffer` calls; the response is cut to the length given in its header
- [nxpdebugmbox](https://spsdk.readthedocs.io/en/latest/apps/nxpdebugmbox.html):
  - `dat auth` no longer reports a misleading protocol version warning in the DAC versus DC verification on EdgeLock Enclave based devices (i.MX8ULP, i.MX9, RT118x, ...), where the DAC and DC protocol versions are not compared and may legitimately differ
  - use a 4 byte authentication beacon in the DAT response of mimxrtl3450; the 2 byte beacon left the signature block of the signed message at an offset that is not word aligned and the ROM rejected the authentication
  - `dat dc export` and `dat dc get-template` for mimxrtl3450 use the hybrid (ECC + PQC) AHAB v2 debug credential with `public_key_0`/`signer_0` and `public_key_1`/`signer_1`; the legacy ELE v1 format was used before and a hybrid configuration failed with `Missing field(s): signer`
  - `famode-image export` no longer appends the manifest digest to the signed FA request of kw47b42zb7 and mcxw72x; the ROM rejected such a request, so the transition to the OEM field return lifecycle failed
  - `cmd ispmode` without `--mode` now uses the per-family default ISP mode from the database; on KW43/MCXW70 it is `0xF` (auto-detection on all enabled ISP interfaces) instead of `1`, which selected the I2C interface only, so the device did not respond over UART after entering ISP mode
  - `dat auth` on i.MX91 no longer reports a missing AHB access after a successful authentication; the AHB check halted the core through the Cortex-M `DHCSR` register at `0xE000EDF0`, which i.MX91 (Cortex-A55 only) does not have, the address is DRAM on its system bus. Core halt, resume and status are now reported as not supported for i.MX91 instead of accessing this address
  - `mem-tool test-connection --help` shows the default value (`cpu_mem`) of the optional `-d/--destination` option
  - `start-debug-session` now reports an actionable error on RT1180/RT1189, i.MX91, i.MX93 and i.MX94/i.MX95 when debug access is already open (e.g. after booting from SD card with debug already authenticated): on these families the Debug Mailbox AP and a standard MEM-AP are two mutually exclusive, HW-multiplexed personalities of the same AP index, so the previous generic "IDR value doesn't match the expected value" message gave no indication that the command is expected to fail in this state and that direct memory read/write still works without it
- [nxpfuses](https://spsdk.readthedocs.io/en/latest/apps/nxpfuses.html):
  - RT266x: the `BOOT_CFG4` to `BOOT_CFG8` fuse words now expose the individual boot configuration bitfields described in the reference manual (e.g. `XMC_CRC32_CHECK_EN` and `XMC_DISABLE` in `BOOT_CFG8`) instead of a single opaque 16-bit value
- [nxpimage](https://spsdk.readthedocs.io/en/latest/apps/nxpimage.html):
  - `mbi export` and `mbi verify` of images with a Boot Configuration Area (BCA), e.g. for mcxc444 and mwct20d2a, no longer report the `Feature 'bca' verification` "Not implemented" warning, which failed the export with `SPSDK_WARNING_STRICT` enabled; the BCA verification checks the BCA tag and size and reports the configured register values
  - `iped export` no longer requires the IPED context to cover the trailing zero padding of a data blob, such as the block-size padding of a sparse image; the padding beyond the context end is left unencrypted, and the error for data that really exceeds the context now reports the required `end_address`
  - `iped export` resolves output file names in the same way as OTFAD and IEE: a plain file name is placed into `output_folder` and a name containing a path is relative to the configuration file
  - `iped export` pads the standalone IPED table to the `table_size` (0x400 on RT266x) like the bootable image keyblob segment, and uses the IPED address alignment as the sparse block size, so the sparse table is no longer 0x1000 bytes and sparse encrypted data is no longer padded to 4 KiB
  - the IPED context `nonce` is now marked as required in the configuration schema and template for RT266x; the ROM configuration blob always serializes it and a missing nonce was rejected only after schema validation
  - `bootable-image parse` no longer fails while generating the configuration of an i.MX image without the optional secondary AHAB container set; the absent segment is kept as an empty value and the configuration can be exported again
  - MBI configuration loading and export are faster: the TrustZone registers database is loaded only when the TrustZone data are really needed (custom preset, parse or verification), not for the default TrustZone of an MBI without a preset
  - the AHAB SRK table loaded from a configuration now requires exactly four SRK keys also when used through the Python API (e.g. `SecureBinary4.load_from_config`); previously only the CLI schema validation enforced it, and the API silently created an SB4.0 or AHAB image with a malformed SRK table
  - AHAB on RT266x: an SRK table that mixes key types or sizes (e.g. ECC P-256 and P-384) with `hash_algorithm: default` no longer gets a different default hash for each key (SHA256 for P-256, SHA384 for P-384), which caused ELE events on the device; the default hash algorithm of the first SRK key is used for the whole table. The verifier now rejects SRK tables whose records use different hash algorithms
  - `iped export` supports IPED regions that cover only part of a data blob, such as an AHAB image where only the application is encrypted; each part of the blob is encrypted with the region that contains it and data outside all regions is kept as plaintext, instead of failing with "No IPED context covers data range"
  - `bootable-image parse` no longer fails with "Wrong alignment" on segments of variable size, such as the SB3.1 segment of `recovery_spi_sb31` memory type
  - `sb21 export`: the warning for an image that is not within its OTFAD key blob identifies the `encrypt` command (`keyblob_id` and file), the image address range and other key blobs covering the image; previously only the key blob range was reported
  - `ahab parse` writes the image `hash_type` in lowercase (e.g. `sha256`) as listed in the configuration template, so the parsed configuration can be exported again; previously the uppercase value (e.g. `SHA256`) failed the schema validation. Uppercase values in existing configurations are still accepted
  - `HabImage.parse()` and `hab parse` no longer fail with "Application offset could not be found" for HAB images of Cortex-A based devices (e.g. i.MX6 and i.MX8M images created by U-Boot `mkimage`); when no Cortex-M vector table is found, the application offset is taken from the IVT entry point and its end from the Boot Data Table image length, an IVT-referenced but empty (unsigned) CSF area is reported as no CSF, and an image for a family not present in the database can be parsed. New `HabImage.find_offset_of_hab()` locates the HAB container in a binary with leading data
- [nxpcrypto](https://spsdk.readthedocs.io/en/latest/apps/nxpcrypto.html):
  - `rot export` and `rot calculate-hash` for HAB devices set the SRK CA flag from the certificate Basic Constraints (`CA:TRUE`) like CST `srktool` (OpenSSL `X509_check_ca`), certificates without Basic Constraints keep the legacy Key Usage `keyCertSign` rule; SRK certificates generated by `pki-tree hab --srk-is-ca` have no Key Usage extension, so the flag was left cleared, and the SRK table and SRK hash differed from the CST ones, making HAB authentication fail in closed mode
- `spsdk utils setup-autocomplete`:
  - PowerShell completion of a file path no longer drops the already typed directory part (e.g. `subfolder/`) and cycles through bare item names; path completion is delegated to the PowerShell file name completer, which also quotes names with spaces
  - bash completion of a file path no longer appends a space after a directory name and no longer splits file names containing spaces
- [blhost](https://spsdk.readthedocs.io/en/latest/apps/blhost.html):
  - an interrupted data phase (e.g. a failed USB write during `receive-sb-file`) is reported as `NoResponse` together with the number of bytes sent, instead of an unknown error with a `Success` status, when the target does not send a final response
  - `get-property --family mcxc151 17` (also mcxc161, mcxc162) prints the lifecycle name, e.g. `Life Cycle State = DEVELOP (0x3)`, instead of the bare value `0x3`; `nxpdebugmbox cmd -f mcxc151 get-crp` prints the lifecycle name as well. The MCXC151 program lifecycle Jupyter notebook now passes `--family` to `get-property 17` and states the correct expected output
- values given by the `-oc`/`--override-config` option of all applications are now converted to the type required by the configuration schema (boolean, integer/number, array, object), so e.g. `-oc containers/0/container/images/0/is_encrypted=true` no longer fails with `must be boolean`; values the schema accepts as strings (paths, keys, hex strings) are kept unchanged
- [nxpdevhsm](https://spsdk.readthedocs.io/en/latest/apps/nxpdevhsm.html):
  - the implicitly added CUST_MK_SK/SBKEK `loadKeyBlob` command is inserted before trailing `reset` commands in SB3.1 and SB4 files, so it is no longer placed after a final reset where it was never executed
- [crypto](https://spsdk.readthedocs.io/en/latest/api/crypto.html):
  - a malformed signature provider configuration (e.g. `so_path:<path>` instead of `so_path=<path>`, a missing `type`, an unknown provider type or a missing required parameter) is now reported with the actual configuration problem instead of a misleading "file not found" error caused by falling back to a private key file path; key file paths containing `=` keep working
  - a password provided for a private key that is not encrypted (RSA, ECC, ML-DSA, PEM or DER) is now ignored with a warning instead of blocking the signing; an encrypted key still requires the correct password
  - update the [crypto](https://spsdk.readthedocs.io/en/latest/api/crypto.html) keys Jupyter notebook to list the currently supported key types (ML-DSA, Dilithium with the `dil2`/`dil3`/`dil5` names, LMS) and to show post-quantum key generation and key conversion with [nxpcrypto](https://spsdk.readthedocs.io/en/latest/apps/nxpcrypto.html)
- [el2go-host](https://spsdk.readthedocs.io/en/latest/apps/el2go-host.html):
  - EL2GO HTTP error responses (status code >= 400) are now always raised as `SPSDKHTTPClientError`; previously a response with a valid JSON error body (e.g. a normal `401 Unauthorized`) was silently returned instead of raised, which the EL2GO plugin then surfaced as a generic `RuntimeError`/"GENERAL ERROR" instead of a meaningful error. If you call `EL2GOTPClient`/`EL2GOClient` methods directly and inspect `response.status_code`, catch `SPSDKHTTPClientError` instead
- database: with the cache disabled (`SPSDK_CACHE_DISABLED`), SPSDK no longer reports that no family supports a feature; all families were missing, so for example `nxpdebugmbox famode-image export` failed with "family doesn't support TrustZone". The "nothing to clear" message of the cache cleanup is logged as info instead of an error, as it was printed on every start with the cache disabled

## [3.13.0] - 2026-11-03

### Added

- add support for mcxc353, mcxc352
- add support for mcxn526t
- add support for mimxrt1183 and mimxrt118d
- [nxpdebugmbox](https://spsdk.readthedocs.io/en/latest/apps/nxpdebugmbox.html):
  - add `tool execute` command to start (or restart) execution from a vector table on any Cortex-M based ARM device connected over a CoreSight debug probe; optionally loads a binary into target memory first, otherwise reads the existing vector table already present at the given address (e.g. an already-flashed bootable image)
  - the `-f`/`--family` option of `tool list-probes` is no longer mandatory; when omitted, connected probes are listed for all architectures instead of being filtered to a single family
  - add `dat export-dar` command to export the Debug Authentication Response binary; `dat auth --debug-artifacts` now stores the DAC binary as well
  - `mem-tool test-connection` prints a colour-coded table with the status of each debug access gate (probe opened, probe connected, debug access, debug mailbox or SDA access point, memory access), so it is visible at which step the connection fails
- [nxpimage](https://spsdk.readthedocs.io/en/latest/apps/nxpimage.html):
  - allow the `devhsm` SRK set in the signed MBI configuration; the AHAB v2 SRK set field is four bits wide, so it can hold the DevHSM value
  - add optional secondary-image table for the `sd` and `emmc` bootable images of mimxrt2660, mimxrt2661, mimxrt2662 and mimxrt2663
  - add parallel verification support to AHAB containers of mimxrt2660, mimxrt2661, mimxrt2662 and mimxrt2663
- [nxpele](https://spsdk.readthedocs.io/en/latest/apps/nxpele.html):
  - add `forward-boot-crypto` command and the matching signed message
  - add HSE core reset release and SMR/core boot status attributes to control and diagnose the multi-core boot
  - support the second Cortex-M7 core (M7_1) of the dual-core mcxe327 and mcxe32b in the HSE commands
- [nxpcrypto](https://spsdk.readthedocs.io/en/latest/apps/nxpcrypto.html):
  - add `--fuse-script` option to `rot calculate-hash` to store a device specific fuse script that burns the calculated RoT hash; it is not available for devices storing the RoT hash in the PFR CMPA
- [blhost](https://spsdk.readthedocs.io/en/latest/apps/blhost.html):
  - add `--mode` option to `trust-provisioning prove_genuinity` to select the `ECDSA` or `Hybrid` mode; the default is `ECDSA`, so the previous behavior is unchanged
- debug probes:
  - add ARM ADIv6 (CoreSight 600 / DPv3) support: automatic ADI version detection, ADIv6-aware Access Port addressing (memory-mapped AP base address and DP SELECT1 for 64-bit address spaces), and auto-discovery of the ADIv6 MEM-AP and debug mailbox via CoreSight ROM table walk
  - each debug probe now declares its supported ADI versions via `SUPPORTED_VERSIONS`; connecting to an unsupported ADI version raises a clear error instead of silently misbehaving
- add `SPSDK_DEPRECATED_STRICT` environment variable; when set, deprecated register aliases and deprecated schema properties are reported as errors instead of warnings

### Changed

- `spsdk-pyocd` is no longer installed by default; it was an optional PyOCD debug probe plugin unconditionally pinned as a core dependency. If you rely on PyOCD-based debug probes, install it explicitly with `pip install spsdk-pyocd`
- `DebugProbeCoreSightOnly` has moved from `spsdk.debuggers.debug_probe` to `spsdk.debuggers.debug_probe_arm`; debug probe plugins importing it from the old location fail to load, update them to at least spsdk-jlink 0.3.12, spsdk-pemicro 0.3.12, spsdk-lauterbach 0.5.9 and spsdk-mcu-link 0.6.18

### Fixed

- [nxpdebugmbox](https://spsdk.readthedocs.io/en/latest/apps/nxpdebugmbox.html):
  - add missing `srk_revoke_mask` property to the EdgeLock Enclave V2 DAT configuration schema; the field was already consumed to build the signed DAR message and verified against fuses, but was stripped from the schema, causing a false "Unknown property found in configuration" warning and its absence from `dat get-template` output
  - `dat dc export` no longer raises false `Unknown property found in configuration: 'cc_vu'`/`'cc_beacon'` warnings for EdgeLock Enclave container v2 devices (e.g. mimx9596, mimx943); the pre-validation auto-fill of these fields now only applies to ELE container v1 devices, whose schema actually declares them
  - fix the debug authentication waiting for the debug mailbox only on one status bit; on mimx943 with hybrid keys the mailbox was used before the reset request had been processed and the following command failed
  - decode the debug mailbox command status from its lower 16 bits, so a readable error description is reported instead of the generic "Status code is not success" message
  - use the AHB access port of the Cortex-M7_0 core (AP4) for all mcxe31b, mcxe32b and mcxe327 devices; the memory access through AP5 failed with a wire ACK fault on the dual-core devices when the second core was not running
- [nxpimage](https://spsdk.readthedocs.io/en/latest/apps/nxpimage.html):
  - fix AHAB container signature verification for keys declaring the plain `RSA` signing algorithm, which is PKCS#1 v1.5 padded; the verification incorrectly assumed RSA-PSS padding for all RSA keys and rejected valid containers
  - align the AHAB v2 signature block members (SRK table array, signature, certificate and blob) and the signatures inside the AHAB certificate to a word boundary on kw43l43z97, mcxa457 and mcxn556s; unaligned offsets caused a data abort in the ROM
  - report the actual reason why a bootable image has been rejected instead of the generic "image is not matching any of memory types" message
  - read the AHAB container offset from the IVT layout of the actual device family; families overriding the IVT offsets failed to parse their signed MBI
  - AHAB `double_authentication` image extracts the ELE and V2X firmware correctly from NXP firmware with container version 2 (mimx943, mimx95294, mimx9596 B0); the V2X container is no longer skipped and the ELE and V2X images keep the original NXP container layout, so their hashes match. A version 2 NXP firmware used in a version 1 AHAB image is now reported as an error
  - map an SRK table with LMS keys to the PQC SRKH fuses, the same way as ML-DSA and Dilithium tables, instead of the classic SRKH fuses
  - generate a single shared set of SRKH fuse files for MPU images with one NXP signed container followed by several OEM signed containers using the same SRK table, instead of one set per OEM container
  - handle the ICCS signed ELE firmware of mimxrt2660, mimxrt2661, mimxrt2662 and mimxrt2663 as a binary container without requiring an OEM blob and decode the full AHAB v2 SRK set field
  - correct the list of supported signing algorithms, hash algorithms and image types of mimxrt2660, mimxrt2661, mimxrt2662 and mimxrt2663
  - remove Cortex-M7 from the AHAB `core_ids` of mimxrt1181 and mimxrt1182, which have a single application core
  - warn when a user defined `image_offset` is ignored because the `serial_downloader` target memory computes the offsets automatically
  - remove the misleading "Not implemented" warning printed for every MBI export with TrustZone enabled
  - fix the `reset` command in the SB3.1 configuration schema; its `params` property was misspelled and therefore never parsed
- [nxpcrypto](https://spsdk.readthedocs.io/en/latest/apps/nxpcrypto.html):
  - fix `key convert --puk` silently exporting the private key instead of the public key for post-quantum keys (ML-DSA, Dilithium) and LMS keys
- [crypto](https://spsdk.readthedocs.io/en/latest/api/crypto.html):
  - report an actionable error instead of an `UnsupportedAlgorithm` traceback when loading a composite (hybrid) certificate holding a classic and a post-quantum public key in a single `SubjectPublicKeyInfo`; the error now names the algorithm OID and describes the supported AHAB dual-signing approach, including how to split a composite key with `pqctool split`
- [nxpele](https://spsdk.readthedocs.io/en/latest/apps/nxpele.html):
  - fix the response size check of signed messages carrying the `WRITE_SEC_FUSE_REQ` command, which failed with "Message SIZE in response is invalid: 0x3"
- [nxpuuu](https://spsdk.readthedocs.io/en/latest/apps/nxpuuu.html):
  - fix the image argument of `write -b spl`, which is now substituted in every boot stage of the SPL boot template
- libusbsio:
  - fix setting of the IRQ notifier pin: `nirq_port=0` was rejected and the pin was configured before the LIBUSBSIO device was opened
- SPSDK logging no longer fails to strip the color escape sequences and no longer raises a `TypeError` when a non-string object (e.g. an exception) is logged
- report the original input instead of a mutated value in the error of a file or hex value that cannot be loaded
- use explicit UTF-8 encoding in text file operations, so the behavior does not depend on the system locale (default encoding changes in Python 3.15)
- add `pyyaml` as an explicit core dependency; it was only ever installed transitively (e.g. via `spsdk-pyocd`), so a minimal SPSDK installation without that plugin used to fail with `ModuleNotFoundError: No module named 'yaml'`
- remove i.MX 95 family aliases that are not orderable part numbers: `mimx9512`, `mimx9514`, `mimx9516`, `mimx9532`, `mimx9542`, `mimx9544` and `mimx9584`

## [3.12.0] - 2026-10-13

### Added

- [nxpdebugmbox](https://spsdk.readthedocs.io/en/latest/apps/nxpdebugmbox.html):
  - add `dat dc verify` command to verify a Debug Credential binary file against a family
  - add `--debug-artifacts` / `-da` option to `dat auth` to store the signed DAR binary for debug and analysis purposes

### Fixed

- [nxpdebugmbox](https://spsdk.readthedocs.io/en/latest/apps/nxpdebugmbox.html):
  - validate that all debug credential keys use the same size and report a clear reason when a debug credential binary cannot be parsed (mixed or truncated key sizes) instead of raising an unhandled error
- [nxpimage](https://spsdk.readthedocs.io/en/latest/apps/nxpimage.html):
  - align `hse smr-entry create-auth-tag` hash algorithm and authentication scheme options with the SMR entry template, and remove the unsupported XCBC_MAC option
- [nxpuuu](https://spsdk.readthedocs.io/en/latest/apps/nxpuuu.html):
  - restore the terminal cursor after a command finishes; the progress bar hid the cursor and never showed it again
  - fix the `progress_bar` argument of `SPSDKUUU` being ignored, which kept the progress bar always enabled

## [3.11.0] - 2026-08-25

### Added

- add support for rt1150 and rt1152
- add support for mcxa557
- add support for mcxe32b and mcxe327
- add support for kw43b43z92, kw43b43z93, kw43b43z96, kw43b43z97, kw43b43zc2, kw43b43zc3, kw43b43zc6, kw43b43zc7, kw43e43zc7, mcxw706a, mcxw706c, mcxw706d, mcxw70aa, mcxw70ac, and mcxw70ad
- add support for mimx93714 and mimx93734
- add mimx943 A1 support
- [nxpdebugmbox](https://spsdk.readthedocs.io/en/latest/apps/nxpdebugmbox.html):
  - add program lifecycle debug mailbox command for mcxc151, mcxc161, and mcxc162 devices
- [nxpimage](https://spsdk.readthedocs.io/en/latest/apps/nxpimage.html):
  - add IPED tool
  - add `raw_export_as_subregs` flag for grouped register byte export
  - add BinaryImage draw support for SB4.0 containers
  - add cert_version support to V2 AHAB signed message containers
  - allow `parse` command to print YAML to stdout when output is not specified
  - use Yocto generic filenames as defaults in MPU bootable image templates
  - add `--no-fuse-scripts` to ahab export and handle `uuu_version` in nxpuuu scripts
- [pfr](https://spsdk.readthedocs.io/en/latest/apps/pfr.html):
  - support writing monotonic counter special values
  - support MBI binary as rot-config input for pfr export
  - add RSA4096 chain certificate warning for LPC55S16
- use ML-DSA implementation from cryptography 48
- add support for Python 3.14

### Fixed

- [nxpdebugmbox](https://spsdk.readthedocs.io/en/latest/apps/nxpdebugmbox.html):
  - fix test connection handling
  - fix mismatched expected transfer size
  - fix no-reset debug mailbox option
  - fix mcxn947 flash read over J-Link
  - revert debug auth reset that broke J-Link DAT authentication
- [nxpdevhsm](https://spsdk.readthedocs.io/en/latest/apps/nxpdevhsm.html):
  - fix keyblob command position
- [nxpimage](https://spsdk.readthedocs.io/en/latest/apps/nxpimage.html):
  - fix KeyError in hex_value_option for multi-word options
  - fix mcxc151 IMG_MISR_SEED byte order in CMPA_PSWD
  - fix mimx943 A0 AHABv2 algorithm definitions
  - parse NXP containers as binary
  - fix ECC-only MBI broken by PQC signature_algorithms addition
  - fix PQC SRKH fuses and add DILITHIUM/ML-DSA to signature_algorithms
  - limit RSA pubExponentSize to 8 bytes for HSE-B devices
  - disable SIPHASH and DH key types for HSE-B devices
  - improve AHAB signature verification error messages
  - fix mimx95 b0 fastboot container order and alignment
  - restrict mcxl255 SB3.1 commands
- [nxpshe](https://spsdk.readthedocs.io/en/latest/apps/nxpshe.html):
  - raise a user-friendly error on reset instead of a generic ValueError
- [pfr](https://spsdk.readthedocs.io/en/latest/apps/pfr.html):
  - prevent empty custom_value dict from falling through to template defaults
- fix mimx95 reset problem
- harden database cache deserialization with restricted unpickler
- fix HMAC cache race condition in schema_validator
- add missing mboot error codes from mcu-boot repo
- fix vulnerable OpenSSL included in cryptography wheels
- fix duplicated log and reduce false AHAB V1 error log
- add ECC individual write lock type for fuses and missing OEM_SRKH locks for mimx95
- handle expected timeout in SetBrickedMode command
- fix UsbSio I2C/SPI read returning error on device NAK

## [3.10.0] - 2026-06-19

### Added

- add mcxn246t, mcxn247t, mcxn527t, mcxn536t, mcxn537t, mcxn546t, mcxn547t, mcxn556t, mcxn557t, mcxn946t, and mcxn947t
- add i.mx93 and i.mx95 part numbers
- [nxpimage](https://spsdk.readthedocs.io/en/latest/apps/nxpimage.html):
  - add LZMA compression support to SB3.1 CmdLoad commands
  - add AHAB SRKH fuse generation for supported devices
  - add signed template generation to `bootable-image get-templates` with `--sign` and `-s`
  - add xSPI NAND support in memcfg
  - change the default bootable image output filename to `flash.bin`
- [nxpdebugmbox](https://spsdk.readthedocs.io/en/latest/apps/nxpdebugmbox.html):
  - add Jupyter notebook examples for debug authentication, including password-based authentication for mcxc151, mcxc161, and mcxc162
- [nxpdevhsm](https://spsdk.readthedocs.io/en/latest/apps/nxpdevhsm.html):
  - add `writeIFR` provisioning step support
- [nxpele](https://spsdk.readthedocs.io/en/latest/apps/nxpele.html):
  - add address-based `authKeyHandle` support for `HSE_KEY_TYPE_*_PUB_EXT` keys in SMR configuration
- [nxpdevscan](https://spsdk.readthedocs.io/en/latest/apps/nxpdevscan.html):
  - add `--baudrate` support for UART scans

### Fixed

- [blhost](https://spsdk.readthedocs.io/en/latest/apps/blhost.html):
  - treat `ROMLDR_PENDING_JUMP_COMMAND` and `ROMLDR_PENDING_RESET_COMMAND` as successful `receive-sb-file` completion
- [el2go-host](https://spsdk.readthedocs.io/en/latest/apps/el2go-host.html):
  - fix default UUU wait timeout for `UBOOT_FASTBOOT` provisioning
  - separate `oem_provisioning_config` host path from uploaded device filename
- [nxpcrypto](https://spsdk.readthedocs.io/en/latest/apps/nxpcrypto.html):
  - fix SM2 support
  - remove unsupported `none` hash choice from the CLI
- [nxpdebugmbox](https://spsdk.readthedocs.io/en/latest/apps/nxpdebugmbox.html):
  - accept zero value in debug credential UUID
- [nxpimage](https://spsdk.readthedocs.io/en/latest/apps/nxpimage.html):
  - keep existing AHAB container flags when signing bootable images for MPUs
  - fix AHAB verification for images with multiple data encryption keys
  - fix key exchange salt and user-provided info handling in signed messages
  - fix HAB encryption to reuse an existing random key
  - prevent eMMC bootable image corruption when `init_offset` changes
  - validate family and revision consistency between bootable-image and AHAB sub-configs
  - require `image_path` in whole-AHAB image configurations
  - validate `wrappingKeyId` in SB3.1 `CmdLoadKeyBlob` configurations
- [pfr](https://spsdk.readthedocs.io/en/latest/apps/pfr.html):
  - correct mcxc151 CPU identifier in CMPA configuration files
  - group mcxc151 128-bit password fields as one configuration item
- [nxpdevhsm](https://spsdk.readthedocs.io/en/latest/apps/nxpdevhsm.html):
  - log the loadKeyBlob position warning only once per image generation
- [nxpele](https://spsdk.readthedocs.io/en/latest/apps/nxpele.html):
  - accept `port,baudrate` syntax for U-Boot serial connections
  - prevent unsupported `DH_PAIR` key type selection in HSE key info configuration
- [nxpdevscan](https://spsdk.readthedocs.io/en/latest/apps/nxpdevscan.html):
  - prevent one failing UART port from aborting the whole scan
  - improve UART ping failure hints and narrow-terminal output
- [nxpuuu](https://spsdk.readthedocs.io/en/latest/apps/nxpuuu.html):
  - make the run command and scripts interruptible with Ctrl-C
  - fix missing `Logger.trace` handling in the UUU runner
- improve libusbsio scan diagnostics and UART ping error reporting

## [3.9.0] - 2026-05-20

### Added

- add support for MCXC151, MCXC161, and MCXC162 microcontroller families
- update support for MCXL255, MCXL254, and MCXL253 device families
- [crypto](https://spsdk.readthedocs.io/en/latest/api/crypto.html):
  - add clear notification when Post-Quantum Cryptography (PQC) support is not available
  - add mapping for Elliptic Curve to Secure Memory Region (SMR) ECC-CURVE-ID attribute for improved key validation
  - add Hardware Security Module (HSM) signature provider example for i.MX RT10xx HAB-based devices
- [nxpdebugmbox](https://spsdk.readthedocs.io/en/latest/apps/nxpdebugmbox.html):
  - add challenge-response debug authentication support for MCXE31B, MCXC315, MCXE316, and MCXE317 devices
  - add password-based debug authentication support for MCXE31B, MCXC315, MCXE316, and MCXE317 devices
  - add ISP mode requirement warning for MCXA55x debug authentication to prevent configuration errors
  - add debug access protection configuration and debug authentication support for MCXE31B, MCXC315, MCXE316, and MCXE317 devices
- [nxpdevhsm](https://spsdk.readthedocs.io/en/latest/apps/nxpdevhsm.html):
  - add devhsm function support for MCXL255, MCXL254, and MCXL253 devices
  - add warning for MCXA55x devices when loadKeyBlob is not at end of configuration to prevent key slot conflicts
- [nxpele](https://spsdk.readthedocs.io/en/latest/apps/nxpele.html):
  - add devhsm function support for MCXL255, MCXL254, and MCXL253 devices
- [nxpfuses](https://spsdk.readthedocs.io/en/latest/apps/nxpfuses.html):
  - unify shadowregs and fuses under same base class to eliminate code duplication and improve maintainability
- [nxpimage](https://spsdk.readthedocs.io/en/latest/apps/nxpimage.html):
  - implement SBc v2 support for MCXL255, MCXL254, and MCXL253 devices
  - **AHAB container enhancements:**
    - add support for i.MX943 AHAB debug authentication with IEE region clearing capability
    - add support for i.MX952 unsigned AHAB container building for multiple boot memories (eMMC, SD card, Serial Downloader)
    - add AES_CCM DEK blob support in AHAB containers
  - **Boot image support:**
    - add FlexSPI NOR flash boot image support for MCXA55x device
    - add support for i.MX952 imx-bootloader integration
    - add support for MCXC151, MCXC161, and MCXC162 device families with Plain, CRC, and MISR boot image types
- add secure installer (SI) support for MCXL255, MCXL254, and MCXL253 devices with P-256 secure boot and OEM provisioning firmware
- [pfr](https://spsdk.readthedocs.io/en/latest/apps/pfr.html):
  - **Documentation improvements:**
    - update documentation to recommend pfr tool for writing PFR regions instead of write-memory command for better reliability
  - **Device support for MCXC151, MCXC161, and MCXC162:**
    - add support for these device families including CMPA configuration areas (CMPA_CFG, CMPA_BOOT, CMPA_KEY_STORE)
    - add support for MISR image format generation with IMG_MISR_SEED configuration
  - **Enhanced signing and security:**
    - add support for MCXA55x signed boot with ECC and ECC+MLDSA signing for FlexSPI NOR boot
    - Enhance WriteIfr command with monotonic counter field interpretation (0xFFFFFFFF for keep same, 0xFFFFFFFE for auto-increment)
- fix RW61x boot failure when using LOCK_CFG with shadow registers
- add dynamic Universal Update Utility (UUU) rules generation from device database with helper subcommand for improved device detection
- fix pip path traversal security vulnerability

### Fixed

- [blhost](https://spsdk.readthedocs.io/en/latest/apps/blhost.html):
  - improve error code descriptions for RT5xx flash-erase-all operations on eMMC to provide clearer feedback
- [nxpimage](https://spsdk.readthedocs.io/en/latest/apps/nxpimage.html):
  - **i.MX95 specific fixes:**
    - fix bootable-image verify tool to properly detect signature issues in OEM container headers
    - fix fast boot image padding to ensure proper 128-byte alignment for i.MX95 B0 silicon
  - **Security and validation improvements:**
    - add support for multiple data encryption keys in AHAB verify command for enhanced security validation
    - add data decryption support for bootable image verification
  - **General bug fixes:**
    - fix RT700 load-to-ram image recognition in bootable image verification
    - fix binary-image convert command to preserve original memory addresses
    - improve error message clarity for user-facing operations
    - fix MCXA55 SB4 file validation to allow keyblob placement before PFR write command
    - add format definition for data property in writeIFR command schema
    - add support for MP (Miyaguchi-Preneel) hash algorithm in SMR-entry or remove from template options
- [nxpuuu](https://spsdk.readthedocs.io/en/latest/apps/nxpuuu.html):
  - fix PowerShell display issues when running list-devices command
  - fix progress bar to properly update during operations
  - fix stdout environment variable handling to prevent synchronous abort after cancelling fastboot mode
- fix broken link to Linux user guide in documentation

## [3.8.0] - 2026-03-27

### Added

- [nxpcrypto](https://spsdk.readthedocs.io/en/latest/apps/nxpcrypto.html):
  - add PQC (Post-Quantum Cryptography) support in pki-tree ahab command for i.MX95/i.MX943 hybrid keys
- [nxpdebugmbox](https://spsdk.readthedocs.io/en/latest/apps/nxpdebugmbox.html):
  - add warning that there is an exception and DAT must be performed in ISP mode
- [nxpele](https://spsdk.readthedocs.io/en/latest/apps/nxpele.html):
  - make U-Boot prompt configurable instead of hardcoded value
- [nxpfuses](https://spsdk.readthedocs.io/en/latest/apps/nxpfuses.html):
  - add bitfields display to rich print output for improved fuse register visualization
- [nxpimage](https://spsdk.readthedocs.io/en/latest/apps/nxpimage.html):
  - add SPI support for RT118x device family
  - add MBI verifier functionality for Master Boot Image validation
  - adopt flexible format support for AHAB containers
  - restore QB data availability for i.MX95 device
  - fix signed message flag handling for i.MX95 B0 HSM keystore reprovisioning
  - resolve ML-DSA PQC signing issues for i.MX95 platform
- add signature provider support for MCXN55xS
- create jupyter notebook documentation for Secure Memory Region feature on MCX E31
- unify indentation of data files across SPSDK for consistency
- notify user when PQC support is not available

### Changed

- Certificate block module has been refactored - cert_block.py split into individual files per certification block type to maintain clear code organization

### Fixed

- [blhost](https://spsdk.readthedocs.io/en/latest/apps/blhost.html):
  - fix CAN interface operation with rx/tx arbitration IDs specified
- [el2go-host](https://spsdk.readthedocs.io/en/latest/apps/el2go-host.html):
  - fix provision_device_command() missing uboot_prompt parameter
- [nxpele](https://spsdk.readthedocs.io/en/latest/apps/nxpele.html):
  - clarify HSE secure lifecycle transition requirements and error handling
- [nxpfuses](https://spsdk.readthedocs.io/en/latest/apps/nxpfuses.html):
  - i.MX95 fix reading single fuses for grouped fuses like SRKH
  - i.MX95 resolve read failures on i.MX95 B0 silicon and synchronize with CRR data
  - i.MX95 fix nxpfuses failures when reading all fuses
  - fix fuse address display showing incorrect 0x0 value when using --rich parameter
- [nxpimage](https://spsdk.readthedocs.io/en/latest/apps/nxpimage.html):
  - i.MX95 correct keystore reprovisioning flag in signed message for HSM
  - i.MX95 add support for OTFAD scramble mode on i.MX95 B0 silicon
  - i.MX95/i.MX943 update AHAB metadata for System Manager core mapping
  - fix bootable image HAB parse method to properly store parsed files
  - improve error reporting when segment parsing fails in bimg
  - fix AHAB flexSPI NOR image signing issues
  - correct A35 core count for i.MX8ULP in database
  - fix AHAB export failures with OEI extra sections on i.MX95
- [nxpuuu](https://spsdk.readthedocs.io/en/latest/apps/nxpuuu.html):
  - fix synchronous abort handler after cancelling uboot fastboot mode
- [pfr](https://spsdk.readthedocs.io/en/latest/apps/pfr.html):
  - fix cert block parsing error for lpc55s36 family support
- validate embedded YAML config definitions in main configuration files
- correct documentation error for signed u-boot replacement sequence
- remove appended hash from signed FA messages for OEM-Return transitions

## [3.7.1] - 2026-03-20

### Added

- add support for MCXE31x device family
- add support for MCXA577/567/566/557/556/537/536/457/456 devices
- [nxpimage](https://spsdk.readthedocs.io/en/latest/apps/nxpimage.html):
  - add SPI support for RT118x
  - add support with AHAB QB data for i.MX95
- [pfr](https://spsdk.readthedocs.io/en/latest/apps/pfr.html):
  - update PFR implementation for kw43/mcxa55 devices
  - improve mcxa55 CFPA/CMPA grouping
  - improve error messages for incorrect YAML indentation in configuration files
- [nxpele](https://spsdk.readthedocs.io/en/latest/apps/nxpele.html):
  - add support for MCXE31 device family with Core Reset Entry Install command
  - implement key import functionality for MCXE31 with hardware testing and fixes
  - add automatic authentication tag calculation for Secure Memory Regions (SMR) on MCX E31
  - add HSE_SRV_ID_ACTIVATE_PASSIVE_BLOCK service for MCXE31 passive block activation

### Fixed

- [nxpimage](https://spsdk.readthedocs.io/en/latest/apps/nxpimage.html):
  - rename image version to firmware version for plain and CRC images on PQC devices
- [pfr](https://spsdk.readthedocs.io/en/latest/apps/pfr.html):
  - mcxa55: fix ROTKH first 4 bytes inversion in CMPA
  - mcxa55: replace mcxa455 with mcxa457 device support and correct memory map configuration
  - mcxa55: fix reading of additional CMPA data with update_cfpa_cmpa command
  - mcxa55: fix verifier issue for debug authentication with hybrid keys (ECC384 + MLDSA87)

## [3.7.0] - 2026-01-30

### Added

- MCXE31
- MCXN556S
- i.MX952
- i.MX95
- Highlights:
  - SPARSE file format support added
  - Added support for the imx-bootloader, which simplifies bootloader creation compared to generic templates. When generating templates for a bootable image using the nxpimage bootable-image get-templates command, comprehensive templates are created, including SPL and U-Boot configurations. All required files can be copied directly to the inputs directory without modifying configuration files. Currently, i.MX95 and i.MX93 flash_all imx bootloaders are supported.
- [nxpimage](https://spsdk.readthedocs.io/en/latest/apps/nxpimage.html):
  - implement SBc v2 support for MCXL255 new product introduction
  - add support for RSA and ECC P-521 keys in TLV blob functionality
  - implement SPARSE format support
  - enable hash algorithm specification in nxpcrypto rot calculate-hash command
  - move output and output-format options from command line to config in bootable image
  - implement update-keyblob command with SPARSE support
  - add missing memory type option for booting from eMMC boot0/1 partitions
  - update MPU bootable-image with optional boot media input and workspace creation
- [blhost](https://spsdk.readthedocs.io/en/latest/apps/blhost.html):
  - add SPARSE format support
- [nxpele](https://spsdk.readthedocs.io/en/latest/apps/nxpele.html):
  - add MCX E31 set attribute command support for new product introduction
  - implement secure memory region (SMR) based secure boot for MCX E31 device
  - support multiple MU channels in HSE commands for MCX E31
  - add optional parameter to get info command for retrieving specific attributes
- create jupyter notebook describing basic secure boot feature

### Fixed

- [nxpimage](https://spsdk.readthedocs.io/en/latest/apps/nxpimage.html):
  - fix trust zone template that was bricking MCXN556S devices
  - resolve signed image boot failure due to incorrect firmware version check on MCXN556S
  - fix authenticated image boot failure for MCXE3x devices
  - correct CSF/IMG certificate issuer from CA to SRK for pki-tree command
- [nxpwpc](https://spsdk.readthedocs.io/en/latest/apps/nxpwpc.html):
  - fix malformed signature in WPC CSR preventing verification by systems like EL2GO
- [nxpele](https://spsdk.readthedocs.io/en/latest/apps/nxpele.html):
  - fix SRKH fuse BCF generation issue for i.MX952 device support
  - resolve image order issue for SDP/Flash hash/eMMC fastboot on i.MX952
  - fix export NXP production key failure for i.MX95 device support
  - resolve i.MX95 B0 boot image parsing with SignatureBlockV2 version compatibility
  - fix HSE firmware update exit code handling when update fails

## [3.6.0] - 2025-12-19

### Added

- [el2go-host](https://spsdk.readthedocs.io/en/latest/apps/el2go-host.html):
  - enable product based provisioning over fastboot
  - enable EL2GO support for mcxn556s device
  - add unclaim skip interactive mode option
  - sync error codes between SPSDK and TP FW
- [nxpimage](https://spsdk.readthedocs.io/en/latest/apps/nxpimage.html):
  - implement Key Import feature for MCX E31
  - add NBU signing support for KW47
- add support for reserved bitfields access information in database JSON files
- enable support for all available USB devices in Serial Downloader mode
- drop support for Python 3.9

### Fixed

- [nxpimage](https://spsdk.readthedocs.io/en/latest/apps/nxpimage.html):
  - fix SB4.0 parsing support in AHAB
- [el2go-host](https://spsdk.readthedocs.io/en/latest/apps/el2go-host.html):
  - fix product based flow for MPUs
- Fix spsdk utils clear-cache command when cache is broken

## [3.5.0] - 2025-11-28

### Added

- [el2go-host](https://spsdk.readthedocs.io/en/latest/apps/el2go-host.html):
  - enhance SecureObject and TLVElement string representations and size handling
- [nxpcrypto](https://spsdk.readthedocs.io/en/latest/apps/nxpcrypto.html):
  - add RoT binary parsing functionality with public key extraction
- [nxpimage](https://spsdk.readthedocs.io/en/latest/apps/nxpimage.html):
  - add image descriptor flag support to AHAB Image Array Entry
  - add support for configuration strings in SB3.1 and SB4.0 PCK validation
- add case-insensitive config key matching for registers and bitfields
- support i.MX95294

### Fixed

- [el2go-host](https://spsdk.readthedocs.io/en/latest/apps/el2go-host.html):
  - add PROV_ID element tag to secure objects
  - fix i.MX93 El2go provisioning batch mode issue with more robust handling of loading bootloaders with temporary timeouts
  - disable cleanup method on mcxn236
- [nxpdice](https://spsdk.readthedocs.io/en/latest/apps/nxpdice.html):
  - add support for truncated RKTH length validation in DICE target
- [nxpdevhsm](https://spsdk.readthedocs.io/en/latest/apps/nxpdevhsm.html):
  - explicitly enable execute command for RT700
- [nxpimage](https://spsdk.readthedocs.io/en/latest/apps/nxpimage.html):
  - fix multiple warnings for update in AHAB container
  - fix image size should not be aligned in AHAB with reworked offsets handling
  - make update-keyblob work with different ahab container types
  - fix the last ahab image size is aligned to 8 bytes but the image itself NOT
  - fix handling YAML boolean auto-conversion for plainInput field in SB31/SB4
  - correct RADIO_IP enum name to RADIO_LP in firmware version check command for SB31
  - reduce the minimum alignment requirement for AHAB binary images when using serial downloader target memory from 512 bytes to 4 bytes
  - improve HSE IVT address handling with optional fields
- [nxpuuu](https://spsdk.readthedocs.io/en/latest/apps/nxpuuu.html):
  - fix -d flag timeout
  - add printout of the error message string and change the computation of click progress bar

## [3.4.0] - 2025-10-24

### Added

- [blhost](https://spsdk.readthedocs.io/en/latest/apps/blhost.html):
  - add property warnings system for device-specific safety alerts
- [nxpimage](https://spsdk.readthedocs.io/en/latest/apps/nxpimage.html):
  - add HSE lifecycle configuration support to MBI for mcx-e31b device family

### Fixed

- [el2go-host](https://spsdk.readthedocs.io/en/latest/apps/el2go-host.html):
  - fix u-boot support for product flow
- [blhost](https://spsdk.readthedocs.io/en/latest/apps/blhost.html):
  - add fuse-program-voltage property to blhost overrides
- [nxpimage](https://spsdk.readthedocs.io/en/latest/apps/nxpimage.html):
  - add selecting AHAB images to be updated in multiple ahab image binaries
- [pfr](https://spsdk.readthedocs.io/en/latest/apps/pfr.html):
  - fix data for mcxn556s
  - fix revisions for kw47xx and kw32w1

## [3.3.0] - 2025-09-26

### Added

- [el2go-host](https://spsdk.readthedocs.io/en/latest/apps/el2go-host.html):
  - extend error codes for EL2GO product-based provisioning
- [nxpdebugmbox](https://spsdk.readthedocs.io/en/latest/apps/nxpdebugmbox.html):
  - add validation in DAT authentication of SRKH for MCU PQC
  - unify get-template output messages
- [nxpele](https://spsdk.readthedocs.io/en/latest/apps/nxpele.html):
  - secure enclave key provision support
- [nxpimage](https://spsdk.readthedocs.io/en/latest/apps/nxpimage.html):
  - implement iae templates for kernel image and dtb
  - reorganize AHAB image types and add V2X support for i.MX8 devices
  - add default instance value to FlexSPI RAM XMCD configurations
- [nxpshe](https://spsdk.readthedocs.io/en/latest/apps/nxpshe.html):
  - add verify_only flag support and enable additional user keys
- add shell autocompletion setup command for SPSDK tools

### Fixed

- [nxpimage](https://spsdk.readthedocs.io/en/latest/apps/nxpimage.html):
  - add validation for empty binary image export
- [nxpshe](https://spsdk.readthedocs.io/en/latest/apps/nxpshe.html):
  - remove debug prints and unused auth-key-id parameter from SHE boot MAC functionality
- [nxpwpc](https://spsdk.readthedocs.io/en/latest/apps/nxpwpc.html):
  - fix new name for property 17

## [3.2.0] - 2025-08-29

**Rapid blhost**: Introducing RAPID BLHOST - a high-performance version of our blhost application written in Rust for significantly faster startup times and improved overall performance compared to the Python-based implementation. Available on [GitHub](https://github.com/nxp-mcuxpresso/rblhost), [Crates](https://crates.io/crates/rblhost), and [PyPI](https://pypi.org/project/pymboot-rs/).

### Added

- [nxpimage](https://spsdk.readthedocs.io/en/latest/apps/nxpimage.html):
  - implement MBI PQC
  - support configurable hash algorithms in ahab certificate
  - add SHAKE hash algorithms to SPSDK and AHAB container
- [el2go-host](https://spsdk.readthedocs.io/en/latest/apps/el2go-host.html):
  - add API/command to get stats of db file with product-based secure objects
  - add prepare-device command to prod command group
- [nxpdevhsm](https://spsdk.readthedocs.io/en/latest/apps/nxpdevhsm.html):
  - add new format for sbfile for mcxa family devices with secure installer/extended bootloader
- support mcxe24
- support mcxn556s
- add S19 to binary converter
- update CLI apps to display subgroups as trees
- update way how SVN's are handled in the template for DICE

### Fixed

- [el2go-host](https://spsdk.readthedocs.io/en/latest/apps/el2go-host.html):
  - fix parameter "--secure-objects-file" for prod prepare-device
  - fix get-next-so fails with static-only database
- [nxpdevhsm](https://spsdk.readthedocs.io/en/latest/apps/nxpdevhsm.html):
  - fix final reset jump out of ISP for mcxa series
  - fix invalid OEM ENC MASTER SHARE size for mcxn556s
- [nxpimage](https://spsdk.readthedocs.io/en/latest/apps/nxpimage.html):
  - fix container offset in verbose is incorrect
  - fix SB31 export issue with plain encryption key
  - fix AHAB certificate confusing comments in DAT template
- [pfr](https://spsdk.readthedocs.io/en/latest/apps/pfr.html):
  - fix pfr for mcxa, mcxal series

## [3.1.0] - 2025-07-11

### Added

- [el2go-host](https://spsdk.readthedocs.io/en/latest/apps/el2go-host.html):
  - implement product based provisioning for RW61x
  - improved exit code handling on error
- [nxpdebugmbox](https://spsdk.readthedocs.io/en/latest/apps/nxpdebugmbox.html):
  - add `--help` parameter description for ispmode command
  - add `-d` flag to `nxpuuu write`
- [nxpimage](https://spsdk.readthedocs.io/en/latest/apps/nxpimage.html):
  - support for BCA and FCF configuration for MCX devices
  - support for DAT protocol 3.0
  - support for verifying MLDSA signature from DICE Hybrid CSR
  - support for verifying PRK & PUK from DICE Alias keys
  - support for i.MX943
- add offline HSM signature provider as a plugin
- fix offline signature provider script errors
- implement SB3.1 data compression
- add DICE CSR verifier
- add support for DAT on MX943/MX95 B0
- add support for hybrid PQC keys in PQC plugin
- add support for MLDSA variant

### Fixed

- [el2go-host](https://spsdk.readthedocs.io/en/latest/apps/el2go-host.html):
  - fix exit code on error
  - fix YAML configuration loading
- [nxpdebugmbox](https://spsdk.readthedocs.io/en/latest/apps/nxpdebugmbox.html):
  - fix debug mailbox protocol handling
  - fix UUID truncation in DAR message header
- [nxpfuses](https://spsdk.readthedocs.io/en/latest/apps/nxpfuses.html):
  - fix progress bar ending prematurely
- [nxpimage](https://spsdk.readthedocs.io/en/latest/apps/nxpimage.html):
  - fix invalid length in AHAB verify
  - fix unclear error messages during export
  - fix container verification for ATF/U-Boot image
  - fix typo in MBI config template
  - fix XMCD data for mimxrt798s
- [nxpmemcfg](https://spsdk.readthedocs.io/en/latest/apps/nxpmemcfg.html):
  - fix wrong dictionary access
- fix parsing of MLDSA private keys

## [3.0.1] - 2025-06-27

### Fixed

- [nxpcrypto](https://spsdk.readthedocs.io/en/latest/apps/nxpcrypto.html):
  - improve serial number validation in certificate generation
- [nxpimage](https://spsdk.readthedocs.io/en/latest/apps/nxpimage.html):
  - fix AHAB container header info display
  - fix MBI parameter for mcxa series
  - add input data size validation for HAB segments
  - add hardware key mixin to NHS52S04 MBI types
  - add load address mixin to every MBI type
  - improve CA Flag description in AHAB schemas
  - fix AHAB update keyblob
  - add new Fast Boot flags to AHABContainerV2
- [nxpmemcfg](https://spsdk.readthedocs.io/en/latest/apps/nxpmemcfg.html):
  - add missing memory types (MicronOPI_SDR, AdestoOPI_SDR)
- update default BOOT_FLAGS value in MC56F81x68 BCA configuration
- validate and clean up the contents of SPSDK data files

## [3.0.0] - 2025-05-16

Current version introduces breaking changes, which are described in details in [migration guide](https://spsdk.readthedocs.io/en/latest/migration_guide.html).

### Added

- [el2go-host](https://spsdk.readthedocs.io/en/latest/apps/el2go-host.html):
  - check UUID fuse index
- [ifr](https://spsdk.readthedocs.io/en/latest/usage/applications.html#ifr):
  - move into [pfr](https://spsdk.readthedocs.io/en/latest/apps/pfr.html) application
- [nxpcrypto](https://spsdk.readthedocs.io/en/latest/apps/nxpcrypto.html):
  - allow adding image key into existing PKI tree
  - remove nxpcertgen application (all functionality is now available in nxpcrypto application)
  - consolidate options `-k/--private-key` and `-sp/--signature-provider` replace with option `-s/--signer`
- [nxpdebugmbox](https://spsdk.readthedocs.io/en/latest/apps/nxpdebugmbox.html):
  - move commands to separated groups with clearer organization
  - move parameter --family from the root command to individual command groups
  - derive test address from the family parameter
- [nxpdevhsm](https://spsdk.readthedocs.io/en/latest/apps/nxpdevhsm.html):
  - require oemRandomShare when oemEncMasterShare is defined
  - add new format for sbfile for mcxa family devices with secure installer/extended bootloader
- [nxpimage](https://spsdk.readthedocs.io/en/latest/apps/nxpimage.html):
  - generate fuse script when merging signed image
  - add unicode characters for better BinaryImage visualization
  - remove the deprecated 'image_type' key in ahab configuration and replace by 'target_memory'
  - remove input_binary and base_address parameters from bee
  - rename merge commands in bootable-image and binary-image to export
  - remove 'mainCertChainId' key in cert-block configuration by 'mainRootCertId'
  - replace hab export /parse commands with unified configuration approach
  - implement SB3.1 data compression
  - add parser of SB3.1
  - consolidate all keys for data of SB3.1 load command into one
  - simplify load command configuration
  - simplify input data values
- [pfr](https://spsdk.readthedocs.io/en/latest/apps/pfr.html):
  - remove option --show-calc from parse/read commands
  - remove option --calc-inverse from generate binary command
  - rename generate-binary command to export
  - rename parse-binary command to parse
  - require 'family' in BD file for SB2.1 and optionally 'revision' in the 'options' block
- [tphost](https://spsdk.readthedocs.io/en/latest/usage/applications.html#tphost)/[tpconfig](https://spsdk.readthedocs.io/en/latest/usage/applications.html#tpconfig):
  - remove applications
- remove family option from main top command to individual subcommands
- remove '--plugin' as optional parameter
- rename merge commands to export
- improve displaying of --help
- all applications that support the `--config` option now also support the `-oc/--override-config` option

### Fixed

- [blhost](https://spsdk.readthedocs.io/en/latest/apps/blhost.html):
  - fix receive-sb-file command failures with usb
- [el2go-host](https://spsdk.readthedocs.io/en/latest/apps/el2go-host.html):
  - fix family parameter issue
- [nxpdebugmbox](https://spsdk.readthedocs.io/en/latest/apps/nxpdebugmbox.html):
  - fix famode-image get-templates command
  - resolve debug authentication issues
  - fix general error handling
- [nxpdevhsm](https://spsdk.readthedocs.io/en/latest/apps/nxpdevhsm.html):
  - fix config file issues
- [nxpele](https://spsdk.readthedocs.io/en/latest/apps/nxpele.html):
  - fix get-info error
- [nxpfuses](https://spsdk.readthedocs.io/en/latest/apps/nxpfuses.html):
  - fix get-config errors
- [nxpimage](https://spsdk.readthedocs.io/en/latest/apps/nxpimage.html):
  - fix HAB and BIMG issues
  - fix ahab export assertion error
  - fix RT118x build IEE image failure
  - fix parsing of imx943 bootable image
  - fix issues with receiving sb31
  - fix conversion binary from S19
  - fix parsing of FCB for RT7xx
  - remove unnecessary enableTrustZone parameter in MBI config files
  - fix overlapping detection and adjust-offsets functionality in binary-image merge
- [nxpmemcfg](https://spsdk.readthedocs.io/en/latest/apps/nxpmemcfg.html):
  - fix deprecation warning
- [nxpwpc](https://spsdk.readthedocs.io/en/latest/apps/nxpwpc.html):
  - fix missing family parameter for service parameters
  - fix api key existence
- [shadowregs](https://spsdk.readthedocs.io/en/latest/apps/shadowregs.html):
  - fix general error
- fix invalid -oc option behavior

## [2.6.0] - 2025-02-07

### Added

- [el2go-host](https://spsdk.readthedocs.io/en/latest/apps/el2go-host.html):
  - support iMX8ULP
  - add possibility to save OEM app config
- [lpcprog](https://spsdk.readthedocs.io/en/latest/apps/lpcprog.html):
  - support set CRP in lpcprog
  - add optional parameter to repeat the command several times if fails
- [nxpimage](https://spsdk.readthedocs.io/en/latest/apps/nxpimage.html):
  - support BCA and FCF configuration for mcxc family devices
- support mcxw23x
- support i.MX943
- implement Key Import signed message
- add support for RSA in DAT on RT118x

### Deprecated

- the following backwards incompatible changes were announced for SPSDK 3.0.0:
  - BD file support for HAB will be dropped. Only the yaml configuration files will be supported. The conversion from BD file to yaml will be available
  - The obscure way of determination of private key file path from certificate in HAB path will be dropped. The public key will need to be specified explicitly
  - The family will be mandatory for most tools in SPSDK
  - The family option will be moved in most tools to sub-commands
  - Complete redesign handling of configuration files through all SPSDK
  - All backward compatibility code will be removed (deprecated commands and configurations)
  - The definition of signing local key and signature provider definition in configuration will be implemented into one configuration record
  - All data in database will be unified under one style (utility/registers.py)
  - The configuration option on CLI will be extended by new -oc/--override-config to override any configuration in CLI
  - SmartCard Trust Provisioning has been discontinued. Associated applications (tphost, tpconfig) will be removed.

### Fixed

- [el2go-host](https://spsdk.readthedocs.io/en/latest/apps/el2go-host.html):
  - fix loading item yaml configuration
- [nxpimage](https://spsdk.readthedocs.io/en/latest/apps/nxpimage.html):
  - fix XMCD data for mimxrt798s
  - fix invalid scramble mechanism in OTFAD
- [nxpmemcfg](https://spsdk.readthedocs.io/en/latest/apps/nxpmemcfg.html):
  - fix wrong dict access

## [2.5.0] - 2024-12-20

### Added

- [nxpdevscan](https://spsdk.readthedocs.io/en/latest/apps/nxpdevscan.html):
  - add timeout option
- [el2go-host](https://spsdk.readthedocs.io/en/latest/apps/el2go-host.html):
  - enablement on i.MX 93
- support i.MX RT735S and i.MX RT758S
- support i.MX RT1043 and i.MX RT1046
- support mcxa13x variants
- support Python 3.13
- drop pyocd requirement and replace by spsdk-mcu-link and spsdk-pyocd
- support kw47xx and mcxw72x devices
- add loading of OTPS-encoded public keys
- add nxpfuses tool for handling operations with fuses

### Fixed

- [nxpimage](https://spsdk.readthedocs.io/en/latest/apps/nxpimage.html):
  - fix encryption in OTFAD
  - fix bootable image creation with just one bootable image
- [nxpdevscan](https://spsdk.readthedocs.io/en/latest/apps/nxpdevscan.html):
  - fix filtering the correct serial port devices on macOS

### Known Issues

- [nxpdebugmbox](https://spsdk.readthedocs.io/en/latest/apps/nxpdebugmbox.html):
  - interface mcu-link is not working on Ubuntu 24.04

## [2.4.0] - 2024-11-15

### Added

- [el2go-host](https://spsdk.readthedocs.io/en/latest/apps/el2go-host.html):
  - implement parallel download of Secure Objects using database
  - speed up repeated calls to EL2GO server
  - allow to specify scope of Secure Objects to download
- [nxpdebugmbox](https://spsdk.readthedocs.io/en/latest/apps/nxpdebugmbox.html):
  - support halt, resume commands
  - AHB access test address remove as an option and move into database
  - support for block memory transfer over debug probes
- [nxpmemcfg](https://spsdk.readthedocs.io/en/latest/apps/nxpmemcfg.html):
  - add support for RT700

### Fixed

- [el2go-host](https://spsdk.readthedocs.io/en/latest/apps/el2go-host.html):
  - fix memory buffer used for data exchange for KW45
- [nxpimage](https://spsdk.readthedocs.io/en/latest/apps/nxpimage.html):
  - allow to parse AHAB image with empty image hash for rt118x

## [2.3.0] - 2024-10-11

Current version introduces breaking changes, which are described in details in [migration guide](https://spsdk.readthedocs.io/en/latest/migration_guide.html).

### Added

- [blhost](https://spsdk.readthedocs.io/en/latest/apps/blhost.html):
  - support nIRQ pin feature
- [el2go-host](https://spsdk.readthedocs.io/en/latest/apps/el2go-host.html):
  - unify subcommands for RW61x
  - add get-otp-binary command
  - add UUID harvesting
  - add default handler to unknown errors while assigning device to a group
  - add checker for max amount of Secure Objects and their size
  - add Remote Database for Secure Objects for Azurewave
  - add close_device to blhost; display response of RW TPFW responses
  - implement database storage for UUIDs harvesting
  - erase CMPA in EdgeLock2GO indirect flow
- [lpcprog](https://spsdk.readthedocs.io/en/latest/apps/lpcprog.html):
  - add programmer for LPC8xx parts
- [nxpcrypto](https://spsdk.readthedocs.io/en/latest/apps/nxpcrypto.html):
  - add subcommand for creating PKI tree
- [nxpdebugmbox](https://spsdk.readthedocs.io/en/latest/apps/nxpdebugmbox.html):
  - support for MX95 revision A0/A1/B0 (PQC support)
- [nxpdevhsm](https://spsdk.readthedocs.io/en/latest/apps/nxpdevhsm.html):
  - add execute command for mcxn9xx
  - allow SB files without loading the wrapped CUST_MK_SK
  - implement oem duk certificate provisioning
- [nxpdice](https://spsdk.readthedocs.io/en/latest/apps/nxpdice.html):
  - add nxpdice application
- [nxpele](https://spsdk.readthedocs.io/en/latest/apps/nxpele.html):
  - support nxpele over fastboot
- [nxpimage](https://spsdk.readthedocs.io/en/latest/apps/nxpimage.html):
  - support AHAB version 2
  - add verificator to bootable image
  - support linux image in bootable image
  - add ahab sign command for signing existing AHAB images
- [nxpmemcfg](https://spsdk.readthedocs.io/en/latest/apps/nxpmemcfg.html):
  - add blhost-script option for exporting configuration for secure address
- [nxpuuu](https://spsdk.readthedocs.io/en/latest/apps/nxpuuu.html):
  - new tool based on the UUU (Universal Update Utility), add capability to deploy images to i.MX MPU targets
- [nxpwpc](https://spsdk.readthedocs.io/en/latest/apps/nxpwpc.html):
  - add special handler when pre-CSR are are empty
- [tphost](https://spsdk.readthedocs.io/en/latest/usage/applications.html#tphost)/[tpconfig](https://spsdk.readthedocs.io/en/latest/usage/applications.html#tpconfig):
  - implement lightweight Chain-of-Trust checker for DevCert located in the device
- support MCXC series (blhost)
- support RT7xx
- support MCXN23x, MCXN9xx, KW45xx EL2Go
- support MCXW71 and its variants

### Fixed

- [el2go-host](https://spsdk.readthedocs.io/en/latest/apps/el2go-host.html):
  - fix general error when database has no blob
  - fix revision in configuration
- [nxpdebugmbox](https://spsdk.readthedocs.io/en/latest/apps/nxpdebugmbox.html):
  - fix get-crp command for mcxa series
  - fix template for famode-image
  - fix dat for RT1180
  - fix template for RT1180
- [nxpele](https://spsdk.readthedocs.io/en/latest/apps/nxpele.html):
  - fix get-info details
- [nxpimage](https://spsdk.readthedocs.io/en/latest/apps/nxpimage.html):
  - fix flag in AHAB
  - fix plain MBI for NHS52sxx
  - fix trustzone for NHS52Sxx
  - remove header form XMCD segment
- [pfr](https://spsdk.readthedocs.io/en/latest/apps/pfr.html):
  - fix erase-cmpa for mcxa series
- shadowregs:
  - fix fuses-script
  - fix loading shadow registers on RW61x

## [2.2.1] - 2024-07-26

### Fixed

- [ifr](https://spsdk.readthedocs.io/en/latest/usage/applications.html#ifr):
  - fix read command
- [nxpimage](https://spsdk.readthedocs.io/en/latest/apps/nxpimage.html):
  - fix parsing bootable image without specified memory type
  - fix plain mbi for NHS52sxx
- [nxpwpc](https://spsdk.readthedocs.io/en/latest/apps/nxpwpc.html):
  - fix unavailable item

## [2.2.0] - 2024-06-07

Current version introduces breaking changes, which are described in details in [migration guide](https://spsdk.readthedocs.io/en/latest/migration_guide.html).

### Added

- [blhost](https://spsdk.readthedocs.io/en/latest/apps/blhost.html):
  - add can interface
- [el2go-host](https://spsdk.readthedocs.io/en/latest/apps/el2go-host.html):
  - support for mwct2x12, mwct2xd2
- [ifr](https://spsdk.readthedocs.io/en/latest/usage/applications.html#ifr):
  - add option to configure sector 2
- [nxpdebugmbox](https://spsdk.readthedocs.io/en/latest/apps/nxpdebugmbox.html):
  - add family and revision info into DAC config file
- [nxpdevhsm](https://spsdk.readthedocs.io/en/latest/apps/nxpdevhsm.html):
  - commands limited based on specific devices capabilities
- [nxpele](https://spsdk.readthedocs.io/en/latest/apps/nxpele.html):
  - add fuses script
- [nxpimage](https://spsdk.readthedocs.io/en/latest/apps/nxpimage.html):
  - add support for RAW image
  - add re-sign subcommand to ahab
  - support parsing FCB block with swapped bytes
  - support MBI CRC for mwct2x12, mwct2xd2, mc56f818xx, mc56f817xx
  - support BinaryImage in MBI export
  - support i.MX 95 unsigned build image
- [nxpwpc](https://spsdk.readthedocs.io/en/latest/apps/nxpwpc.html):
  - add correlation-id into REST request
- drop support for Python 3.8
- support NHS52Sxx, mcxw71xx
- support RW61x EL2Go
- P&E Micro and J-Link as separate plugins
- all options in sub-commands case-insensitive

### Fixed

- [nxpdebugmbox](https://spsdk.readthedocs.io/en/latest/apps/nxpdebugmbox.html):
  - fix debug authentication on NHS52Sxx
  - fix generation of DC config file
  - fix dac response length on kw45xx
- [nxpele](https://spsdk.readthedocs.io/en/latest/apps/nxpele.html):
  - fix timeout
  - fix verify image for i.mx93
  - fix failure in communication with uboot
- [nxpimage](https://spsdk.readthedocs.io/en/latest/apps/nxpimage.html):
  - fix signed-msg incorrect signature
  - fix wrong offset in FCB
  - fix xmcd generation
  - fix mbi export
  - fix ahab with invalid SRK
  - fix bootable-image for RW61x
  - fix mbi config for kw45xx
  - fix bootable-image with dynamic offset segments
  - fix inconsistent core ID in parser and export
- [pfr](https://spsdk.readthedocs.io/en/latest/apps/pfr.html):
  - fix generate-binary argument position
  - fix generating cmpa template for mcxa1xx
  - fix default cmpa page for mcxa1xx
- shadowregs:
  - fix shadow registers on RW61x
  - fix loadconfig command

## [2.1.1] - 2024-03-27

### Added

- [nxpcrypto](https://spsdk.readthedocs.io/en/latest/apps/nxpcrypto.html):
  - add RSA-PSS support
- [nxpdevhsm](https://spsdk.readthedocs.io/en/latest/apps/nxpdevhsm.html):
  - support external devhsm provisioning

### Fixed

- [dk6prog](https://spsdk.readthedocs.io/en/latest/apps/dk6prog.html#dk6prog):
  - fix DK6 operations
- [nxpdevhsm](https://spsdk.readthedocs.io/en/latest/apps/nxpdevhsm.html):
  - fix buffer address MC56
- [nxpele](https://spsdk.readthedocs.io/en/latest/apps/nxpele.html):
  - fix write fuse
- [nxpimage](https://spsdk.readthedocs.io/en/latest/apps/nxpimage.html):
  - add advanced params setting to configurations (padding, keys, timestamp, etc.)
  - fix manifest hash digest KW45/K32W1

## [2.1.0] - 2024-02-02

### Added

- [nxpcrypto](https://spsdk.readthedocs.io/en/latest/apps/nxpcrypto.html):
  - add signing commands (create, verify)
- [nxpdebugmbox](https://spsdk.readthedocs.io/en/latest/apps/nxpdebugmbox.html):
  - add subcommands for Fault Analysis Mode (export, parse, get-templates)
  - add printing the result of auth command
  - add dedicated plugin system
- [nxpele](https://spsdk.readthedocs.io/en/latest/apps/nxpele.html):
  - U-BOOT interface
  - add commit command
  - add commands related to release-container
- [nxpimage](https://spsdk.readthedocs.io/en/latest/apps/nxpimage.html):
  - enable IEE encryption for RT1180
  - add key exchange signed message
  - add signature provider for RT1xxx
- support mcxn23x
- deployment of new database
- EL2GO mockup for S32K WPC
- introduce memory configuration tool

### Fixed

- [nxpele](https://spsdk.readthedocs.io/en/latest/apps/nxpele.html):
  - fix get-trng state command
- [nxpimage](https://spsdk.readthedocs.io/en/latest/apps/nxpimage.html):
  - fix cmpa template
  - fix parsing ahab image for i.MX95
  - fix xmcd export command
  - fix certificate block as binary file
  - fix sb21 get-template command
- [nxpmemcfg](https://spsdk.readthedocs.io/en/latest/apps/nxpmemcfg.html):
  - fix export command
- [pfr](https://spsdk.readthedocs.io/en/latest/apps/pfr.html):
  - fix pfr generate command
- shadowregs:
  - fix default family parameter

## [2.0.1] - 2023-12-15

### Fixed

- [nxpele](https://spsdk.readthedocs.io/en/latest/apps/nxpele.html):
  - remove temporary file
- [nxpdebugmbox](https://spsdk.readthedocs.io/en/latest/apps/nxpdebugmbox.html):
  - fix test memory AP address
- [nxpimage](https://spsdk.readthedocs.io/en/latest/apps/nxpimage.html):
  - fix detection of input file for FCB in bootable image
  - fix IEE encryption for RT1180
  - fix signed MBI for Anguilla Nano
  - fix SB21 export with yaml config
- shadowregs:
  - fix behavior of the RKTH registers
  - fix invalid names of CRC field in database
- fix setting a register value as raw value when loading from configuration

## [2.0.0] - 2023-10-13

Current version introduces breaking changes, which are described in details in [migration guide](https://spsdk.readthedocs.io/en/latest/migration_guide.html).

### Added

- [blhost](https://spsdk.readthedocs.io/en/latest/apps/blhost.html):
  - dedicated plugin system
  - check of written data length in USB Interface
- [nxpcrypto](https://spsdk.readthedocs.io/en/latest/apps/nxpcrypto.html):
  - remove dependency on PyCryptodome
  - add rot command for calculating RoT hash
- [nxpimage](https://spsdk.readthedocs.io/en/latest/apps/nxpimage.html):
  - distinguish between fw version and image version
  - support YAML configuration for HAB
  - support build RT11xx image with ECC keys
  - support OSCCA
  - support AHAB NAND
  - implement HTTP Proxy Signature Provider
  - signature provider for OSCCA
  - add validation of signature in AHAB
  - support OTFAD for RT1010
  - export HAB from yaml config in bootable image
  - revision of offsets in AHAB container
  - command filter in SB 2.1 based on family
  - refactor memory types for mbi
  - add to AHAB key identifier for encrypted images
- [pfr](https://spsdk.readthedocs.io/en/latest/apps/pfr.html)/[ifr](https://spsdk.readthedocs.io/en/latest/usage/applications.html#ifr):
  - remove devices subcommand
- [sdpshost](https://spsdk.readthedocs.io/en/latest/apps/sdpshost.html):
  - connection support for iMX91 and iMX95
- shadowregs:
  - unify endianness
- tool for converting JSON configuration into YAML with comments
- support mcxa1xx
- unify naming: RKTH/RKHT
- remove nxpkeygen and nxpcertgen apps, replaced by [nxpcrypto](https://spsdk.readthedocs.io/en/latest/apps/nxpcrypto.html)
- remove elftosb app, replaced by [nxpcrypto](https://spsdk.readthedocs.io/en/latest/apps/nxpcrypto.html)
- positional arguments replaced by options for all parameters with an exception to [blhost](https://spsdk.readthedocs.io/en/latest/apps/blhost.html), [sdphost](https://spsdk.readthedocs.io/en/latest/apps/sdphost.html) and [dk6prog](https://spsdk.readthedocs.io/en/latest/apps/dk6prog.html#dk6prog)
- remove backward compatibility with command get-cfg-template, replaced fully with get-template(s)
- unify family name within all modules
- remove lpc55xx from family names

### Fixed

- [blhost](https://spsdk.readthedocs.io/en/latest/apps/blhost.html):
  - fix error of SPI connection
- [nxpdevhsm](https://spsdk.readthedocs.io/en/latest/apps/nxpdevhsm.html):
  - add missing sdio in generate command
- [nxpele](https://spsdk.readthedocs.io/en/latest/apps/nxpele.html):
  - fix generate-keyblob IEE
  - fix issue with get-info command
- [nxpimage](https://spsdk.readthedocs.io/en/latest/apps/nxpimage.html):
  - fix certificate block in AHAB
  - fix signature in AHAB
  - fix some commands for SB21
  - fix non generated keys for AHAB parse
  - fix RAM images for LPC55Sxx
  - fix MBI signed for xip for MCXN9xx
  - fix sb21 export yaml errors
  - fix OTFAD with DUK
  - fix wrong core ID in parse for iMX93
  - fix binary certificate block for MBI
  - fix manifest for mcxn9xx
  - fix bootable image merge
  - fix in MBI configurations
  - fix missing parameters in MBI config in bootable-image parse
  - fix sb21 file generation without SBKEK
  - update list of supported MBI images for mcxn9xx

## [1.11.0] - 2023-07-07

Next version of spsdk (2.0) will introduce breaking changes:

- elftosb will be replaced by nxpimage
- nxpcertgen and nxpkeygen will be replaced by nxpcrypto
- select appropriate family will be done using: -f/--family parameter
- move towards options for all parameters with an exception to BLHost
- removal of crypto backends
- extend dedicated spsdk.crypto module - serve as the de-facto backend of SPSDK
- module level imports via init files

### Added

- [nxpimage](https://spsdk.readthedocs.io/en/latest/apps/nxpimage.html):
  - enable signature providers for AHAB image and signed messages
  - add support for rt104x in bootable-image
- [tphost](https://spsdk.readthedocs.io/en/latest/usage/applications.html#tphost)/[tpconfig](https://spsdk.readthedocs.io/en/latest/usage/applications.html#tpconfig):
  - add possibility to check TP_RESPONSE only with NXP_PROD raw binary key
- add support for mcxn9xx
- add API for FuseLockedStatus
- possibility to declare private keys with passphrase in signature provider config
- add checking of written data length in usb interface
- add support for dk6 tools

### Fixed

- [nxpimage](https://spsdk.readthedocs.io/en/latest/apps/nxpimage.html):
- nxpimage:
  - fix offset on NAND memory in AHAB image
- fix plugin error for signature Provider for sb21

## [1.10.2] - 2023-07-07

### Added

- [tphost](https://spsdk.readthedocs.io/en/latest/usage/applications.html#tphost)/[tpconfig](https://spsdk.readthedocs.io/en/latest/usage/applications.html#tpconfig):
  - add support for LPC55S3x
- [nxpimage](https://spsdk.readthedocs.io/en/latest/apps/nxpimage.html):
  - add possibility to define multiple regions in OTFAD in one data blob

## [1.10.1] - 2023-05-26

### Added

- [nxpimage](https://spsdk.readthedocs.io/en/latest/apps/nxpimage.html):
  - support encrypted image hab
  - support for RT11xx and RT10xx
  - improve OTFAD/IEE names generation
- add API to retrieve info about fuses

### Fixed

- [nxpimage](https://spsdk.readthedocs.io/en/latest/apps/nxpimage.html):
  - fix XMCD load_from_config
  - fix IEE template
- fix circular dependency in signature provider import
- fix issue with loading keys as INT
- not enable logging when spsdk is used as a library

## [1.10.0] - 2023-04-05

### Added

- [blhost](https://spsdk.readthedocs.io/en/latest/apps/blhost.html):
  - add new command: ele_message
- [nxpdebugmbox](https://spsdk.readthedocs.io/en/latest/apps/nxpdebugmbox.html):
  - add command: read UUID from device
  - update PyOCD to latest version to support MCU LINK FW v3, implementing CMSIS-DAP v2.1
- [nxpdevhsm](https://spsdk.readthedocs.io/en/latest/apps/nxpdevhsm.html):
  - USER_PCK rename to CUST_MK_SK
- [nxpimage](https://spsdk.readthedocs.io/en/latest/apps/nxpimage.html):
  - add subcommand group for generate and parse certificate block
  - replace private key to signature provider in master boot image
  - OTFAD support for RT1170
- [ifr](https://spsdk.readthedocs.io/en/latest/usage/applications.html#ifr):
  - add commands read/write
- [pfr](https://spsdk.readthedocs.io/en/latest/apps/pfr.html):
  - add CMPA erase command

### Fixed

- [nxpdebugmbox](https://spsdk.readthedocs.io/en/latest/apps/nxpdebugmbox.html):
  - fix AP selection issue for PyOCD and PEMICRO
  - fix DAC verification when there is only 1 root key
- [nxpimage](https://spsdk.readthedocs.io/en/latest/apps/nxpimage.html):
  - fix MBI issue with HMAC
- shadowregs:
  - fix endianness for OTP MASTER KEY
- drop support for Python 3.7

## [1.9.1] - 2023-03-17

### Added

- [nxpdevhsm](https://spsdk.readthedocs.io/en/latest/apps/nxpdevhsm.html):
  - split reset option in nxpdevhsm into two; disable init reset by default

### Fixed

- [nxpdebugmbox](https://spsdk.readthedocs.io/en/latest/apps/nxpdebugmbox.html):
  - fix Linux error on PyOCD
  - fix PyOCD and PEmicro connection for kw45xx and k32w1xx
- [nxpdevhsm](https://spsdk.readthedocs.io/en/latest/apps/nxpdevhsm.html):
  - fix buffer base address for DevHSM operations
- [nxpimage](https://spsdk.readthedocs.io/en/latest/apps/nxpimage.html):
  - fix handling exception when the root cert index is wrong
- [tphost](https://spsdk.readthedocs.io/en/latest/usage/applications.html#tphost)/[tpconfig](https://spsdk.readthedocs.io/en/latest/usage/applications.html#tpconfig):
  - Incorrect output in TP PG command in case of an failure

## [1.9.0] - 2023-01-30

### Added

- [nxpdebugmbox](https://spsdk.readthedocs.io/en/latest/apps/nxpdebugmbox.html):
  - add check of root of trust hash in dat authentication
  - enable debug authentication protocol on RT1180
- [nxpdevhsm](https://spsdk.readthedocs.io/en/latest/apps/nxpdevhsm.html):
  - reset target before and after DevHSM SB3 file creation
- [nxpimage](https://spsdk.readthedocs.io/en/latest/apps/nxpimage.html):
  - XMCD support
  - signed messages support for RT1180
  - add bootable image for RT10xx, RT1180, RT1170, LPC55S3x
  - implement IEE encryption
  - support Memory ID for erase in sb21
  - support Memory ID for enable and load in sb21
  - implement JUMP and JUMP_SP commands in BD file  for SB2.1
  - enable encryption in AHAB container
- [tphost](https://spsdk.readthedocs.io/en/latest/usage/applications.html#tphost)/[tpconfig](https://spsdk.readthedocs.io/en/latest/usage/applications.html#tpconfig):
  - create command for loading ProvFW
  - add command for retrieving TP_RESPONSE without models or smart card
  - smart card reader name hash identification
- debug authentication improvements
- unify memory access cross all debuggers
- replace json file with yml file for TZ
- support for k32w1xx, kw45xx
- improve format of debugging logger

### Fixed

- [nxpdebugmbox](https://spsdk.readthedocs.io/en/latest/apps/nxpdebugmbox.html):
  - remove duplicated option --protocol for gendc command
- [nxpdevhsm](https://spsdk.readthedocs.io/en/latest/apps/nxpdevhsm.html):
  - fix skipping commands from config file
- [nxpimage](https://spsdk.readthedocs.io/en/latest/apps/nxpimage.html):
  - fix non working 384/521 ECC keys for signature in AHAB container
  - fix CRC mode in external flash for lpc55s3x
  - failure on start due to boot_image hook definition
- [pfr](https://spsdk.readthedocs.io/en/latest/apps/pfr.html):
  - command line parameter '-t' is duplicated
- [tphost](https://spsdk.readthedocs.io/en/latest/usage/applications.html#tphost)/[tpconfig](https://spsdk.readthedocs.io/en/latest/usage/applications.html#tpconfig):
  - TPhost load-tpfw requires TP device definition
  - OEM ProvFW boot-check incorrectly fails with non-verbose flavor

### Known Issues

- [nxpdebugmbox](https://spsdk.readthedocs.io/en/latest/apps/nxpdebugmbox.html):
  - we do not support CMSIS-DAP version 2 (bulk pipes, https://arm-software.github.io/CMSIS_5/DAP/html/group__DAP__ConfigUSB__gr.html) This means sw debuggers such as MCU-Link v3 will not work (nxpdebugmbox will not detect the debugger probe) This issue will be resolved in next version of SPSDK

## [1.8.0] - 2022-10-21

### Added

- [nxpimage](https://spsdk.readthedocs.io/en/latest/apps/nxpimage.html):
  - add support for BEE
  - enable OTFAD on RT1180
- [pfr](https://spsdk.readthedocs.io/en/latest/apps/pfr.html):
  - move the functionality of pfrc tool into PFR tool
- [tphost](https://spsdk.readthedocs.io/en/latest/usage/applications.html#tphost)/[tpconfig](https://spsdk.readthedocs.io/en/latest/usage/applications.html#tpconfig):
  - implement USB re-enumeration in TPHost after OEM ProvFW is started
  - create command for checking the Chain of Trust used in TP
  - investigate TP performance loss during device reset after TP is completed
  - add possibility to select TP SmartCard via card reader's name
- unify option for getting template across tools
- add API for parsing XMCD
- support cryptography >= 37.0.0
- support bincopy 17.14

### Fixed

- [nxpdevscan](https://spsdk.readthedocs.io/en/latest/apps/nxpdevscan.html):
  - fix hanging up for serial communication
- [tphost](https://spsdk.readthedocs.io/en/latest/usage/applications.html#tphost)/[tpconfig](https://spsdk.readthedocs.io/en/latest/usage/applications.html#tpconfig):
  - blhost_port should not be mandatory in TP target settings
  - fix disabling timeout in TP is ignored
- fix documentation regarding SB31 programFuses

## [1.7.1] - 2022-09-16

### Added

- [nxpimage](https://spsdk.readthedocs.io/en/latest/apps/nxpimage.html):
  - add OTFAD support for RT5xx and RT6xx devices
- [pfr](https://spsdk.readthedocs.io/en/latest/apps/pfr.html):
  - read command allows independent binary and yaml exports
- shadowregs:
  - new subcommand: fuses-script
- add OEM cert size check into TPConfig

### Fixed

- [nxpdebugmbox](https://spsdk.readthedocs.io/en/latest/apps/nxpdebugmbox.html):
  - fix debug authentication for RT595
- [nxpimage](https://spsdk.readthedocs.io/en/latest/apps/nxpimage.html):
  - fix sb21 command line argument in documentation
- fix the use of pyyaml's load in tests (use safe_load())

## [1.7.0] - 2022-07-29

### Added

- [nxpimage](https://spsdk.readthedocs.io/en/latest/apps/nxpimage.html) application as replacement for elftosb
- [nxpcrypto](https://spsdk.readthedocs.io/en/latest/apps/nxpcrypto.html) application for generating and verifying keys, certificates, hash digest, converting key's format
- trust provisioning applications ([tphost](https://spsdk.readthedocs.io/en/latest/usage/applications.html#tphost) and [tpconfig](https://spsdk.readthedocs.io/en/latest/usage/applications.html#tpconfig))
- [blhost](https://spsdk.readthedocs.io/en/latest/apps/blhost.html):
  - support LifeCycleUpdate command for RT1180
  - add option to specify peripheral index of SPI/I2C for LIBUSBSIO
  - allow lowercase names in the filter for USB mboot devices
- [nxpdebugmbox](https://spsdk.readthedocs.io/en/latest/apps/nxpdebugmbox.html):
  - utility to read/write memory using debug probe
- [nxpimage](https://spsdk.readthedocs.io/en/latest/apps/nxpimage.html):
  - support of Master Boot Images
  - support AHAB container for RT1180
  - support of Secure Binary 2.1 / 3.1
  - support for TrustZone blocks
  - support for Bootable images for RTxxx devices
  - support for FCB block parsing and exporting for RTxxx and some RTxxxx devices
  - simply binary image support, like create, merge, extract and convert (S19,HEX,ELF and BIN format)
- [pfr](https://spsdk.readthedocs.io/en/latest/apps/pfr.html):
  - load PFR configuration directly from chip using BLHOST
- [sdphost](https://spsdk.readthedocs.io/en/latest/apps/sdphost.html):
  - support for SET_BAUDRATE command
  - support for iMX93
- drop support for Python 3.6
- pypemicro dependency update in order to cover latest bug fixes in this package
- libusbsio update to version 2.1.11
- unify debug options within applications
- add API to compute RKTH
- support LPC553x in elftosb/nxpimage
- support dual image boot on RT5xx and RT6xx
- replace click/sys.exit with raising an SPSDKAppError exception
- encryption of remapped images

### Fixed

- [blhost](https://spsdk.readthedocs.io/en/latest/apps/blhost.html):
  - efuse_program_once returns failure message when using 'lock' option but still the fuse is burnt
  - fix in re-scanning LIBUSBSIO devices when target MCU is not connected
  - scan_usb() should return nxp devices
  - read memory command doesn't print read data when mem region is defined
- [elftosb](https://spsdk.readthedocs.io/en/latest/usage/applications.html#elftosb):
  - fix trustzone config template for rt5xx and rt6xx
  - fix MBI_PLainRamRTxxx image
  - fix CRC bootable image on RT685 EVK
  - fix image located in FLASH executed in RAM on RT6xx
  - fix burning fuses in BD file
- [nxpdebugmbox](https://spsdk.readthedocs.io/en/latest/apps/nxpdebugmbox.html):
  - fix in Jlink debugger probe initialization
  - fix get-crp command

## [1.6.3] - 2022-04-01

### Added

- pypemicro dependency update in order to cover latest bug fixes in this package
- libusbsio update to version 2.1.11

### Fixed

- fix in rescanning LIBUSBSIO devices when target MCU is not connected
- efuse_program_once returns failure message when using 'lock' option but still the fuse is burnt
- fix memory leaks in elftosb

## [1.6.2] - 2022-03-11

### Added

- bump-up version of bincopy to <17.11
- add plain load image to build example bootable i.MX-RT image
- align docs requirements with project dependencies
- add stability notice to documentation
- speed-up application's start due to move of bincopy import

## [1.6.1] - 2022-03-04

### Added

- [blhost](https://spsdk.readthedocs.io/en/latest/apps/blhost.html):
  - add parameter --no-verify for efuse-program-once
  - add possibility to select USBSIO bridge device via VID:PID, USB path, serial number
  - lower the timeout during MBoot's UART Ping command
  - improve type hints for scan_* functions for detecting devices
- [elftosb](https://spsdk.readthedocs.io/en/latest/usage/applications.html#elftosb):
  - dynamically generate config json schema per family
- [nxpdevscan](https://spsdk.readthedocs.io/en/latest/apps/nxpdevscan.html):
  - extend scan with device serial number information
  - list all connected USB or UART or SIO devices
  - update device's USB path ([usb_device_identification](https://spsdk.readthedocs.io/en/latest/usage/usb.html))
- [sdphost](https://spsdk.readthedocs.io/en/latest/apps/sdphost.html):
  - improve type hints for scan_* functions for detecting SDP devices
- reduce number of findings from Pylint
- update JINJA2 requirement

### Fixed

- [blhost](https://spsdk.readthedocs.io/en/latest/apps/blhost.html):
  - fix UART open operation for RT1176, RT1050 and LPC55S06 platforms (and probably others)
- [elftosb](https://spsdk.readthedocs.io/en/latest/usage/applications.html#elftosb):
  - fix preset data for lpc55s0x, lpc55s1x
- SPI communication failure (changed FRAME_START_NOT_READY to 0xFF for SPI)
- PYI files are not included in the distribution package

## [1.6.0] - 2022-02-04

### Added

- [blhost](https://spsdk.readthedocs.io/en/latest/apps/blhost.html):
  - add experimental batch mode into blhost
  - support command get property 30
  - change output display for blhost get-property 8
  - provide the real exit code (status code) from BLHOST application
  - report progress of data transfer operations in blhost
  - performance boost in receive-sb-file
- [elftosb](https://spsdk.readthedocs.io/en/latest/usage/applications.html#elftosb):
  - validation inputs using jsonschemas
  - reorganize and improve elftosb
  - add support for more input file types
  - [RTxxx] HMAC_KEY is now accepted in binary form
- [nxpdebugmbox](https://spsdk.readthedocs.io/en/latest/apps/nxpdebugmbox.html):
  - move gendc into nxpdebugmbox
- [pfr](https://spsdk.readthedocs.io/en/latest/apps/pfr.html):
  - unify CMPA/CFPA fields descriptions and bit-field values within XML registers data
  - implement CMPA data generator and parser
- improve documentation
- remove dependency on munch and construct modules
- add support for reserved bitfields in registers
- support multiple occurrence of certificate attributes for subject/issuer
- remove backward compatibility mode in Registers
- reorganize functions from misc.py
- add support for bumpversion

### Fixed

- [blhost](https://spsdk.readthedocs.io/en/latest/apps/blhost.html):
  - generate-key-blob does not generate blob.bin on RT1176
  - parse_property_tag in blhost_helper converts incorrectly in some cases
  - different return code on Linux/Mac and Windows
  - USBSIO - fixed issue when busy signal on I2C was interpreted as data
- [crypto](https://spsdk.readthedocs.io/en/latest/api/crypto.html):
  - DER encoded certificates are loaded as PEM
  - fixed dependency on cryptography's internal keys
  - moved to fully typed versions of cryptography
- [elftosb](https://spsdk.readthedocs.io/en/latest/usage/applications.html#elftosb):
  - cannot build CRC image into ext flash for lpc55s3x
  - cannot generate signed image with <4 ROT keys
  - fixed some failing cases in regards of TZ
  - [rtxxx] missing plain for load-to-ram image
  - configuration validation failed in some cases
- [nxpdebugmbox](https://spsdk.readthedocs.io/en/latest/apps/nxpdebugmbox.html):
  - return code is 0 in case of fail
  - nxpdebugmbox fails on Linux
- [nxpdevhsm](https://spsdk.readthedocs.io/en/latest/apps/nxpdevhsm.html):
  - generate ends with general error when no container is provided
- [pfr](https://spsdk.readthedocs.io/en/latest/apps/pfr.html):
  - fix problem in registers class with another size of register than 32 bits
- pfrc:
  - displays false brick conditions
  - wrong validation of CMPA.CC_SOCU_PIN bits

## [1.5.0] - 2021-08-07

### Added

- [nxpdevhsm](https://spsdk.readthedocs.io/en/latest/apps/nxpdevhsm.html): new application added:
  - The nxpdevhsm is a tool to create initial provisioning SB3 file for LPC55S36 to provision device with SB KEK needed to validate in device all standard SB3 files.
- [LIBUSBSIO](https://www.nxp.com/design/software/development-software/library-for-windows-macos-and-ubuntu-linux:LIBUSBSIO?tid=vanLIBUSBSIO) integration as a replacement for HID_API module:
  - blhost - extend blhost by LPCUSBSIO interface
- [blhost](https://spsdk.readthedocs.io/en/latest/apps/blhost.html): following trust-provisioning  sub-commands added:
  - [oem_get_cust_cert_dice_puk](https://spsdk.readthedocs.io/en/latest/apps/blhost.html#blhost-trust-provisioning-oem-get-cust-cert-dice-puk): creates the initial trust provisioning keys
  - [oem_gen_master_share](https://spsdk.readthedocs.io/en/latest/apps/blhost.html#blhost-trust-provisioning-oem-gen-master-share): creates shares for initial trust provisioning keys
  - [oem_set_master_share](https://spsdk.readthedocs.io/en/latest/apps/blhost.html#blhost-trust-provisioning-oem-set-master-share): takes the entropy seed and the Encrypted OEM Master Share
  - [hsm_gen_key](https://spsdk.readthedocs.io/en/latest/apps/blhost.html#blhost-trust-provisioning-hsm-gen-key): creates OEM common keys, including encryption keys and signing keys
  - [hsm_store_key](https://spsdk.readthedocs.io/en/latest/apps/blhost.html#blhost-trust-provisioning-hsm-store-key): stores known keys, and generate the corresponding key blob
  - [hsm_enc_blk](https://spsdk.readthedocs.io/en/latest/apps/blhost.html#blhost-trust-provisioning-hsm-enc-blk): encrypts the given SB3 data bloc
  - [hsm_enc_sign](https://spsdk.readthedocs.io/en/latest/apps/blhost.html#blhost-trust-provisioning-hsm-enc-sign): signs the given data
- [elftosb](https://spsdk.readthedocs.io/en/latest/usage/applications.html#elftosb):
  - support for SB 2.1 generation using BD file
  - LPC55S3x - add support for unsigned/plain images
  - SB2.1 - SHA256 digest of all sections included in signed SB2.1 header
  - add supported families listing into elftosb
  - implement chip family option as a click.Choice
  - allow loading certificates for MBI in PEM format
- [nxpcertgen](https://spsdk.readthedocs.io/en/latest/usage/applications.html#nxpcertgen):
  - generate the template for yml configuration file containing the parameters for certificate
  - improve yml template description for nxpcertgen
  - add support for generating certificates in DER format
- [nxpkeygen](https://spsdk.readthedocs.io/en/latest/usage/applications.html#nxpkeygen):
  - moved option -p from general space to gendc subcommand.
  - add new -k keygen subcommand option to specify key type to generate
- [nxpdebugmbox](https://spsdk.readthedocs.io/en/latest/apps/nxpdebugmbox.html):
  - refactor DebugCredential base class so that it will be possible to pass certificates in yml config file
  - check nxpdebugmbox on LPC55S3x
- [pfr](https://spsdk.readthedocs.io/en/latest/apps/pfr.html): update CMPA/CFPA registers XML data for LPC55S3x with CRR update
- SPSDK [Applications](https://spsdk.readthedocs.io/en/latest/usage/applications.html#applications):
  - spsdk applications show help message when no parameter on command line provided
  - improved help messages
  - support Ctrl+C in cmd applications
- replace functional asserts with raising a SPSDK-based exception
- replace all general exception with SPSDK-based exceptions

### Fixed

- [nxpkeygen](https://spsdk.readthedocs.io/en/latest/usage/applications.html#nxpkeygen): regenerates a key without --force
- [elftosb](https://spsdk.readthedocs.io/en/latest/usage/applications.html#elftosb): unclear error message: No such file or directory: 'None'
- [pfr](https://spsdk.readthedocs.io/en/latest/apps/pfr.html): duplicated error message: The silicon revision is not specified
- [nxpdebugmbox](https://spsdk.readthedocs.io/en/latest/apps/nxpdebugmbox.html): fix Retry of AP register reads after Chip reset
- [nxpdebugmbox](https://spsdk.readthedocs.io/en/latest/apps/nxpdebugmbox.html): add timeout to never ending loops in spin_read/write methods in Debug mailbox
- [blhost](https://spsdk.readthedocs.io/en/latest/apps/blhost.html): flash-erase-region command doesn't accept the memory_id argument in hex form
- [elftosb](https://spsdk.readthedocs.io/en/latest/usage/applications.html#elftosb): using kdkAccessRights = 0 in SB31 is throwing an error in KeyDerivator

## [1.4.0] - 2021-06-25

### Added

- version flag added for all command-line application
- support for Python 3.9 added
- [blhost](https://spsdk.readthedocs.io/en/latest/apps/blhost.html): following sub-commands added:
  - list-memory
  - flash-program-once
  - set-property
  - flash-erase-all-unsecure
  - flash-security-disable
  - flash-read-resource
  - reliable-update
  - fuse-program
  - flash-image
  - program-aeskey
- [blhost](https://spsdk.readthedocs.io/en/latest/apps/blhost.html): memoryId clamp-down for mapped external memories added
- [elftosb](https://spsdk.readthedocs.io/en/latest/usage/applications.html#elftosb): support for SB 2.1 added
- [elftosb](https://spsdk.readthedocs.io/en/latest/usage/applications.html#elftosb): basic support for BD configuration file added
- [nxpdebugmbox](https://spsdk.readthedocs.io/en/latest/apps/nxpdebugmbox.html): debug port enabled check added
- [nxpkeygen](https://spsdk.readthedocs.io/en/latest/usage/applications.html#nxpkeygen): new sub-command added to nxpkeygen to create a template for configuration YML file for DC keys
- [nxpkeygen](https://spsdk.readthedocs.io/en/latest/usage/applications.html#nxpkeygen): new sub-command added to create a template for configuration YML file for DC keys
- [pfr](https://spsdk.readthedocs.io/en/latest/apps/pfr.html): default JSON config file generation removed, but still accepted as an input. The preferred is the YML configuration format.
- docs - Read The Docs documentation improvements

### Fixed

- wrong DCD size by BootImgRT.parse
- cmdKeyStoreBackupRestore wrong param description
- [blhost](https://spsdk.readthedocs.io/en/latest/apps/blhost.html): typo in McuBootConnectionError exception
- [blhost](https://spsdk.readthedocs.io/en/latest/apps/blhost.html): mcuBoot Uart doesn't close the device after failed ping command
- [blhost](https://spsdk.readthedocs.io/en/latest/apps/blhost.html): assertion error when connection lost during fuses readout
- [blhost](https://spsdk.readthedocs.io/en/latest/apps/blhost.html): sub-command  flash-read-resource fails when the length is not aligned
- [pfr](https://spsdk.readthedocs.io/en/latest/apps/pfr.html): incorrect keys hash computation for LPC55S3x
- [pfr](https://spsdk.readthedocs.io/en/latest/apps/pfr.html): wrong LPC55S69 silicon revision
- [pfr](https://spsdk.readthedocs.io/en/latest/apps/pfr.html): parse does not show PRINCE IV fields
- [sdphost](https://spsdk.readthedocs.io/en/latest/apps/sdphost.html): running spdhost --help fails
- shadowregs - bad DEV_TEST_BIT in shadow registers

## [1.3.1] - 2021-03-29

### Changed

- [pfr](https://spsdk.readthedocs.io/en/latest/apps/pfr.html): configuration template supports YAML with description, backward compatibility with JSON ensured
- [pfr](https://spsdk.readthedocs.io/en/latest/apps/pfr.html): API change: "keys" parameter has been moved from `__init__` to export
- [pfr](https://spsdk.readthedocs.io/en/latest/apps/pfr.html): sub-commands renamed:
  - user-config -> get-cfg-template
  - parse -> parse-binary
  - generate -> generate-binary
- [blhost](https://spsdk.readthedocs.io/en/latest/apps/blhost.html): allow key names for key-provisioning commands
- [blhost](https://spsdk.readthedocs.io/en/latest/apps/blhost.html): support for RT1170, RT1160
- shadowregs - shadow registers tool is now top-level module
- [blhost](https://spsdk.readthedocs.io/en/latest/apps/blhost.html): fix baud rate parameter
- [pfr](https://spsdk.readthedocs.io/en/latest/apps/pfr.html): fix in data for LPC55S6x, LPC55S1x, LPC55S0x
- [blhost](https://spsdk.readthedocs.io/en/latest/apps/blhost.html): communication stack breaks down on RT1170 after unsuccessful key-prov enroll command

## [1.3.0] - 2021-03-05

### Added

- support creation of SB version 3.1
- [elftosb](https://spsdk.readthedocs.io/en/latest/usage/applications.html#elftosb) application based on legacy elf2sb supporting SB 3.1 support
- [nxpdevscan](https://spsdk.readthedocs.io/en/latest/apps/nxpdevscan.html): application for connected USB, UART devices discovery
- shadowregs -  application for shadow registers management using DebugProbe
- support USB path argument in blhost/sdphost (all supported OS)
- [nxpcertgen](https://spsdk.readthedocs.io/en/latest/usage/applications.html#nxpcertgen) CLI application (basicConstrains, self-signed)
- [blhost](https://spsdk.readthedocs.io/en/latest/apps/blhost.html): commands added:
  - flash-erase-all
  - call
  - load-image
  - execute
  - key-provisioning
  - receive-sb-file
- [blhost](https://spsdk.readthedocs.io/en/latest/apps/blhost.html): extend commands' options:
  - configure-memory now allows usage of internal memory
  - extend error code in the output
  - add parameters lock/nolock into efuse-program-once command
  - add key selector option to the generate-key-blob command
  - add nolock/lock selector to efuse-program-once command
  - add hexdata option to the write-memory command

## 1.2.0 - 2020-12-11

### Added

- support for LPC55S3x devices
- extend support for LPC55S1x, LPC55S0x
- pfrc - console script for searching for brick conditions in pfr settings
- custom HSM support
- sdpshost CLI utility using sdpshost communication protocol
- remote signing for Debug Credential
- added command read-register into sdphost CLI
- dynamic plugin support
- MCU Link Debugger support
- [pfr](https://spsdk.readthedocs.io/en/latest/apps/pfr.html): added CMAC-based seal
- [pfr](https://spsdk.readthedocs.io/en/latest/apps/pfr.html): load Root of Trust from elf2sb configuration file

## 1.1.0 - 2020-09-04

### Added

- support for i.MX RT1170 device
- support for elliptic-curve cryptography (ECC)
- support for SDPS protocol
- included Debug Authentication functionality
- included support for debuggers
- [nxpkeygen](https://spsdk.readthedocs.io/en/latest/usage/applications.html#nxpkeygen): utility for generating debug credential files and corresponding keys

## 1.0.0 - 2020-04-04

### Added

- support for LPC55S69 and LPC55S16 devices
- support for i.MX RT105x and RT106x devices
- support for i.MX RT595S and RT685S devices
- connectivity to the target via UART, USB-HID.
- support for generating, saving, loading RSA keys with different sizes
- generation and management of certificate
- [blhost](https://spsdk.readthedocs.io/en/latest/apps/blhost.html): CLI utility for communication with boot loader on a target
- [sdphost](https://spsdk.readthedocs.io/en/latest/apps/sdphost.html): CLI utility for communication with ROM on a target
- [pfr](https://spsdk.readthedocs.io/en/latest/apps/pfr.html): CLI utility for generating and parsing Protected Flash Regions - CMPA and CFPA regions

[3.14.0]: https://github.com/nxp-mcuxpresso/spsdk/releases/tag/v3.14.0
[3.13.0]: https://github.com/nxp-mcuxpresso/spsdk/releases/tag/v3.13.0
[3.12.0]: https://github.com/nxp-mcuxpresso/spsdk/releases/tag/v3.12.0
[3.11.0]: https://github.com/nxp-mcuxpresso/spsdk/releases/tag/v3.11.0
[3.10.0]: https://github.com/nxp-mcuxpresso/spsdk/releases/tag/v3.10.0
[3.9.0]: https://github.com/nxp-mcuxpresso/spsdk/releases/tag/v3.9.0
[3.8.0]: https://github.com/nxp-mcuxpresso/spsdk/releases/tag/v3.8.0
[3.7.1]: https://github.com/nxp-mcuxpresso/spsdk/releases/tag/v3.7.1
[3.7.0]: https://github.com/nxp-mcuxpresso/spsdk/releases/tag/v3.7.0
[3.6.0]: https://github.com/nxp-mcuxpresso/spsdk/releases/tag/v3.6.0
[3.5.0]: https://github.com/nxp-mcuxpresso/spsdk/releases/tag/v3.5.0
[3.4.0]: https://github.com/nxp-mcuxpresso/spsdk/releases/tag/v3.4.0
[3.3.0]: https://github.com/nxp-mcuxpresso/spsdk/releases/tag/v3.3.0
[3.2.0]: https://github.com/nxp-mcuxpresso/spsdk/releases/tag/v3.2.0
[3.1.0]: https://github.com/nxp-mcuxpresso/spsdk/releases/tag/v3.1.0
[3.0.1]: https://github.com/nxp-mcuxpresso/spsdk/releases/tag/v3.0.1
[3.0.0]: https://github.com/nxp-mcuxpresso/spsdk/releases/tag/v3.0.0
[2.6.0]: https://github.com/nxp-mcuxpresso/spsdk/releases/tag/v2.6.0
[2.5.0]: https://github.com/nxp-mcuxpresso/spsdk/releases/tag/v2.5.0
[2.4.0]: https://github.com/nxp-mcuxpresso/spsdk/releases/tag/v2.4.0
[2.3.0]: https://github.com/nxp-mcuxpresso/spsdk/releases/tag/v2.3.0
[2.2.1]: https://github.com/nxp-mcuxpresso/spsdk/releases/tag/2.2.1
[2.2.0]: https://github.com/nxp-mcuxpresso/spsdk/releases/tag/2.2.0
[2.1.1]: https://github.com/nxp-mcuxpresso/spsdk/releases/tag/2.1.1
[2.1.0]: https://github.com/nxp-mcuxpresso/spsdk/releases/tag/2.1.0
[2.0.1]: https://github.com/nxp-mcuxpresso/spsdk/releases/tag/2.0.1
[2.0.0]: https://github.com/nxp-mcuxpresso/spsdk/releases/tag/2.0.0
[1.11.0]: https://github.com/nxp-mcuxpresso/spsdk/releases/tag/1.11.0
[1.10.2]: https://github.com/nxp-mcuxpresso/spsdk/releases/tag/1.10.2
[1.10.1]: https://github.com/nxp-mcuxpresso/spsdk/releases/tag/1.10.1
[1.10.0]: https://github.com/nxp-mcuxpresso/spsdk/releases/tag/1.10.0
[1.9.1]: https://github.com/nxp-mcuxpresso/spsdk/releases/tag/1.9.1
[1.9.0]: https://github.com/nxp-mcuxpresso/spsdk/releases/tag/1.9.0
[1.8.0]: https://github.com/nxp-mcuxpresso/spsdk/releases/tag/1.8.0
[1.7.1]: https://github.com/nxp-mcuxpresso/spsdk/releases/tag/1.7.1
[1.7.0]: https://github.com/nxp-mcuxpresso/spsdk/releases/tag/1.7.0
[1.6.3]: https://github.com/nxp-mcuxpresso/spsdk/releases/tag/1.6.3
[1.6.2]: https://github.com/nxp-mcuxpresso/spsdk/releases/tag/1.6.2
[1.6.1]: https://github.com/nxp-mcuxpresso/spsdk/releases/tag/1.6.1
[1.6.0]: https://github.com/nxp-mcuxpresso/spsdk/releases/tag/1.6.0
[1.5.0]: https://github.com/nxp-mcuxpresso/spsdk/releases/tag/1.5.0
[1.4.0]: https://github.com/nxp-mcuxpresso/spsdk/releases/tag/1.4
[1.3.1]: https://github.com/nxp-mcuxpresso/spsdk/releases/tag/1.3.1
[1.3.0]: https://github.com/nxp-mcuxpresso/spsdk/releases/tag/1.3
