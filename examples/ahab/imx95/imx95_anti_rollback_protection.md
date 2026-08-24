# i.MX95 Anti-rollback Protection Example

This guide provides guidance on how to enable the anti-rollback protection on ELE based i.MX devices using SPSDK. For additional information refer to the application note available at: https://www.nxp.com/doc/AN14533.

This example uses a signed U-Boot binary targeting i.MX95. To build and sign a bootable image with ELE firmware and U-Boot bootloader, follow the procedure described in the i.MX95 signed AHAB with U-Boot example.
 

## 1. Prerequisites
 - SPSDK is needed with examples extension. `pip install spsdk[examples]` (Please refer to the installation documentation.)
 - This demo was tested with i.MX95 EVK board wih LPDDR5 memory and A1 chip revision. 

### 1.1 Requirements
 - A valid signed bootable image containing U-Boot, ELE firmware and other necessary binaries for i.MX95 (see [i.MX95 signed AHAB with U-BOOT](../imx95/imx95_signed_ahab_uboot.ipynb) examples).

### 1.2 Device and connection configuration

Adjust these variables to match your setup:

```bash
FAMILY="mimx9596"
DEVICE="uboot_serial"
PORT="/dev/ttyUSB0"
VERBOSITY="-v"
```

## 2. Anti-rollback protection enablement

To enable anti-rollback protection, the NXP container or OEM container must have the *fuse version* that is intended to commit to the fuses. The user can then send an ELE commit command to program the corresponding fuses.

### 2.1 Commit NXP fuse version

After writing the AHAB image with *nxpuuu*, set the boot mode to Cortex-M eMMC (1010 on EVK boot switch) and reset the board. Find the serial port that belongs to U-Boot console and interrupt the boot. When the console is switched to U-Boot menu, we can use the *nxpele* tool to communicate with the ELE and burn the version values into fuses.

```bash
nxpele -f mimx9596 -d uboot_serial -p /dev/ttyUSB17 commit -i NXP_FW_FUSE 
```

The NXP container is released with the BSP in a binary format. NXP manages the fuse version in the NXP container, usually increasing it with major feature changes. The user cannot modify
the fuse version value in the NXP container because the container header is signed with NXP keys. For the semantic versioning specification of ELE firmware <x.y.z>, the x represent the major version which is used for the fuse version. See below table with an example of the NXP container fuse version.


| Firmware Filename             | Version   | Fuse Version          | Value |
|-------------------------------|-----------|-----------------------|-------|
| mx93a1-ahab-container.img     | Q3 2024   | v1.2.0-38f309fe       | 0x1   |

Commit the NXP firmware fuse version (make sure the board is booted and U-Boot console is accessible):

```bash
nxpele $VERBOSITY -f $FAMILY -d $DEVICE -p $PORT commit -i nxp_fw_fuse
```

### 2.3 Commit OEM fuse version

The OEM container fuse version corresponds to the *fuse_version* field in the AHAB container YAML files. Therefore, this field should be set to the desired value before sending the commit command. The commit procedure follows the same steps as before, with the exception of using different commit information.

```bash
nxpele -f mimx9596 -d uboot_serial -p /dev/ttyUSB17 commit -i OEM_FW_FUSE 
```

Commit the OEM firmware fuse version (ensure the fuse_version field is set in the AHAB container YAML before committing):

```bash
nxpele $VERBOSITY -f $FAMILY -d $DEVICE -p $PORT commit -i oem_fw_fuse
```

### 2.4 Verify committed fuse versions

After committing fuse versions, use the `nxpele get-info` command to verify the device state and check the current lifecycle and firmware information.

```bash
nxpele $VERBOSITY -f $FAMILY -d $DEVICE -p $PORT get-info
```

## 3. Test 

The following information relates to negative testing scenarios — for example, evaluating system behavior when attempting to boot with NXP/OEM containers that have fuse version values lower than the one already programmed.

### 3.1 NXP fuse version

If the NXP fuse version check fails, the NXP container does not boot up in the OEM Open/Closed/Locked lifecycle.

### 3.2 OEM fuse version

On OEM Closed/Locked devices, if the OEM fuse version check fails, the container does not boot up. Every OEM container fuse version is checked against the OEM version value in the fuses. On an OEM Open device, the container boots up with ELE event - similar to the one provided below. For additional information regarding ELE events, refer to the EdgeLock Secure Enclave User Guide.

```bash
The command of the ELE event is 0x87 – ELE_OEM_CNTN_AUTH_REQ.
The indicator of the ELE event is 0xF8 – ELE_BAD_VERSION_FAILURE_IND.
The status field is 0xD6 – SUCCESS as the device is in the OEM Open life cycle mode.
```
