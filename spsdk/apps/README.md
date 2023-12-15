# SPSDK Applications

After installing SPSDK, several applications are present directly on PATH as executables.

- [spsdk](spsdk_apps.py) - entry point for all available applications.
- [blhost](blhost.py) - console script for MBoot module.
- [dk6prog](dk6prog.py) - utility for DK6 Programming tool.
- [ifr](ifr.py) - simple utility for creation and analysis of IFR0 region.
- [nxpcrypto](nxpcrypto.py) - utility for generating/verifying RSA/ECC key pairs, and converting key file format (PEM/DER/RAW).
- [nxpdebugmbox](nxpdebugmbox.py) - utility for performing the Debug Authentication.
- [nxpdevhsm](nxpdevhsm.py) - utility for generating initialization SB file.
- [nxpdevscan](nxpdevscan.py) - utility for listing all connected NXP USB and UART devices.
- [nxpele](nxpele.py) -  utility for communication with NXP EdgeLock Enclave.
- [nxpimage](nxpimage.py) - utility for generating TrustZone, MasterBootImage and SecureBinary images.
- [pfr](pfr.py) - simple utility for creation and analysis of protected regions - CMPA and CFPA.
- [sdphost](sdphost.py) - console script for SDP module.
- [sdpshost](sdpshost.py) - console script for SDPS module.
- [shadowregs](shadowregs.py) -  utility for Shadow Registers controlling.
- [tpconfig](tpconfig.py) -  utility for Trust provisioning config application.
- [tphost](tphost.py) -  utility for Trust provisioning host application.


`` spsdk --help`` - lists all available commands.

`` spsdk <application> --help`` - print help for given application.

`` spsdk <application> <command> --help `` - print help for given command.
