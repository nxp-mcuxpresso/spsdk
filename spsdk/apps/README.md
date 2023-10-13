# SPSDK Applications

After installing SPSDK, several applications are present directly on PATH as executables.

- [spsdk](spsdk_apps.py) - entry point for all available applications.
- [blhost](blhost.py) - console script for MBoot module.
- [ifr](ifr.py) - simple utility for creation and analysis of IFR0 region.
- [dk6prog](dk6prog.py) - utility for DK6 Programming tool.
- [nxpdevhsm](nxpdevhsm.py) - utility for generating initialization SB file.
- [nxpdebugmbox](nxpdebugmbox.py) - utility for performing the Debug Authentication.
- [nxpdevscan](nxpdevscan.py) - utility for listing all connected NXP USB and UART devices.
- [nxpcrypto](nxpcrypto.py) - utility for generating/verifying RSA/ECC key pairs, and converting key file format (PEM/DER/RAW).
- [nxpimage](nxpimage.py) - utility for generating TrustZone, MasterBootImage and SecureBinary images.
- [pfr](pfr.py) - simple utility for creation and analysis of protected regions - CMPA and CFPA.
- [sdphost](sdphost.py) - console script for SDP module.
- [sdpshost](sdpshost.py) - console script for SDPS module.
- [shadowregs](shadowregs.py) -  utility for Shadow Registers controlling.
- [nxpele](nxpele.py) -  utility for communication with NXP EdgeLock Enclave.


`` spsdk --help`` - lists all available commands.

`` spsdk <application> --help`` - print help for given application.

`` spsdk <application> <command> --help `` - print help for given command.
