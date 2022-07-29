# SPSDK Applications

After installing SPSDK, several applications are present directly on PATH as executables.

- [spsdk](spsdk_apps.py) - entry point for all available applications.
- [blhost](blhost.py) - console script for MBoot module.
- [elftosb](elftosb.py) - (Deprecated; replaced by nxpimage) utility for generating TrustZone, MasterBootImage and SecureBinary images.
- [nxpcertgen](nxpcertgen.py) - utility for generating  the self-signed x.509 certificate.
- [nxpdebugmbox](nxpdebugmbox.py) - utility for performing the Debug Authentication.
- [nxpdevscan](nxpdevscan.py) - utility for listing all connected NXP USB and UART devices.
- [nxpkeygen](nxpkeygen.py) - (Deprecated; replaced by nxpcrypto) utility for generating RSA/ECC key pairs.
- [nxpcrypto](nxpcrypto.py) - utility for generating/verifying RSA/ECC key pairs, and converting key file format (PEM/DER/RAW).
- [nxpimage](nxpimage.py) - utility for generating TrustZone, MasterBootImage and SecureBinary images.
- [pfr](pfr.py) - simple utility for creation and analysis of protected regions - CMPA and CFPA.
- [pfrc](pfrc.py) - simple utility for search of brick-conditions in PFR settings.
- [sdphost](sdphost.py) - console script for SDP module.
- [sdpshost](sdpshost.py) - console script for SDPS module.
- [shadowregs](shadowregs.py) -  utility for Shadow Registers controlling.


`` spsdk --help`` - lists all available commands.

`` spsdk <application> --help`` - print help for given application.

`` spsdk <application> <command> --help `` - print help for given command.
