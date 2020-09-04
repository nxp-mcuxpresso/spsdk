NXP SPSDK Applications
----------------------
After installing SPSDK, several applications are present directly on PATH as executables.

- [spsdk](spsdk_apps.py) - entry point for all available applications.
- [blhost](blhost.py) - console script for MBoot module.
- [sdphost](sdphost.py) - console script for SDP module.
- [pfr](pfr.py) - simple utility for creation and analysis of protected regions - CMPA and CFPA.
- [nxpkeygen](nxpkeygen.py) - utility for generating RSA/ECC key pairs and debug credential files based on YAML configuration file
- [nxpdebugmbox](nxpdebugmbox.py)- utility for performing the Debug Authentication

`` spsdk --help`` - lists all available commands.

`` spsdk <application> --help`` - print help for given application. 

`` spsdk <application> <command> --help `` - print help for given command.
