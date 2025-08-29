==========================
Secure update
==========================

Containers used for secure device firmware ugprade that cannot be executed directly on target but must be processed by the bootROM first.

--------------
Secure Binary
--------------

Secure binary is a binary output file that contains the user's application image along with a series of bootloader commands.
The output file is known as a "Secure Binary" or SB file for short.
These files typically have an .sb extension.

This format has a long history, the latest version is 4.0. (2025).
SPSDK nxpimage tool supports SB 2.1 (2.0), SB 3.1 and SB 4.0.

.. toctree::
    :caption: Secure Binary
    :maxdepth: 1

    sb2
    sb3
    sb4
    sbc
