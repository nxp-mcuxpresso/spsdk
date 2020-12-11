NXP Secure Provisioning SDK
===========================

**Secure Provisioning SDK (SPSDK)** allows the user to connect and communicate with a device; configure the device; prepare, download, and upload data including security operations. It is delivered in a form of python library and command-line applications.

* [Documentation](https://spsdk.readthedocs.io)

Architecure
-----------
<img src="docs/_static/images/SPSDK-Architecture.png" alt="drawing" width="400"/>

**SPSDK** is a library which may be separated into the following layers based on performed functionality:

- **Application Layer** is a layer allowing SPSDK integration into various applications such as command-line utilities, GUI tools, DevOps/Automation infrastructure which is used in prototyping, production, or testing environments or any application based on specific customer needs. As a part of the library, several command-line applications are [included](spsdk/apps). 

- **Library Layer** abstracts functionality related to images or messages creation and parsing including required security and cryptography functionality.
    - SB - Secure Boot File [module](https://spsdk.readthedocs.io/en/latest/api/sbfile.html).
    - MBI - Master Boot Image [module](https://spsdk.readthedocs.io/en/latest/api/image.html).
    - Crypto - Cryptography [module](https://spsdk.readthedocs.io/en/latest/api/crypto.html).
    
- **Protocol Layer** packs or unpacks messages and images into a protocol defined by the required device counterpart.
    - BL Host [module](https://spsdk.readthedocs.io/en/latest/api/mboot.html).
    - SDP Host [module](https://spsdk.readthedocs.io/en/latest/api/sdp.html).

- **Communication Layer** links SPSDK and connected devices.

Supported Devices
----------------
Following NXP devices are supported:
- [LPCXpresso55S69](https://www.nxp.com/products/processors-and-microcontrollers/arm-microcontrollers/general-purpose-mcus/lpc5500-cortex-m33/lpcxpresso55s69-development-board:LPC55S69-EVK), 
- [LPCXpresso55S16](https://www.nxp.com/design/development-boards/lpcxpresso-boards/lpcxpresso55s16-development-board:LPC55S16-EVK)
- [LPC55S28](https://www.nxp.com/design/software/development-software/lpcxpresso55s28-development-board:LPC55S28-EVK), 
- [LPC55S06](https://www.nxp.com/design/development-boards/lpcxpresso-boards/lpcxpresso-development-board-for-lpc55s0x-0x-family-of-mcus:LPC55S06-EVK), 
- [i.MX RT600](https://www.nxp.com/products/processors-and-microcontrollers/arm-microcontrollers/i-mx-rt-crossover-mcus/i-mx-rt600-crossover-mcu-with-arm-cortex-m33-and-dsp-cores:i.MX-RT600)
- [i.MX RT1050](https://www.nxp.com/products/processors-and-microcontrollers/arm-microcontrollers/i-mx-rt-crossover-mcus/i-mx-rt1050-crossover-mcu-with-arm-cortex-m7-core:i.MX-RT1050), [i.MX RT1060](https://www.nxp.com/products/processors-and-microcontrollers/arm-microcontrollers/i-mx-rt-crossover-mcus/i-mx-rt1060-crossover-mcu-with-arm-cortex-m7-core:i.MX-RT1060)

Installation
------------
- Make sure to have Python 3.6+ installed
- Create a virtual environment (venv, pipenv, etc.)

Directly from GitHub:

``` bash
    $ pip install -U https://github.com/NXPmicro/spsdk/archive/master.zip
```

Install SPSDK from sources:

``` bash
    $ git clone https://github.com/NXPmicro/spsdk.git
    $ cd spsdk
    $ pip install -r requirements-develop.txt
    $ pip install -U -e .
```
> In **Windows OS** you need to install [Microsoft Visual C++ Build Tools](https://www.scivision.dev/python-windows-visual-c-14-required/)
 
 Note: If you use pip version 20.3, please downgrade it to 20.2.4, because of new resolver functionality.

Usage
-----

- See [examples](examples) directory
- See [application](spsdk/apps) directory

---
**i.Mx RT 1050**

To run examples using i.MX RT 1050 you need to download a flashloader:
- Go to: https://www.nxp.com/webapp/sps/download/license.jsp?colCode=IMX-RT1050-FLASHLOADER
- Review the license agreement, download and unzip the package
- Convert the elf file into bin (For this operation you need to have MCUXpresso IDE, IAR or Keil)
  - run ```python tools\flashloader_converter.py --elf-path <path/to/flashloader.elf> --ide-type <mcux | iar | keil> --ide-path <path/to/IDE/install/folder```

---

Dependencies
------------

SPSDK requires [Python](https://www.python.org) >3.5 and <3.9 interpreter, old version 2.x is not supported !

- requirements.txt
  - list of requirements for running SPSDK core + apps
- requirements-develop.txt
  - requirements needed for development (running tests, checking coding style)
- docs/requirements.txt
  - requirements needed for generating docs
