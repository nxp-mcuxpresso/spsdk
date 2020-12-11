Overview
========

Secure Provisioning SDK (SPSDK) is unified, reliable and easy to use SW library working across NXP MCU and MPU portfolio providing strong 
foundation from quick customer prototyping up to production deployment. Is following the philosophy: **code less but do more**. 

<p align="center">
  <img src="_static/images/spsdk.png" alt="SPSDK Concept"/>
</p>

**SPSDK Modules:**

- **Crypto** - Support for key's and certificate's operations
- **DAT** - Covering functionality of `debug authentication` tool
- **Image** - Covering functionality of `srktool`, `dcdgen`, `mkimage` and other similar tools
- **MBoot** - Covering functionality of `blhost` tool
- **PFR** - Support for configuration of Protected Flash Region areas (CMPA, CFPA)
- **SBFile** - Covering functionality of `elftosb` tool
- **SDP** - Covering functionality of `sdphost` tool


Installation
============

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
> In Windows OS you need to install [Microsoft Visual C++ Build Tools](https://www.scivision.dev/python-windows-visual-c-14-required/)


Note: If you use pip version 20.3, please downgrade it to 20.2.4, because of new resolver functionality.
 
Dependencies
============

SPSDK requires [Python](https://www.python.org) >3.5 and <3.9 interpreter, old version 2.x is not supported !

The core dependencies are included in requirements.txt file. 

The dependencies for the development and testing are included in requirements-develop.txt.
