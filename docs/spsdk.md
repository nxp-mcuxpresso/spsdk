Overview
========

Secure Provisioning SDK (SPSDK) is unified, reliable and easy to use SW library working across NXP MCU and MPU portfolio providing strong 
foundation from quick customer prototyping up to production deployment. Is following the philosophy: **code less but do more**. 

<p align="center">
  <img src="_static/images/spsdk.png" alt="SPSDK Concept"/>
</p>

**SPSDK Modules:**

- **MBoot** - Covering functionality of `blhost` tool
- **SDP** - Covering functionality of `sdphost` tool
- **Image** - Covering functionality of `srktool`, `dcdgen`, `mkimage` and other similar tools
- **SBFile** - Covering functionality of `elftosb` tool


Dependencies
============

SPSDK requires [Python](https://www.python.org) >3.5 interpreter, old version 2.x is not supported !

The core dependencies are included in requirements.txt file. 

The dependencies for the development are included in requirements-develop.txt.

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
> In Windows OS you need to instal [Microsoft Visual C++ Build Tools](https://www.scivision.dev/python-windows-visual-c-14-required/)

Contribution
============
