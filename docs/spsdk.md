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

Installation directly from master branch [bitbucket.sw.nxp.com](https://bitbucket.sw.nxp.com/spsdk):

```bash
pip install -U https://bitbucket.sw.nxp.com/rest/api/latest/projects/SPSDK/repos/spsdk/archive?format=zip
```

If you will be asked for credentials, use your NXP login and password:

```text
User for bitbucket.sw.nxp.com: nxa...
Password: ******
```

In case of development, install SPSDK from sources:

```bash
git clone ssh://git@bitbucket.sw.nxp.com/spsdk/spsdk.git
cd spsdk
pip install -r requirements-develop.txt
pip install -U -e .
```
 

Contribution
============