.. SPSDK links definition block

.. Project location

.. _github_loc: https://github.com/NXPmicro/spsdk
.. _pypi_loc: https://pypi.org/project/spsdk/

.. Start of SPSDK document

============
Introduction
============

**Secure Provisioning SDK (SPSDK)** is a unified, reliable, and easy to use Python SDK library working across the NXP MCU portfolio providing a strong foundation from quick customer prototyping up to production deployment.

The library allows the user to connect and communicate with the device, configure the device, prepare, download, and upload data including security operations.

It is delivered in a form of:

- :ref:`Applications` - applications which could be called from command-line using Python virtual environment,
- :ref:`APIs` - functions in form of Python library.

.. figure:: _static/images/spsdk-architecture.png
    :scale: 50 %

========
Delivery
========

*SPSDK* is delivered to:

- `GitHub <github_loc_>`__
- `PyPI <pypi_loc_>`__

============
Organization
============

*SPSDK* is organized into modules:

.. include:: _prebuild/table_project_structure.inc

=================
Supported Devices
=================

.. include:: _prebuild/devices_table.inc
    :parser: myst_parser.sphinx_


============
Supported OS
============

- Windows 10 and 11, 64bit
- Ubuntu 22.04.1 LTS
- Mac OS Sonoma 14

=====================
Supported Environment
=====================

SPSDK is tested on *Python 3.9+* interpreter, old version 2.x is not supported.

===========
Versioning
===========

In a given version ``spsdk x.y.z``

* ``x`` major version (`SemVer <https://semver.org/>`_)
* ``y`` minor version
* ``z`` patch version

========================
CLI/API stability notice
========================

* **Minor release may break compatibility!!!**
* Patch release will not break backward compatibility (any occurrence is treated as a bug)

New features might be implemented in both patch and minor releases.

==========
Disclaimer
==========

All products, including those with advanced security features, may be subject to unidentified vulnerabilities. Customers are responsible for the design and operation of their applications and products to reduce the effect of these vulnerabilities on the customer's applications and products.  NXP accepts no liability for any security vulnerability.  Customers are responsible for the design and operation of their applications and products and are responsible to implement appropriate design and operating safeguards to minimize the risk of potential security vulnerabilities associated with their applications and products.


.. toctree::
    :caption: Project overview
    :maxdepth: 1
    :hidden:

    self
    release_notes
    migration_guide
    devices_list

.. toctree::
    :caption: Usage
    :maxdepth: 1
    :hidden:

    usage/installation
    usage/applications
    usage/apis
    examples/plugins/README

.. toctree::
    :caption: Supported Binary Images
    :maxdepth: 1
    :hidden:

    images/executable
    images/secure_update
    images/flash
    images/bootable

.. toctree::
    :caption: Application User Guides
    :maxdepth: 1
    :hidden:

    apps/blhost
    apps/dk6prog
    apps/el2go
    apps/ifr
    apps/nxpcrypto
    apps/nxpdebugmbox
    apps/nxpdevhsm
    apps/nxpdevscan
    apps/nxpele
    apps/nxpimage
    apps/nxpmemcfg
    apps/pfr
    apps/sdphost
    apps/sdpshost
    apps/shadowregs
    apps/trust_provisioning
    apps/nxpwpc


.. toctree::
    :caption: API Development Guide
    :maxdepth: 1
    :hidden:

    api/crypto
    api/dat
    api/debuggers
    api/dk6
    api/ele_msg
    api/image
    api/mboot
    api/memcfg
    api/pfr
    api/sbfile
    api/sdp
    api/shadowregs
    api/spsdk
    api/tp
    api/wpc
    api/utils

.. toctree::
    :caption: General examples
    :maxdepth: 1
    :hidden:

    examples/jupyter
    examples/init_notebook
    examples/flashloader/ahab/rt118x_signed_flashloader
    examples/flashloader/hab/rt105x_flashloader
    examples/general/crypto
    examples/general/image
    examples/general/image_dcd
    examples/general/image_srk
    examples/general/sbfile
    examples/general/mboot
    examples/general/sdp_mboot
    examples/general/sdp
    examples/general/sdps
    examples/general/get_keys
    examples/signature_prov
    examples/wpc_provisioning

.. toctree::
    :caption: MCU examples
    :maxdepth: 1
    :hidden:

    examples/lpc55sxx_secure_boot/lpc55sxx_secure_boot
    examples/lpc55sxx_secure_boot/lpc55sxx_secure_fw_update
    examples/kw45xx_k32w1xx/kw45xx_k32w1xx_secure_boot
    examples/kw45xx_k32w1xx/kw45xx_k32w1xx_load_NBU_image
    examples/dk6/dk6prog_intro
    examples/mc56/mc56_devhsm
    examples/rw61x/shadowregs/rw61x_shadowregs
    examples/rw61x/debug_auth/rw61x_debug_auth
    examples/rw61x/bootable_image/rw61x_bootable_image
    examples/mcxn9xx_debug_auth/mcxn9xx_debug_auth
    examples/imx93/imx93_ahab_uboot
    examples/imx93/imx93_signed_ahab_uboot
    examples/rt118x/rt118x_debug_authentication
    examples/rt118x/rt118x_secure_boot


.. Indices and tables
.. ==================

.. * :ref:`genindex`
.. * :ref:`modindex`
.. * :ref:`search`
