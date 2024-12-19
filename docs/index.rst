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

    examples/_knowledge_base/installation_guide
    usage/applications
    usage/apis

    Application User Guides <apps/index>
    API Development Guide <api/index>

    examples/plugins/README

.. toctree::
    :caption: Supported Binary Images
    :maxdepth: 1
    :hidden:

    images/executable
    images/secure_update
    images/flash
    images/bootable
    examples/_knowledge_base/cert_block_summary

.. toctree::
    :caption: Examples
    :maxdepth: 1
    :hidden:


    examples/jupyter
    examples/ahab/index
    examples/blhost/blhost
    examples/bootable_image/index
    examples/certificate_block/index
    examples/crypto/index
    examples/dat/index
    examples/devhsm/index
    examples/dice/index
    examples/dk6/dk6prog_intro
    examples/el2go/index
    examples/hab/index
    examples/lpcprog/lpcprog
    examples/mbi/index
    examples/memcfg/index
    examples/otfad/index
    examples/sb/index
    examples/sdp/index
    examples/shadowregs/index
    examples/signature_provider/index
    examples/wpc_provisioning/index

