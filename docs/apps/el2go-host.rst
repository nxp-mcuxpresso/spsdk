.. |br| raw:: html

   <br/>

=======================
User Guide - el2go-host
=======================
This user's guide describes how to interface with the *EdgeLock 2GO service* and *Edgelock 2GO NXP Provisioning Firmware* using the *el2go-host* application.

The *el2go-host* application is a command-line utility used on the host computer to act as an intermediate layer between Edgelock 2GO Service's REST API and Edgelock 2GO NXP Provisioning Firmware running on a device. The application only sends one command per invocation.

-------------
Prerequisites
-------------
* Activate and configure your EdgeLock 2GO account (https://www.nxp.com/products/security-and-authentication/secure-service-2go-platform/edgelock-2go:EDGELOCK-2GO)
* Install Secure Provisioning SDK(SPSDK)
* Load on the device *EdgeLock 2GO NXP Provisioning Firmware*

----------------------------------
Setup of the EdgeLock 2GO platform
----------------------------------
In the documentation menu of your EdgeLock 2GO account available at https://www.edgelock2go.com you can find the documents which explain how to setup the EdgeLock 2GO Account to:

#. Create EdgeLock 2GO API key
#. Create device group
#. Create Secure Object
#. Assign Secure Object to Device Group

-------------
Communication
-------------

The *el2go-host* application communicates with the *EdgeLock 2GO API* over the host computer's internet network and
with the *EdgeLock 2GO NXP Provisioning Firmware* over the host computer's UART (Serial Port) or USB connections.

*EdgeLock 2GO NXP Provisioning Firmware* supports I2C and SPI connections if an external BUSPAL connection is used.

el2go-host - USB
================

*el2go-host* could be connected to MCU Bootloader and EdgeLock 2GO NXP Provisioning Firmware over USB HID.

:ref:`USB device identification in SPSDK`

el2go-host - UART
=================

*el2go-host* could be connected to MCU bootloader and EdgeLock 2GO NXP Provisioning Firmware over UART.

:ref:`UART device identification in SPSDK`

el2go-host - BUSPAL
===================

The BusPal acts as a bus translator running on selected platforms. BusPal assists *el2go-host* in carrying out commands and responses from the target device through an established connection with *el2go-host* over UART, and the target device over I2C or SPI.

----------------------
Command line interface
----------------------
*el2go-host* consist of a set of sub-commands followed by options and arguments.

Some of these commands are used for communication with *EdgeLock 2GO* and others with the *EdgeLock 2GO NXP Provisioning Firmware* running on device.

.. click:: spsdk.apps.el2go:main
    :prog: el2go-host
    :nested: full

-------------
Usage example
-------------

A proposed order of *el2go-host* application usage is presented below:

* **get-template**
    * **Syntax**:

    .. code-block:: python

            el2go-host get-template -f [CHIP_FAMILY] -o [PATH_TO_OUTPUT_FILE]

    * **Description**: A configuration file template will be generated on the desired path and for the desired chip family.

* **test-connection(Optional)**
    * **Syntax**:

    .. code-block:: python

            el2go-host test-connection -c [PATH_TO_CONFIG_FILE]

    * **Description**: Given the path to the configuration file, a request to EdgeLock 2GO REST API will be send to establish connection with the service.

* **get-secure-objects**
    * **Syntax**:

    .. code-block:: python

            el2go-host get-secure-objects [INTERFACE_OPTIONS] -c [PATH_TO_CONFIG_FILE] -o [PATH_TO_OUTPUT_BINARY_FILE]

    * **Description**: Given the path to the configuration file, with required inputs defined, this command will:

        * Harvest device's UUID.
        * Whitelist device to the defined Device Group.
        * Request generation of Secure Objects assigned to the Device Group.
        * Download and store locally to a binary file the Secure Objects.

    * **Note**: Device needs to be in ISP boot mode.

* **get-fw-version**
    * **Syntax**:

    .. code-block:: python

            el2go-host get-fw-version [INTERFACE_OPTIONS]

    * **Description**: Since EdgeLock 2GO NXP Provisioning Firmware is loaded on the device, with this command Firmware's version can be extracted. Also, user can check if communication have been established between host machine and EdgeLock 2GO NXP Provisioning Firmware.

    * **Note**: Device needs to be in FlexSPI boot mode.

* **close-device**
    * **Syntax**:

    .. code-block:: python

            el2go-host close-device [INTERFACE_OPTIONS] [ADDRESS]

    * **Description**: This command will provision the device. The FLASH memory address where Secure Objects downloaded using *get-secure-objects* should be passed as argument or else operation will fail.

    * **Note**: Device needs to be in FlexSPI boot mode.
