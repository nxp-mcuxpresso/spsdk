===================================
User Guide - OEM Trust Provisioning
===================================

The aim of the trust provisioning is to enable customers to manufacture parts in the untrusted factories using SmartCard HSM.

The trust provisioning deliverables are provisioning firmware (TPFW), SmartCard with the applet and tphost and tpconfig apps.
Tphost and tpconfig apps are part of the SPSDK. Tphost application is used to secure the trust provisioning process of loading user application in the un-trusted environment.
Tpconfig application is used for the configuration and personalization of the Smart Card.

.. note::
    *TP device* is a hardware security module in this case it's JCOP4 SmartCard with the provisioning applet provided by the NXP.

    *TP target* is an MCU to be provisioned (LPC55S69).

---------------------
Device configuration
---------------------

Device (SmartCard) needs to be configured before use. First we need to insert card to the contact smart card reader and connect it to the PC. Card reader should support PC/SC interface.

Once the device is connected we should see the device ID and the applet version using the command below.

.. code:: bash

    tpconfig list-tpdevices

    #   Name                                                                     Description     Version   Serial number
    -----------------------------------------------------------------------------------------------------------------------------
    0   SCM Microsystems Inc. SCR 3310 [CCID Interface] (53312103235597) 00 00   TP HSM Applet   1.0.9     105276681024525924


If the device has successfully connected we can proceed to the next step - generate configuration template. Template configuration is done using the
*get-cfg-template* subcommand.

.. code:: bash

    tpconfig get-cfg-template -o <config_path.yaml>


Configuration template can look like this

.. code-block:: yaml

    # The template configuration file for TPCONFIG application
    version: 3

    # Target family
    family: lpc55s6x

    ## Provisioning data definition

    # Path to CMPA binary
    cmpa_path:
    # Path to CFPA binary
    cfpa_path:
    # Path to SB file Key Encryption Key
    sb_kek_path:
    # Path to USER Key Encryption Key
    user_kek_path:
    # Production quota
    production_quota: 1_000_000

    # Path to key for Audit log signing
    oem_log_prk_path:

    # Path to device family attestation certificate
    nxp_prod_cert_path:

    ## OEM ID Certificates definitions

    # Number of OEM certificates to generate
    # If it's set to 0, rest of this section is ignored
    oem_id_count:
    # Signing key path (PEM or DER encoded P-256 ECC Key)
    oem_id_prk_path:
    # Addresses where to place OEM Certificates
    oem_id_addresses:
    - 0x1004_0000
    - 0x1004_1000
    - 0x1004_2000
    - 0x1004_3000
    # Configuration of data inside OEM Certificates
    oem_id_config:
    issuer:
        COMMON_NAME: Big Tech Company
        COUNTRY_NAME: CZ
        LOCALITY_NAME: RpR
        STREET_ADDRESS: 1. maje, 1009
        ORGANIZATION_NAME: "BL - EP"
        POSTAL_CODE: 756 61
    subject:
        COMMON_NAME: Super Tech Device
    duration: 3650

    # TP Device connection definition

    # The examples of configuration of TP device
    tp_device: scard

    # The example of specifying configuration for TP device
    tp_device_parameter:
        id: 105276681024525924

    # Timeout configuration in seconds
    timeout: 60

Fill the path to the CFPA, CMPA, SBKEK and USERKEK. Production quota is the limit of devices to be manufactured, *oem_log_prk_path* is a path to the key that will be used for audit log signing. OEM certificates part is optional, you can choose up to 4 OEM certificates that will be generated for the device. The TP device configuration is specified in the *tp_device_parameter* section, the most important parameter is the unique ID of the device that we obtained using the *list-tpdevices* subcommand.

When the configuration is filled up, it's time to load the configuration to the Smart Card using the *load* subcommand.

.. code:: bash

    tpconfig load -c <config_path.yaml>

.. warning::

    Use the option -s to seal the smart card. Use carefully, you will not be able to use tpconfig afterwards!

--------------------
Target provisioning
--------------------

To provision the target we will use the tphost application. Configuration for the tphost application is also provided as a YAML file.
First we can generate template configuration. Template configuration is created using the *get-cfg-template* subcommand.

.. code:: bash

    tphost get-cfg-template -o <config_path.yaml>

Configuration template can look like this

.. code-block:: yaml

    # The template configuration file for TPHOST application
    version: 2

    # The example of device configuration
    family: lpc55s6x

    ## Data settings

    # OEM Provisioning firmware provided by NXP (optional)
    # if omitted, use blhost's receive-sb-file to load prov_fw beforehand
    prov_firmware: c:/oem_prov_fw.sb2

    # The user application SB(secure binary) file (optional)
    # if omitted, use blhost's receive-sb-file to load prov_fw afterwards
    firmware: c:/myapp.sb

    # Path to audit log
    audit_log: c:/audit_log.db

    # Path to audit log validation key (public or private, PEM or DER)
    audit_log_key: c:/oem_log_puk.pem

    ## TP Device connection settings

    # The examples of configuration of TP device
    tp_device: scard

    # The example of specifying configuration for TP device
    tp_device_parameter:
        id: 105276681024525924

    ## TP Target connection settings

    # The examples of configuration of TP target
    tp_target: blhost

    # The example of specifying configuration for TP target
    tp_target_parameter:
        buffer_address: 0x2000_4000
        blhost_timeout: 5_000
        blhost_port: "com10"
        blhost_baudrate: 921600

    # Timeout configuration in seconds
    timeout: 60

Path to the provisioning firmware is optional parameter, if not specified, FW must be loaded (using *blhost receive-sb-file*) before using the tphost load. *audit_log* is a path to the audit log, that will be described later.

The same rules applies for the TP device parameters as described in the *tpconfig* section. TP target is specified in the *tp_target_parameter* section. In the SPSDK version 1.6.0 only UART interface is supported for the trust provisioning, so *blhost_port* -- UART port has to be specified. The *buffer_address* is a specified shared memory area in the trust provisioning firmware that is used for the UART communication, it should be provided by the NXP.

When the configuration is filled up, we are ready to provision the target device using the *load* subcommand. Tphost takes care of the whole trust provisioning process.

.. code:: bash

    tphost load -c <config_path.yaml>

---------
Audit log
---------

Audit log contains record for the each provisioned target, it is used for verification of the production quota. Audit log is a simple encrypted SQLite database. Audit log also contains OEM x509 devattest certificates and NXP devattest certificates which could be extracted.

Verification of the audit log integrity and certificate extraction is done using the *tphost verify* subcommand.

.. code:: bash

    tphost verify -l <audit_log.db> -k <audit_log_key.pem> -d <directory_for_export>

.. note::

    Audit log verification is optimized for the best performance. You can specify the number of jobs to be run in parallel using -j option.

----------------------
Command line interface
----------------------

.. click:: spsdk.apps.tphost:main
    :prog: tphost
    :nested: full


.. click:: spsdk.apps.tpconfig:main
    :prog: tpconfig
    :nested: full
