WPC Provisioning API
====================

WPC provisioning consists of two major parts:

* Service adapter
* Target adapter

Service adapter's responsibility is to provide WPC Certificate chain.
Target adapter is then responsible to injecting said chain into the target.

Out-of-the-box SPSDK provides one :ref:`Service adapter using EL2GO <WPC Service adapter using EL2GO>` and one :ref:`Target adapter using MBoot/BLhost <WPC Target adapter using MBoot>`.


WPC Service adapter using EL2GO
-------------------------------

.. autoclass:: spsdk.wpc.service_el2go.WPCCertificateServiceEL2GO
    :members:
    :undoc-members:
    :show-inheritance:


WPC Target adapter using MBoot
------------------------------

.. autoclass:: spsdk.wpc.target_mboot.WPCTargetMBoot
    :members:
    :undoc-members:
    :show-inheritance:


Creating your own WPC Service/Target adapters
---------------------------------------------

To create your own Service adapter, create new class derived from :class:`~spsdk.wpc.wpc.WPCCertificateService`.
To create your own Target adapter, create new class derived from :class:`~spsdk.wpc.wpc.WPCTarget`.

Service is responsible to provide WPC Certificate Chain as :class:`~spsdk.wpc.wpc.WPCCertChain` via :meth:`~spsdk.wpc.wpc.WPCCertificateService.get_wpc_cert`.
Target adapters then injects said certificate chain into the target using :meth:`~spsdk.wpc.wpc.WPCTarget.wpc_insert_cert`.

Both :class:`~spsdk.wpc.wpc.WPCCertificateService` and :class:`~spsdk.wpc.wpc.WPCTarget` base-classes are using common approach regarding regarding instantiation via configuration data defined in :class:`~spsdk.wpc.wpc.BaseWPCClass`.
Each derived class should implement :meth:`~spsdk.wpc.wpc.BaseWPCClass.s`. This method should return a JSON validation schema which is used for both configuration template creation and validating configuration data specific for each class.
Derived class can be then instantiated via :meth:`~spsdk.wpc.wpc.BaseWPCClass.load_from_config` Method validates configuration data and passes the data into the `__init__` method

To see a practical example on how to create your own Service, please see :ref:`Creating a custom WPC Service adapter`

.. autoclass:: spsdk.wpc.wpc.WPCCertificateService
    :members:
    :undoc-members:
    :show-inheritance:

.. autoclass:: spsdk.wpc.wpc.WPCTarget
    :members:
    :undoc-members:
    :show-inheritance:

.. autoclass:: spsdk.wpc.wpc.BaseWPCClass
    :members:
    :undoc-members:
    :show-inheritance:

.. autoclass:: spsdk.wpc.wpc.WPCCertChain
    :members:
    :undoc-members:
    :show-inheritance:
    :member-order: bysource




