================
EdgeLock2GO
================

EdgeLock2GO Remote Trust Provisioning (RTP)
-------------------------------------------

Term Trust Provisioning (TP) covers injecting confidential assets into the target.
Remote Trust Provisioning (RTP) allows to securely store the assets in a remote server and then transfer them to the target.
EdgeLock2GO handles multiple types of assets (Secure Objects) like symmetric keys, asymmetric keys, certificates, etc.

For more details please check `EdgeLock2GO documentation <https://edgelock2go.com/documentation>`_

Following Jupyter Notebooks showcase using EdgeLock2GO RTP

To run the Jupyter Notebooks please make sure you have:

* EdgeLock2GO account and API token
* Device Group with Secure Objects attached to it
* NXP EL2GO Provisioning Firmware for your board


.. toctree::
    :maxdepth: 1

    mcxn947/mcxn947_single_shot
    mcxn947/mcxn947_split_command
