===================
User Guide - nxpele
===================

This user guide describes how to use *nxpele* application. *nxpele* is a tool to communicate with
EdgeLock Enclave hardware on target where is used(like i.MXRT118x). The tool is build up on *blhost*
commands (write-memory, read-memory and ele-message), so it contains standard *blhost* options to establish connection
with ISP mboot.

.. table:: NXP EdgeLock Enclave - available commands/messages
    :align: left

    ======== ================================
    1        ele-fw-auth
    2        generate-keyblob
    2.a      - DEK
    2.b      - IEE
    2.c      - OTFAD
    3        get-ele-fw-status
    4        get-ele-fw-version
    5        get-info
    6        ping
    7        release-container
    8        signed-message
    9        start-trng
    ======== ================================

----------------------
Command line interface
----------------------

.. click:: spsdk.apps.nxpele:main
    :prog: nxpele
    :nested: full
