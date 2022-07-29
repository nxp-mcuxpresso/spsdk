=====================
User Guide - nxpimage
=====================

This user guide describes how to use *nxpimage* application. *nxpimage* is a tool for generating TrustZone,
Master Boot Image and Secure Binary images. This tool is successor of obsolete *elftosb* application. The motivation to
replace *elftosb* is bring clear and more usable user interface to application that is used to create various kind
of NXP images. To keep backward compatibility as much as possible the configuration files has been kept as is.

For more information about the supported binary images and how to configure them visit page
:ref:`Supported binary images`

----------------------
Command line interface
----------------------

.. click:: spsdk.apps.nxpimage:main
    :prog: nxpimage
    :nested: full
