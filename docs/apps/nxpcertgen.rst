=======================
User Guide - nxpcertgen
=======================

This user’s guide describes how to use *nxpcertgen* application.

.. click:: spsdk.apps.nxpcertgen:main
    :prog: nxpcertgen
    :nested: full

-------------------------
nxpcertgen - Sub-commands
-------------------------

*nxpcertgen* consist of a set of sub-commands followed by options and arguments.
The options and the sub-command are separated with a ‘--’.

.. code:: bash

    nxpcertgen [options] -- [sub-command]

The "help" guide of *nxpcertgen* lists all of the options and sub-commands supported by the *nxpcertgen* utility.

.. code:: bash

    nxpcertgen --help

.. click:: spsdk.apps.nxpcertgen:generate
    :prog: nxpcertgen generate
    :nested: full

.. click:: spsdk.apps.nxpcertgen:get_cfg_template
    :prog: nxpcertgen get-cfg-template
    :nested: full
