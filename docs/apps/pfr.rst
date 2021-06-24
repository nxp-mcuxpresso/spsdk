================
User Guide - pfr
================

This user’s guide describes how to use *pfr* application.

.. click:: spsdk.apps.pfr:main
    :prog: pfr
    :nested: none

------------------
pfr - Sub-commands
------------------

*pfr* consist of a set of sub-commands followed by options and arguments.
The options and the sub-command are separated with a ‘--’.

.. code:: bash

    pfr [options] -- [sub-command]

The "help" guide of *pfr* lists all of the options and sub-commands supported by the *pfr* utility.

.. code:: bash

    pfr --help

.. click:: spsdk.apps.pfr:devices
    :prog: pfr devices
    :nested: full

.. click:: spsdk.apps.pfr:generate
    :prog: pfr generate
    :nested: full

.. click:: spsdk.apps.pfr:generate_binary
    :prog: pfr generate-binary
    :nested: full

.. click:: spsdk.apps.pfr:get_cfg_template
    :prog: pfr get-cfg-template
    :nested: full

.. click:: spsdk.apps.pfr:info
    :prog: pfr info
    :nested: full

.. click:: spsdk.apps.pfr:parse
    :prog: pfr parse
    :nested: full

.. click:: spsdk.apps.pfr:parse_binary
    :prog: pfr parse-binary
    :nested: full

.. click:: spsdk.apps.pfr:user_config
    :prog: pfr user-config
    :nested: full
