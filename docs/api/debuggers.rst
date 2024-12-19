Debuggers API
===============

Debuggers module provides wrappers for various types of debuggers.


Module for DebugMailbox Debug probes support
-----------------------------------------------
.. automodule:: spsdk.debuggers.debug_probe
   :members:
   :special-members: DebugProbe
   :undoc-members:
   :show-inheritance:


Module with common utils for debuggers module
----------------------------------------------
.. automodule:: spsdk.debuggers.utils
   :members:
   :undoc-members:
   :show-inheritance:

Additional debuggers
--------------------

SPSDK does have a plugin system in place to support additional debuggers.
There are couple of plugins provided by NXP which you may find here: https://github.com/nxp-mcuxpresso/spsdk_plugins

If you want to add support for a different debugger, you may create a Python module by using Cookiecutter template in examples/plugins/templates/cookiecutter-spsdk-debug-probe-plugin.zip
