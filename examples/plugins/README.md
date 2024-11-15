# Plugins

SPSDK allows user to install additional plugins and integrate them with SPSDK functionality. They allow to extend the normal SPSDK functionality with additional features.

## SPSDK 2.2 changes

Due to increasingly complex codebase it was decided to move some functionality into plugins. This allows to keep the core SPSDK codebase clean and focused on the main functionality. 
The repository containing the plugins is located at: [https://github.com/nxp-mcuxpresso/spsdk_plugins](https://github.com/nxp-mcuxpresso/spsdk_plugins)
Plugins are also released on PyPi.

Affected functionality is the following:
- J-Link debug probe support (using the PyLink library), installable via `pip install spsdk-jlink`
- PE Micro debug probe support, installable via `pip install spsdk-pemicro`
- Added support for Lauterbach debug probe, installable via `pip install spsdk-lauterbach`

J-Link and PE Micro over PyOCD is kept in the base SPSDK installation.

## Supported plugin types

The table bellow shows the list of support plugin types with associated package entrypoints, cookiecutter templates and base class they are derived from.

| Plugin                 | Entrypoint             | Template name                                  | Base class                                    |
|:-----------------------|:-----------------------|:-----------------------------------------------|-----------------------------------------------|
| Signature Provider     | spsdk.sp               | cookiecutter-spsdk-sp-plugin.zip               | spsdk.crypto.signature_provider.SignatureProvider                |
| Mboot Device Interface | spsdk.device.interface | cookiecutter-spsdk-device-interface-plugin.zip | spsdk.mboot.protocol.base.MbootProtocolBase   |
| SDP Device Interface   | spsdk.device.interface | cookiecutter-spsdk-device-interface-plugin.zip | spsdk.sdp.protocol.base.SDPProtocolBase       |
| WPC Service            | spsdk.wpc.service      | cookiecutter-spsdk-wpc-service-plugin.zip      | spsdk.wpc.utils.WPCCertificateService         |
| Debug probe            | spsdk.debug_probe      | cookiecutter-spsdk-debug-probe-plugin.zip      | spsdk.debuggers.debug_probe.DebugProbeCoreSightOnly      |      


## Plugin implementation

There are basically two ways how a plugin can be implemented.

- A Python package installed in the environment (preferred)
- A single Python module with the plugin implementation in it

The actual implementation depends on actual plugin type. 
In general every plugin must be derived from the plugin base class and implement it's methods.

### Plugin as a Python package
All the plugins installed in the Python environment will be discovered automatically.
The only requirement for package is to add specific entrypoint metadata into the package.

You can find the list of plugin entrypoints based on the plugin type in the table above.

In order to make the implementation of the plugins easier, a cookiecutter template can be used.
You can find all the cookiecutter templates in the `/templates` folder.

The instructions for generating plugin package from cookiecutter template:
- Install cookiecutter: `pip install cookiecutter`
- Create plugin: `cookiecutter <spsdk_root>/examples/plugins/templates/<plugin_template>.zip`
- Follow the instructions in the command prompt
- A new plugin package is created in current folder
- Install plugin: `pip install <my_project_path>` (for development use `-e/--editable` flag)

### Plugin as a single Python module
In some situations the installation into the Python environment is not possible.
For such scenarios a plugin as a single Python module can be implemented.
In this case the plugin is not loaded automatically. 
The plugin will be loaded if the `--plugin <path_to_py_file>` option is used in SPSDK application command.
