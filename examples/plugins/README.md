# Plugins

SPSDK allows user to install additional plugins and integrate them with SPSDK functionality. They allow uset ot extend the normal SPSDK funtionality with additional features.

## Supported plugin types

The table bellow shows the list of support plugin types with associated package entrypoints, cokiecutter templates and base class they are derived from.

| Plugin                 | Entrypoint             | Template name                                  | Base class                                    |
|:-----------------------|:-----------------------|:-----------------------------------------------|-----------------------------------------------|
| Signature Provider     | spsdk.sp               | cookiecutter-spsdk-sp-plugin.zip               | spsdk.crypto.SignatureProvider                |
| Mboot Device Interface | spsdk.device.interface | cookiecutter-spsdk-device-interface-plugin.zip | spsdk.mboot.protocol.base.MbootProtocolBase   |
| SDP Device Interface   | spsdk.device.interface | cookiecutter-spsdk-device-interface-plugin.zip | spsdk.sdp.protocol.base.SDPProtocolBase       |

## Plugin implementation

There are basically two ways how a plugin can be implemented.

- A Python package installed in the environment (preffered)
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
- Unzip plugin template: `plugins/<plugin_template>.zip`
- Install cookiecutter: `pip install cookiecutter`
- Create plugin: `cookiecutter <unzipped_template_dir>`
- Follow the instructions in the command prompt
- A new plugin package is cretaed

### Plugin as a single Python module
In some situations the installation into the Python environment is not possible.
For such scenarios a plugin as a single Python module can be implemented.
In this case the plugin is not loaded automatically. 
The plugin will be loaded if the `--plugin <path_to_py_file>` option is used in SPSDK application command.
