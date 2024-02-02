# NXP Secure Provisioning SDK Database
    The data folder in package contains all data that is used by SPSDK tool.

## Organization of database
  - common: Folder that contains common data as for general run of SPSDK as defaults for all devices.
  - devices: Folder with all supported devices by SPSDK. the name of folder is unique name of supported family. Each family folder must contains at least 'database.yaml' file
            with correct format.
  - jsonschemas: Folder with JSON SCHEMAS used by individual SPSDK tools. Format of file depends on each tool, some of tool is using standard JSON SCHEMA format, rest is
            contains chunks of JSON SCHEMAs organized as a big dictionary.

## Glossary
  - SPSDK_Database: The base SPSDK class to handle with database. It has Singleton behavior so it could created any time without multiplicate load of database.
  - SPSDK_Database cache: See chapter "Database caching"
  - Device: Name of the device. The exact name of the device is specified by name of the folder in 'devices' folder.
  - Revision: Revision of the device. Each device has to have at least one revision.
  - Feature: Device feature. By feature is organized the whole database to support individual tools. Example of features: mbi (Master BOot Image), tp (Trust Provisioning) etc. The whole list contains the SPSDK_Database class.


## Device data composition
    The device data for the using by SPSDK are organized by family chip revisions, the database method 'get_device_features()' is designed as a main way to get data from database.

### Mandatory fields in device 'database.yaml' for fully defined devices
  - revisions: The dictionary with all supported revisions. In case that the revision doesn't contains any changes to standard features it enough to define empty dictionary
  - latest: The name of latest revision of the device.
  - features: The dictionary with all supported features by device. The final device feature is compounded from the defaults from 'common/database_defaults.yaml' updated by information in '{device_name}/database.yaml'

Example of newly created device:
```
revisions:
  rev0: {}
  rev1:
    features:
      feature1:
        key1: override_value_for_this_revision
  rev2:
    features:
      feature1:
        key1: override_value_for_this_revision
      feature2:
        key1: override_value_for_this_revision

latest: rev2
features:
feature1:
key1: value
feature2:
key1: value
```

### Mandatory fields in device 'database.yaml' for alias defined devices
  - alias: The name of a device that is used as origin.

In aliased devices is possible to define also all definitions from 'Mandatory fields in device 'database.yaml' for fully defined devices' chapter.
To define a new revision in aliased device the key word 'alias' must be used also in newly defined revision:

Example of created a new device as a alias of existing device. In example there is also created new revision.
```
alias: origin_device
revisions:
  new_rev:
    alias: origin_device_revision
  features:
    feature1:
      key1: override_value_for_this_revision

latest: new_rev
```

### Steps to create final revision
The SPSDK database flow to get the final data for requested revision.

**The code without alias devices do following steps:**
1. Load device features
2. Load default features
3. For all defined device features do following:
    1. Get default feature values
    2. Updated default feature values by device feature values
4. For all defined device revisions update gotten feature data by revision updates

Here is example of simple data to show creating of final revision data

**Default database file => common/default_database.yaml**
```
revisions: {}
latest: latest

features:
  feature1:
    key1: value_default
  feature2:
    key1: value_default
  feature3: {}


**Device 1 database file => devices/device1/database.yaml**
```
revisions:
  rev1: {}
  rev2:
    features:
      feature1:
        key2: rev2_value
latest: rev2

features:
  feature1:
    key2: value
```

**Device 2 database file => devices/device2/database.yaml**
```
revisions:
  rev1:
    features:
      feature1:
        key1: rev1_value
latest: rev1

features:
  feature1:
    key1: value
  feature2: {}
```

---
---
**The final revisions data for device 1:**
```
rev1:
  features:
    feature1:
      key1: value_default
      key2: value
rev2:
  features:
    feature1:
      key1: value_default
      key2: rev2_value
```

**The final revisions data for device 2:**
```
rev1:
  features:
    feature1:
      key1: rev1_value
    feature2:
      key1: value_default
```

---
---
**The code with alias device do following steps:**
1. Load origin device
2. Load device features
3. If the device features are present, all origin revision are updated by them
4. If the device revisions are present, update the revision data from step 3 by them
5. If there is a new revision defined (must contains alias key), then is copied from aliased revision and update by possible new revision values
6. If a new latest revision field is available, also this one is updated

**Here is example of new aliased device from previous data with new created revision:**
```
alias: device1

revisions:
  new_rev:
    alias: rev2
    features:
      feature1:
        key2: new_rev_value
latest: new_rev
```
**The final revisions data for new aliased device:**
```
rev1:
  features:
    feature1:
      key1: value_default
      key2: value
rev2:
  features:
    feature1:
      key1: value_default
      key2: rev2_value
new_rev:
  features:
    feature1:
      key1: value_default
      key2: new_rev_value
```

### Revision data access in code
The revision class contains few basic methods to get data from database including type hints and type validation.
Each "get_" has two mandatory parameters:
- feature: Name of the feature to be data gets from
- key: What is union of simple string key or list of strings that is used as a path to get into nested values

**List of supported "get_" methods:**
- get_value: Get general value without type checking
- get_bool: Get boolean
- get_int: Get integer
- get_str: Get string
- get_dict: Get dictionary
- get_list: Get list
- get_file_path: Get file path. Path is relative to device folder. In case of aliased device and non existing file in device folder,
                it automatically used device path of aliased device. The method also check if the file exists.

Ech

## Database caching
By default the SPSDK database is cached on local machine to get better performance on load. The cache is independent for each SPSDK instance on machine.
There is also invented invalidation mechanism to detect changes in original data and update the cache. If needed, the cache could be disabled by environment
variable "SPSDK_CACHE_DISABLED_{version}" set to True.

In the database itself is also simple cache for opened configuration files to avoid loading them multiply during application run. The content of that runtime
configuration files is also checked at exit of SPSDK and the main cache is updated if there is some new files.


