MBoot Module
============

This is a user guide for `mboot` module API.

## MBoot: Basic usage

* Import `mboot` module from `spsdk`
* Use `mboot.MbootUSBInterface.scan()` class method for getting list of connected devices
* Select single device from all connected and create `McuBoot` instance over this device
* Start with open connection and finish with close connection

```python
from spsdk import mboot

interfaces = mboot.MbootUSBInterface.scan()
if interfaces:
    mb = mboot.McuBoot(interfaces[0])
    mb.open()
    # read 1000 bytes from address 0
    data = mb.read_memory(0, 1000)
    if data is None:
        print(mboot.mcuboot.StatusCode.desc(mb.status_code, f"Unknown Error: 0x{mb.status_code:08X}"))
        mb.close()
        exit()
    # your code
    mb.close()
```

## MBoot: Skipping open/close call

`McuBoot` class is supporting `with` statement what can make the code cleaner and much more readable.

```python
from spsdk import mboot

interfaces = mboot.MbootUSBInterface.scan()
if interfaces:
    with mboot.McuBoot(interfaces[0]) as mb:
        # read 1000 bytes from address 0
        data = mb.read_memory(0, 1000)
        if data is None:
            print(mboot.mcuboot.StatusCode.desc(mb.status_code, f"Unknown Error: 0x{mb.status_code:08X}"))
            exit()
        # your code
```

## MBoot: Propagating command error as exception

By default is command error propagated by return value which must be processed individually for every command. In many
use-cases is code execution interrupted if any command finish with error. Therefore you have the option to enable the
exception also for command error.

```python
from spsdk import mboot

interfaces = mboot.MbootUSBInterface.scan()
if interfaces:
    try:
        with mboot.McuBoot(interfaces[0], True) as mb:
            # read 1000 bytes from address 0
            data = mb.read_memory(0, 1000)
            # your code
    except mboot.mcuboot.McuBootError as e:
        print(str(e))
```

## MBoot: Logger

MBoot module implement a logging functionality for intuitive debugging of communication interfaces. All what you need
to do is just add line `import logging` into your code and set logging level to `DEBUG` or `INFO` with line
`logging.basicConfig(level=logging.DEBUG)`

```python
from spsdk import mboot
import logging

logging.basicConfig(level=logging.DEBUG)
```

**Terminal output example with logging:**

```text
INFO:MBOOT:Connect: USB COMPOSITE DEVICE (0x15A2, 0x0073)
DEBUG:MBOOT:USB:Open Interface
INFO:MBOOT:TX-CMD: ReadMemory(address=0x00000000, length=100, mem_id=0)
DEBUG:MBOOT:TX-PACKET: Tag=ReadMemory, Flags=0x00, p0=0x00000000, p1=0x00000064, p2=0x00000000
DEBUG:MBOOT:USB:OUT[1021]: 01, 00, 20, 00, 03, 00, 00, 03, 00, 00, 00, 00, 64, 00, 00, 00, 00, ...
DEBUG:MBOOT:USB:IN [1021]: 03, 00, 0C, 00, A3, 01, 00, 02, 00, 00, 00, 00, 64, 00, 00, 00, 00, ...
INFO:MBOOT:RX-PACKET: Tag=ReadMemoryResponse, Status=Success, Length=100
DEBUG:MBOOT:USB:IN [1021]: 04, 00, 64, 00, CC, BF, 19, 63, 4B, 69, 48, B3, E1, AF, E6, 79, 72, ...
DEBUG:MBOOT:USB:IN [1021]: 03, 00, 0C, 00, A0, 00, 00, 02, 00, 00, 00, 00, 03, 00, 00, 00, 72, ...
DEBUG:MBOOT:RX-DATA: Tag=GenericResponse, Status=Success, Cmd=ReadMemory
INFO:MBOOT:RX-DATA: Successfully Received 100/100 Bytes
DEBUG:MBOOT:USB:Close Interface
```
