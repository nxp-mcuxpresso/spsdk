SDP Module
==========

This is a user guide for `sdp` module API.

## SDP: Basic usage

* Import `sdp` module from `spsdk`
* Use `sdp.scan_usb()` function for getting list of connected devices  
* Select single device from all connected and create `SDP` instance over this device
* Start with open connection and finish with close connection

```python
from spsdk import sdp

devices = sdp.scan_usb()
if devices:
    sd = sdp.SDP(devices[0])
    sd.open()
    # read 1000 bytes from address 0
    data = sd.read(0, 1000)
    if data is None:
        print(sdp.StatusCode.desc(sd.status_code, f"Unknown Error: 0x{sd.status_code:08X}"))
        sd.close()
        exit()
    # your code
    sd.close()
```

## SDP: Skipping open/close call  

`SDP` class is supporting `with` statement what can make the code cleaner and much more readable.

```python
from spsdk import sdp

devices = sdp.scan_usb()
if devices:
    with sdp.SDP(devices[0]) as sd:
        # read 1000 bytes from address 0
        data = sd.read(0, 1000)
        if data is None:
            print(sdp.StatusCode.desc(sd.status_code, f"Unknown Error: 0x{sd.status_code:08X}"))
            exit()
        # your code
```

## SDP: Propagating command error as exception

By default is command error propagated by return value which must be processed individually for every command. In many 
use-cases is code execution interrupted if any command finish with error. Therefore you have the option to enable the 
exception also for command error.

```python
from spsdk import sdp

devices = sdp.scan_usb()
if devices:
    try:
        with sdp.SDP(devices[0], True) as sd:
            # read 1000 bytes from address 0
            data = sd.read(0, 1000)
            # your code
    except sdp.SdpError as e:
        print(str(e))
```

## SDP: Logger

SDP module implement a logging functionality for intuitive debugging of communication interfaces. All what you need 
to do is just add line `import logging` into your code and set logging level to `DEBUG` or `INFO` with line 
`logging.basicConfig(level=logging.DEBUG)`

```python
from spsdk import sdp
import logging

logging.basicConfig(level=logging.DEBUG)
```

**Terminal output example with logging:**

```text
INFO:SDP:Connect: SE Blank PELE (0x15A2, 0x0071)
DEBUG:SDP:USB:Open Interface
INFO:SDP:TX-CMD: Read(address=0x00000000, length=100, format=8)
DEBUG:SDP:TX-PACKET: Tag=ReadRegister, Address=0x0000, Format=8, Count=100, Value=0x00000000
DEBUG:SDP:USB:OUT[1025]: 01, 01, 01, 00, 00, 00, 00, 08, 00, 00, 00, 64, 00, 00, 00, 00, 00, 00, ...
DEBUG:SDP:USB:IN [65]: 03, 56, 78, 78, 56, 00, 01, 00, F0, 7F, 30, C4, F8, 00, 01, 50, 69, 20, ...
INFO:SDP:RX-PACKET: Response: UNLOCKED
DEBUG:SDP:USB:IN [65]: 04, 1C, F0, 9F, E5, 1C, F0, 9F, E5, 1C, F0, 9F, E5, 1C, F0, 9F, E5, 1C, ...
DEBUG:SDP:USB:IN [65]: 04, D4, FF, 91, 00, D8, FF, 91, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, ...
DEBUG:SDP:USB:Close Interface
```
