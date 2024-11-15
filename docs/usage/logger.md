## Logger

SPSDK implements a logging functionality for intuitive debugging of communication interfaces. All what you need
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
