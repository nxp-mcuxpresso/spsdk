## Logger

SPSDK implements a comprehensive logging functionality for intuitive debugging of communication interfaces. 

### Quick Start

All you need to do is add `import logging` into your code and set the logging level with `logging.basicConfig(level=logging.DEBUG)`:

#### Basic Usage

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

### Log Levels

SPSDK supports all standard Python logging levels plus a custom **TRACE** level for ultra-detailed protocol logging:

| Level | Value | Purpose |
|-------|-------|---------|
| **TRACE** | 5 | Byte-level data, hex dumps, raw protocol packets (lowest) |
| **DEBUG** | 10 | Diagnostic information and protocol details |
| **INFO** | 20 | General informational messages |
| **WARNING** | 30 | Warning messages |
| **ERROR** | 40 | Error messages |
| **CRITICAL** | 50 | Critical errors (highest) |
### Using SPSDK Logger with TRACE Level

For low-level protocol debugging, use SPSDK's `get_logger()` function which provides native TRACE level support:
```python
from spsdk import get_logger, SPSDK_LOG_LEVEL_TRACE
import logging

# Create a logger with TRACE support
logger = get_logger(__name__)

# Configure to show TRACE level
logging.basicConfig(level=SPSDK_LOG_LEVEL_TRACE)

# Use all log levels
logger.trace("Ultra-detailed protocol data")  # Level 5
logger.debug("Debug information")              # Level 10
logger.info("Informational message")           # Level 20
```
### Advanced Configuration (Build Servers)

For build servers or complex logging scenarios, use `configure_logging()` with a dictionary configuration:
```python
from spsdk import configure_logging, SPSDK_LOG_LEVEL_TRACE
import logging

config = {
    "version": 1,
    "disable_existing_loggers": False,
    "formatters": {
        "detailed": {
            "format": "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
        }
    },
    "handlers": {
        "console": {
            "class": "logging.StreamHandler",
            "formatter": "detailed",
            "level": SPSDK_LOG_LEVEL_TRACE,
        },
        "file": {
            "class": "logging.FileHandler",
            "filename": "spsdk.log",
            "formatter": "detailed",
            "level": SPSDK_LOG_LEVEL_TRACE,
        }
    },
    "loggers": {
        "spsdk": {
            "level": SPSDK_LOG_LEVEL_TRACE,
            "handlers": ["console", "file"],
        }
    }
}

# Configure logging with TRACE level support
configure_logging(config)

# All spsdk loggers now have TRACE support
from spsdk import get_logger
logger = get_logger("spsdk.mymodule")
logger.trace("This will be logged to console and file!")
```
### Recommended Log Levels

- **Development**: `TRACE` (5) – See all protocol communication
- **Testing**: `DEBUG` (10) – Diagnostic info without packet dumps
- **CI/Build Servers**: `DEBUG` or `INFO` (10-20) – Balance detail and performance
- **Production**: `WARNING` or `ERROR` (30-40) – Only important messages