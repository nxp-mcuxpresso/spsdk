Image Module
============

This is a user guide for `image` module API. This module is covering all functionality about i.MX boot image creation,
validation and extraction.

## Device Configuration Data (DCD)

```python
from spsdk.image.segments import SegDCD
from spsdk.image.commands import CmdWriteData, CmdCheckData, CmdNop, EnumWriteOps,EnumCheckOps

dcd = SegDCD(enabled=True)
dcd.append(CmdWriteData(ops=EnumWriteOps.WRITE_VALUE, data=((0x30340004, 0x4F400005),
                                                            (0x30340004, 0x4F400005),
                                                            (0x30340004, 0x4F400005),
                                                            (0x30340004, 0x4F400005))))
dcd.append(CmdWriteData(ops=EnumWriteOps.CLEAR_BITMASK, data=((0x307900C4, 0x00000001),)))
dcd.append(CmdWriteData(ops=EnumWriteOps.SET_BITMASK, data=((0x307900C4, 0x00000001),)))
dcd.append(CmdCheckData(ops=EnumCheckOps.ALL_CLEAR, address=0x307900C4, mask=0x00000001))
dcd.append(CmdCheckData(ops=EnumCheckOps.ALL_CLEAR, address=0x307900C4, mask=0x00000001, count=5))
dcd.append(CmdCheckData(ops=EnumCheckOps.ANY_CLEAR, address=0x307900C4, mask=0x00000001))
dcd.append(CmdCheckData(ops=EnumCheckOps.ANY_CLEAR, address=0x307900C4, mask=0x00000001, count=5))
dcd.append(CmdCheckData(ops=EnumCheckOps.ALL_SET, address=0x307900C4, mask=0x00000001))
dcd.append(CmdCheckData(ops=EnumCheckOps.ALL_SET, address=0x307900C4, mask=0x00000001, count=5))
dcd.append(CmdCheckData(ops=EnumCheckOps.ANY_SET, address=0x307900C4, mask=0x00000001))
dcd.append(CmdCheckData(ops=EnumCheckOps.ANY_SET, address=0x307900C4, mask=0x00000001, count=5))
dcd.append(CmdNop())
```
