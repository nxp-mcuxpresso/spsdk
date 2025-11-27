#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2016-2018 Martin Olejar
# Copyright 2019-2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""SPSDK MBOOT protocol commands and responses implementation.

This module provides comprehensive support for MBOOT (MCU Bootloader) protocol
communication, including command packets, response parsing, and protocol-specific
operations for secure provisioning and device management.
"""

from struct import pack, unpack, unpack_from
from typing import Optional, Type

from typing_extensions import Self

from spsdk.mboot.error_codes import StatusCode
from spsdk.mboot.exceptions import McuBootError
from spsdk.utils.interfaces.commands import CmdPacketBase, CmdResponseBase
from spsdk.utils.spsdk_enum import SpsdkEnum

########################################################################################################################
# McuBoot Commands and Responses Tags
########################################################################################################################

# fmt: off
class CommandTag(SpsdkEnum):
    """McuBoot command enumeration for bootloader operations.
    
    This enumeration defines all available commands that can be sent to NXP MCU bootloaders
    through the McuBoot protocol. Each command includes a numeric identifier, string name,
    and human-readable description for various memory operations, security functions,
    and device configuration tasks.
    """

    NO_COMMAND                  = (0x00, "NoCommand", "No Command")
    FLASH_ERASE_ALL             = (0x01, "FlashEraseAll", "Erase Complete Flash")
    FLASH_ERASE_REGION          = (0x02, "FlashEraseRegion", "Erase Flash Region")
    READ_MEMORY                 = (0x03, "ReadMemory", "Read Memory")
    WRITE_MEMORY                = (0x04, "WriteMemory", "Write Memory")
    FILL_MEMORY                 = (0x05, "FillMemory", "Fill Memory")
    FLASH_SECURITY_DISABLE      = (0x06, "FlashSecurityDisable", "Disable Flash Security")
    GET_PROPERTY                = (0x07, "GetProperty", "Get Property")
    RECEIVE_SB_FILE             = (0x08, "ReceiveSBFile", "Receive SB File")
    EXECUTE                     = (0x09, "Execute", "Execute")
    CALL                        = (0x0A, "Call", "Call")
    RESET                       = (0x0B, "Reset", "Reset MCU")
    SET_PROPERTY                = (0x0C, "SetProperty", "Set Property")
    FLASH_ERASE_ALL_UNSECURE    = (0x0D, "FlashEraseAllUnsecure", "Erase Complete Flash and Unlock")
    FLASH_PROGRAM_ONCE          = (0x0E, "FlashProgramOnce", "Flash Program Once")
    FLASH_READ_ONCE             = (0x0F, "FlashReadOnce", "Flash Read Once")
    FLASH_READ_RESOURCE         = (0x10, "FlashReadResource", "Flash Read Resource")
    CONFIGURE_MEMORY            = (0x11, "ConfigureMemory", "Configure Quad-SPI Memory")
    RELIABLE_UPDATE             = (0x12, "ReliableUpdate", "Reliable Update")
    GENERATE_KEY_BLOB           = (0x13, "GenerateKeyBlob", "Generate Key Blob")
    FUSE_PROGRAM                = (0x14, "ProgramFuse", "Program Fuse")
    KEY_PROVISIONING            = (0x15, "KeyProvisioning", "Key Provisioning")
    TRUST_PROVISIONING          = (0x16, "TrustProvisioning", "Trust Provisioning")
    FUSE_READ                   = (0x17, "ReadFuse", "Read Fuse")
    UPDATE_LIFE_CYCLE           = (0x18, "UpdateLifeCycle", "Update Life Cycle")
    ELE_MESSAGE                 = (0x19, "EleMessage", "Send EdgeLock Enclave Message")
    EL2GO                       = (0x20, "EL2GO", "EL2GO Provisioning Commands and API Calls")

    # reserved commands
    CONFIGURE_I2C = (0xC1, "ConfigureI2c", "Configure I2C")
    CONFIGURE_SPI = (0xC2, "ConfigureSpi", "Configure SPI")
    CONFIGURE_CAN = (0xC3, "ConfigureCan", "Configure CAN")



class CommandFlag(SpsdkEnum):
    """McuBoot command flags enumeration.
    
    This enumeration defines flags that can be applied to McuBoot commands to specify
    their behavior and characteristics, such as whether a command includes a data phase.
    """

    NONE           = (0, "NoFlags", "No flags specified")
    HAS_DATA_PHASE = (1, "DataPhase", "Command has a data phase")



class ResponseTag(SpsdkEnum):
    """McuBoot response tag enumeration.
    
    This enumeration defines response tags used by McuBoot protocol to identify different types
    of responses returned by the target device. Each tag corresponds to a specific command
    response type with associated metadata including tag value, name, and description.
    """

    GENERIC                     = (0xA0, "GenericResponse", "Generic Response")
    READ_MEMORY                 = (0xA3, "ReadMemoryResponse", "Read Memory Response")
    GET_PROPERTY                = (0xA7, "GetPropertyResponse", "Get Property Response")
    FLASH_READ_ONCE             = (0xAF, "FlashReadOnceResponse", "Flash Read Once Response")
    FLASH_READ_RESOURCE         = (0xB0, "FlashReadResourceResponse", "Flash Read Resource Response")
    KEY_BLOB_RESPONSE           = (0xB3, "CreateKeyBlobResponse", "Create Key Blob")
    KEY_PROVISIONING_RESPONSE   = (0xB5, "KeyProvisioningResponse", "Key Provisioning Response")
    TRUST_PROVISIONING_RESPONSE = (0xB6, "TrustProvisioningResponse", "Trust Provisioning Response")


class KeyProvOperation(SpsdkEnum):
    """Key provisioning operation type enumeration.
    
    This enumeration defines the available operations for key provisioning
    in SPSDK, including enrollment, key management, and storage operations.
    """

    ENROLL              = (0, "Enroll", "Enroll Operation")
    SET_USER_KEY        = (1, "SetUserKey", "Set User Key Operation")
    SET_INTRINSIC_KEY   = (2, "SetIntrinsicKey", "Set Intrinsic Key Operation")
    WRITE_NON_VOLATILE  = (3, "WriteNonVolatile", "Write Non Volatile Operation")
    READ_NON_VOLATILE   = (4, "ReadNonVolatile", "Read Non Volatile Operation")
    WRITE_KEY_STORE     = (5, "WriteKeyStore", "Write Key Store Operation")
    READ_KEY_STORE      = (6, "ReadKeyStore", "Read Key Store Operation")


class KeyProvUserKeyType(SpsdkEnum):
    """Enumeration of supported user keys in PUF for key provisioning operations.
    
    This enumeration defines the various types of cryptographic keys that can be
    provisioned and managed through the Physical Unclonable Function (PUF). The
    availability of specific key types depends on the target SoC capabilities.
    """

    OTFADKEK        = (2, "OTFADKEK", "Key for OTFAD encryption")
    SBKEK           = (3, "SBKEK", "Key for SB file encryption")
    PRINCE_REGION_0 = (7, "PRINCE0", "Key for Prince region 0")
    PRINCE_REGION_1 = (8, "PRINCE1", "Key for Prince region 1")
    PRINCE_REGION_2 = (9, "PRINCE2", "Key for Prince region 2")
    PRINCE_REGION_3 = (10, "PRINCE3", "Key for Prince region 3")

    USERKEK         = (11, "USERKEK", "Encrypted boot image key")
    UDS             = (12, "UDS", "Universal Device Secret for DICE")


class GenerateKeyBlobSelect(SpsdkEnum):
    """Key selector enumeration for generate-key-blob operations.
    
    Defines available key sources for key blob generation on NXP devices.
    For devices with SNVS (Secure Non-Volatile Storage), supports OTPMK from
    FUSE/OTP, ZMK from SNVS, and CMK from SNVS. For devices without SNVS,
    the key selector is ignored and default behavior applies.
    """

    OPTMK   = (0, "OPTMK", "OTPMK from FUSE or OTP(default)")
    ZMK     = (2, "ZMK", "ZMK from SNVS")
    CMK     = (3, "CMK", "CMK from SNVS")


class TrustProvOperation(SpsdkEnum):
    """Trust Provisioning operation enumeration.
    
    This enumeration defines all supported operations for the Trust Provisioning flow,
    including genuinity proving, wrapped data processing, key management, and DICE
    certificate operations for secure device provisioning.
    """

    PROVE_GENUINITY = (0xF4, "ProveGenuinity", "Start the proving genuinity process")
    PROVE_GENUINITY_HYBRID = (0xF5, "ProveGenuinityHybrid", "Start the hybrid proving genuinity process")
    ISP_SET_WRAPPED_DATA = (0xF0, "SetWrappedData", "Start processing Wrapped data")
    """Type of trust provisioning operation."""

    OEM_GEN_MASTER_SHARE        = (0, "OemGenMasterShare", "Enroll Operation")
    OEM_SET_MASTER_SHARE        = (1, "SetUserKey", "Set User Key Operation")
    OEM_GET_CUST_CERT_DICE_PUK  = (2, "GetDiceCaPuk", "Get DICE CA public key")
    HSM_GEN_KEY                 = (3, "HsmGenKey", "HSM gen key")
    HSM_STORE_KEY               = (4, "HsmStoreKey", "HSM store key")
    HSM_ENC_BLOCK               = (5, "HsmEncBlock", "HSM Enc block")
    HSM_ENC_SIGN                = (6, "HsnEncSign", "HSM enc sign")
    OEM_GET_CUST_DICE_RESPONSE  = (7, "GetDiceResponse", "Get DICE response")

class TrustProvOemKeyType(SpsdkEnum):
    """TrustProv OEM key type enumeration.
    
    This enumeration defines the various types of OEM keys used in Trust Provisioning
    operations, including manufacturing firmware signing keys, encryption keys, and
    master keys for key derivation functions.
    """

    MFWISK      = (0xC3A5, "MFWISK", "ECDSA Manufacturing Firmware Signing Key")
    ENCKEY      = (0x3CA5, "ENCKEY", "Generic Encryption Key")
    MFWENCK     = (0xA5C3, "MFWENCK", "CKDF Master Key for Manufacturing Firmware Encryption Key")
    GENSIGNK    = (0x5A3C, "GENSIGNK", "Generic ECDSA Signing Key")
    GETCUSTMKSK = (0x3C5A, "GETCUSTMKSK", "CKDF Master Key for Production Firmware Encryption Key")


class TrustProvKeyType(SpsdkEnum):
    """Trust Provisioning key type enumeration.
    
    Defines the supported key types for trust provisioning operations in SPSDK,
    including cryptographic key derivation functions, message authentication codes,
    and encryption keys.
    """

    CKDFK = (1, "CKDFK", "CKDF Master Key")
    HKDFK = (2, "HKDFK", "HKDF Master Key")
    HMACK = (3, "HMACK", "HMAC Key")
    CMACK = (4, "CMACK", "CMAC Key")
    AESK  = (5, "AESK", "AES Key")
    KUOK  = (6, "KUOK", "Key Unwrap Only Key")


class TrustProvWrappingKeyType(SpsdkEnum):
    """Trust Provisioning wrapping key type enumeration.
    
    Defines the available wrapping key types used in trust provisioning operations
    for wrapping MFG_CUST_MK_SK0_BLOB data.
    """

    INT_SK = (0x10, "INT_SK", "The wrapping key for wrapping of MFG_CUST_MK_SK0_BLOB")
    EXT_SK = (0x11, "EXT_SK", "The wrapping key for wrapping of MFG_CUST_MK_SK0_BLOB")


class TrustProvWpc(SpsdkEnum):
    """WPC trusted facility command enumeration for DSC operations.
    
    This enumeration defines the available commands for Wireless Power Consortium (WPC)
    trusted facility operations in Device Security Controller (DSC) context, including
    ID retrieval, certificate management, and certificate signing request operations.
    """

    WPC_GET_ID              = (0x5000000, "wpc_get_id", "WPC get ID")
    NXP_GET_ID              = (0x5000001, "nxp_get_id", "NXP get ID")
    WPC_INSERT_CERT         = (0x5000002, "wpc_insert_cert", "WPC insert certificate")
    WPC_SIGN_CSR            = (0x5000003, "wpc_sign_csr", "WPC sign CSR")


class TrustProvDevHsmDsc(SpsdkEnum):
    """DSC Device HSM command enumeration for Trust Provisioning.
    
    This enumeration defines the available HSM (Hardware Security Module) commands
    for DSC (Device Security Controller) operations in trust provisioning workflows.
    Each command represents a specific HSM operation with its corresponding command
    code and description.
    """

    DSC_HSM_CREATE_SESSION  = (0x6000000, "dsc_hsm_create_session", "DSC HSM create session")
    DSC_HSM_ENC_BLK         = (0x6000001, "dsc_hsm_enc_blk", "DSC HSM encrypt bulk")
    DSC_HSM_ENC_SIGN        = (0x6000002, "dsc_hsm_enc_sign", "DSC HSM sign")


class EL2GOCommandGroup(SpsdkEnum):
    """EL2GO command group enumeration for EdgeLock 2GO operations.
    
    This enumeration defines the available command groups for EdgeLock 2GO
    trust provisioning operations including version retrieval, device closure,
    and batch trust provisioning workflows.
    """

    EL2GO_GET_FW_VERSION    = (0x1, "el2go_get_version", "EL2GO Get Version")
    EL2GO_CLOSE_DEVICE      = (0x2, "el2go_close_device", "EL2GO Close Device")
    EL2GO_BATCH_TP          = (0x3, "el2go_batch_tp" , "EL2GO Batch Trust Provisioning")

# fmt: on

########################################################################################################################
# McuBoot Command and Response packet classes
########################################################################################################################


class CmdHeader:
    """McuBoot command/response header.

    This class represents the header structure for McuBoot protocol commands and responses,
    providing serialization and parsing capabilities for communication with MCU bootloader.

    :cvar SIZE: Fixed size of the header in bytes (4 bytes).
    """

    SIZE = 4

    def __init__(self, tag: int, flags: int, reserved: int, params_count: int) -> None:
        """Initialize the Command Header.

        :param tag: Tag indicating the command, see CommandTag class
        :param flags: Flags for the command
        :param reserved: Reserved field for future use
        :param params_count: Number of parameters for the command
        """
        self.tag = tag
        self.flags = flags
        self.reserved = reserved
        self.params_count = params_count

    def __eq__(self, obj: object) -> bool:
        """Check equality of two CmdHeader objects.

        Compares this CmdHeader instance with another object by checking if the other
        object is also a CmdHeader instance and has identical attributes.

        :param obj: Object to compare with this CmdHeader instance.
        :return: True if objects are equal CmdHeader instances, False otherwise.
        """
        return isinstance(obj, CmdHeader) and vars(obj) == vars(self)

    def __ne__(self, obj: object) -> bool:
        """Check if this object is not equal to another object.

        This method implements the inequality comparison operator by negating the equality check.

        :param obj: Object to compare against for inequality.
        :return: True if objects are not equal, False if they are equal.
        """
        return not self.__eq__(obj)

    def __repr__(self) -> str:
        """Return string representation of the object.

        Provides a formatted string containing the tag, flags, and parameter count
        in hexadecimal and decimal format for debugging and logging purposes.

        :return: String representation with tag, flags and parameters count.
        """
        return f"<Tag=0x{self.tag:02X}, Flags=0x{self.flags:02X}, ParamsCount={self.params_count}>"

    def __str__(self) -> str:
        """Return string representation of the command header.

        Provides a formatted string containing the tag, flags, reserved field,
        and parameter count values in a readable format.

        :return: Formatted string representation of the command header.
        """
        return (
            f"CmdHeader(tag=0x{self.tag:02X}, flags=0x{self.flags:02X}, "
            f"reserved={self.reserved}, params_count={self.params_count})"
        )

    def export(self) -> bytes:
        """Export the command header to bytes.

        Serializes the command header fields (tag, flags, reserved, params_count) into a 4-byte
        packed binary format.

        :return: Exported command header as bytes.
        """
        return pack("4B", self.tag, self.flags, self.reserved, self.params_count)

    @classmethod
    def parse(cls, data: bytes, offset: int = 0) -> Self:
        """Parse command header from binary data.

        The method extracts a 4-byte command header from the provided binary data
        at the specified offset and creates a CmdHeader object.

        :param data: Binary data containing the command header.
        :param offset: Byte offset within the data where parsing should start.
        :return: Parsed CmdHeader object.
        :raises McuBootError: Invalid data format or insufficient data length.
        """
        if len(data) < 4:
            raise McuBootError(f"Invalid format of RX packet (data length is {len(data)} bytes)")
        return cls(*unpack_from("4B", data, offset))


class CmdPacket(CmdPacketBase):
    """McuBoot command packet format class.

    Represents a command packet used in McuBoot protocol communication, handling
    command formatting, parameter management, and binary serialization for secure
    boot operations.

    :cvar SIZE: Fixed size of the command packet in bytes.
    :cvar EMPTY_VALUE: Default empty value used for padding.
    """

    SIZE = 32
    EMPTY_VALUE = 0x00

    def __init__(
        self, tag: CommandTag, flags: int, *args: int, data: Optional[bytes] = None
    ) -> None:
        """Initialize the Command Packet object.

        Creates a new command packet with the specified tag, flags, arguments, and optional data.
        The data is automatically padded to 4-byte alignment if provided.

        :param tag: Tag identifying the command type
        :param flags: Flags used by the command
        :param args: Variable number of integer arguments used by the command
        :param data: Additional binary data to append to parameters, defaults to None
        """
        self.header = CmdHeader(tag.tag, flags, 0, len(args))
        self.params = list(args)
        if data is not None:
            if len(data) % 4:
                data += b"\0" * (4 - len(data) % 4)
            self.params.extend(unpack_from(f"<{len(data) // 4}I", data))
            self.header.params_count = len(self.params)

    def __eq__(self, obj: object) -> bool:
        """Check equality between two CmdPacket objects.

        Compares this CmdPacket instance with another object by checking if the other
        object is also a CmdPacket instance and if all their attributes are equal.

        :param obj: Object to compare with this CmdPacket instance.
        :return: True if objects are equal CmdPacket instances with same attributes,
                 False otherwise.
        """
        return isinstance(obj, CmdPacket) and vars(obj) == vars(self)

    def __ne__(self, obj: object) -> bool:
        """Check if two objects are not equal.

        This method implements the inequality comparison operator by negating the equality
        comparison result.

        :param obj: Object to compare with this instance.
        :return: True if objects are not equal, False if they are equal.
        """
        return not self.__eq__(obj)

    def __str__(self) -> str:
        """Get string representation of the command object.

        Returns a formatted string containing the command tag, flags, and parameters
        in hexadecimal format for debugging and logging purposes.

        :return: Formatted string with command details including tag, flags and parameters.
        """
        tag = (
            CommandTag.get_label(self.header.tag)
            if self.header.tag in CommandTag.tags()
            else f"0x{self.header.tag:02X}"
        )
        return f"Tag={tag}, Flags=0x{self.header.flags:02X}" + "".join(
            f", P[{n}]=0x{param:08X}" for n, param in enumerate(self.params)
        )

    def export(self, padding: bool = True) -> bytes:
        """Export CmdPacket into bytes.

        The method serializes the command packet by exporting the header with updated
        parameter count, packing all parameters as unsigned integers, and optionally
        adding padding to reach the required size.

        :param padding: If True, add padding to reach the specific packet size.
        :return: Exported command packet as bytes.
        """
        self.header.params_count = len(self.params)
        data = self.header.export()
        data += pack(f"<{self.header.params_count}I", *self.params)
        if padding and len(data) < self.SIZE:
            data += bytes([self.EMPTY_VALUE] * (self.SIZE - len(data)))
        return data


class CmdResponse(CmdResponseBase):
    """McuBoot command response handler.

    This class represents a response from McuBoot commands, providing parsing and
    access to response data including status codes, headers, and raw response content.
    It handles the interpretation of binary response data and provides convenient
    access to response status and values.
    """

    def __init__(self, header: CmdHeader, raw_data: bytes) -> None:
        """Initialize the Command Response object.

        Creates a command response instance with the provided header and raw data.
        The status code is automatically extracted from the raw data.

        :param header: Header for the response
        :param raw_data: Response data containing status and payload
        """
        assert isinstance(header, CmdHeader)
        assert isinstance(raw_data, (bytes, bytearray))
        self.header = header
        self.raw_data = raw_data
        (status,) = unpack_from("<L", raw_data)
        self.status: int = status

    @property
    def value(self) -> int:
        """Get integer representation of the response.

        Unpacks the first 4 bytes of raw_data as a big-endian unsigned integer.

        :return: Integer value extracted from the response data.
        """
        return unpack_from(">I", self.raw_data)[0]

    def _get_status_label(self) -> str:
        """Get human-readable label for the status code.

        Converts the numeric status code to a descriptive string label if the status
        is recognized, otherwise returns a formatted unknown status string.

        :return: Status code label or formatted unknown status string.
        """
        return (
            StatusCode.get_label(self.status)
            if self.status in StatusCode.tags()
            else f"Unknown[0x{self.status:08X}]"
        )

    def __eq__(self, obj: object) -> bool:
        """Check equality of two CmdResponse objects.

        Compares this CmdResponse instance with another object by checking if the other
        object is also a CmdResponse instance and has identical attributes.

        :param obj: Object to compare with this CmdResponse instance.
        :return: True if objects are equal CmdResponse instances with same attributes,
                 False otherwise.
        """
        return isinstance(obj, CmdResponse) and vars(obj) == vars(self)

    def __ne__(self, obj: object) -> bool:
        """Check if this object is not equal to another object.

        This method implements the inequality comparison by negating the equality comparison.

        :param obj: Object to compare with this instance.
        :return: True if objects are not equal, False if they are equal.
        """
        return not self.__eq__(obj)

    def __str__(self) -> str:
        """Get string representation of the object.

        Returns formatted string containing tag, flags and raw data in hexadecimal format.

        :return: Formatted string with object information including tag, flags and raw data.
        """
        return (
            f"Tag=0x{self.header.tag:02X}, Flags=0x{self.header.flags:02X}"
            + " ["
            + ", ".join(f"{b:02X}" for b in self.raw_data)
            + "]"
        )


class GenericResponse(CmdResponse):
    """McuBoot generic response format class.

    This class represents a standard response format for McuBoot commands, providing
    parsing and display functionality for command responses that include status
    information and command tags.
    """

    def __init__(self, header: CmdHeader, raw_data: bytes) -> None:
        """Initialize the Generic response object.

        :param header: Header for the response
        :param raw_data: Response data containing command tag information
        """
        super().__init__(header, raw_data)
        _, tag = unpack_from("<2I", raw_data)
        self.cmd_tag: int = tag

    def __str__(self) -> str:
        """Get string representation of the response object.

        Returns a formatted string containing the response tag, status, and command information
        for debugging and logging purposes.

        :return: Formatted string with tag, status, and command details.
        """
        tag = ResponseTag.get_label(self.header.tag)
        status = self._get_status_label()
        cmd = (
            CommandTag.get_label(self.cmd_tag)
            if self.cmd_tag in CommandTag.tags()
            else f"Unknown[0x{self.cmd_tag:02X}]"
        )
        return f"Tag={tag}, Status={status}, Cmd={cmd}"


class GetPropertyResponse(CmdResponse):
    """McuBoot get property response format class.

    This class represents a response from McuBoot get-property commands, handling
    the parsing and formatting of property values returned by the bootloader.
    """

    def __init__(self, header: CmdHeader, raw_data: bytes) -> None:
        """Initialize the Get-Property response object.

        Parses the raw response data to extract property values from the mboot get-property command
        response.

        :param header: Header for the response containing command information
        :param raw_data: Raw response data bytes to be parsed for property values
        """
        super().__init__(header, raw_data)
        _, *values = unpack_from(f"<{self.header.params_count}I", raw_data)
        self.values: list[int] = list(values)

    def __str__(self) -> str:
        """Get string representation of the response object.

        Returns a formatted string containing the response tag, status, and all parameter values
        in hexadecimal format.

        :return: Formatted string with tag, status and parameter values.
        """
        tag = ResponseTag.get_label(self.header.tag)
        status = self._get_status_label()
        return f"Tag={tag}, Status={status}" + "".join(
            f", v{n}=0x{value:08X}" for n, value in enumerate(self.values)
        )


class ReadMemoryResponse(CmdResponse):
    """McuBoot read memory response format class.

    This class represents the response format for read memory operations in McuBoot protocol,
    handling the parsing and representation of memory data returned from the target device.
    """

    def __init__(self, header: CmdHeader, raw_data: bytes) -> None:
        """Initialize the Read-Memory response object.

        :param header: Header for the response
        :param raw_data: Response data containing length information
        """
        super().__init__(header, raw_data)
        _, length = unpack_from("<2I", raw_data)
        self.length: int = length

    def __str__(self) -> str:
        """Get string representation of the response object.

        Returns formatted string containing response tag, status, and length information.

        :return: Formatted string with tag, status, and length details.
        """
        tag = ResponseTag.get_label(self.header.tag)
        status = self._get_status_label()
        return f"Tag={tag}, Status={status}, Length={self.length}"


class FlashReadOnceResponse(CmdResponse):
    """McuBoot Flash Read Once response handler.

    This class processes and manages response data from McuBoot Flash Read Once operations,
    parsing the response format and extracting length, values, and data fields for further
    processing.
    """

    def __init__(self, header: CmdHeader, raw_data: bytes) -> None:
        """Initialize the Flash-Read-Once response object.

        Parses the raw response data to extract length and values from the Flash-Read-Once command.
        The method unpacks the response data and extracts the actual data bytes based on the length.

        :param header: Header for the response containing command information
        :param raw_data: Raw response data bytes to be parsed
        :raises struct.error: If raw_data cannot be unpacked according to expected format
        """
        super().__init__(header, raw_data)
        _, length, *values = unpack_from(f"<{self.header.params_count}I", raw_data)
        self.length: int = length
        self.values: list[int] = list(values)
        self.data = raw_data[8 : 8 + self.length] if self.length > 0 else b""

    def __str__(self) -> str:
        """Get string representation of the response object.

        Returns formatted string containing response tag, status, and length information.

        :return: Formatted string with tag, status, and length details.
        """
        tag = ResponseTag.get_label(self.header.tag)
        status = self._get_status_label()
        return f"Tag={tag}, Status={status}, Length={self.length}"


class FlashReadResourceResponse(CmdResponse):
    """McuBoot flash read resource response.

    This class represents the response format for flash read resource operations in McuBoot protocol,
    containing the response header and the length of the resource data that was read.
    """

    def __init__(self, header: CmdHeader, raw_data: bytes) -> None:
        """Initialize the Flash-Read-Resource response object.

        :param header: Header for the response
        :param raw_data: Response data containing length information
        """
        super().__init__(header, raw_data)
        _, length = unpack_from("<2I", raw_data)
        self.length: int = length

    def __str__(self) -> str:
        """Get string representation of the response object.

        Returns formatted string containing response tag, status, and length information.

        :return: Formatted string with tag, status, and length details.
        """
        tag = ResponseTag.get_label(self.header.tag)
        status = self._get_status_label()
        return f"Tag={tag}, Status={status}, Length={self.length}"


class KeyProvisioningResponse(CmdResponse):
    """McuBoot Key Provisioning response format class.

    Represents the response data structure returned from McuBoot key provisioning operations,
    including response header information and the length of provisioned key data.
    """

    def __init__(self, header: CmdHeader, raw_data: bytes) -> None:
        """Initialize the Key-Provisioning response object.

        :param header: Header for the response.
        :param raw_data: Response data containing length information.
        """
        super().__init__(header, raw_data)
        _, length = unpack_from("<2I", raw_data)
        self.length: int = length

    def __str__(self) -> str:
        """Get string representation of the response object.

        Returns formatted string containing response tag, status, and length information.

        :return: Formatted string with tag, status and length details.
        """
        tag = ResponseTag.get_label(self.header.tag)
        status = self._get_status_label()
        return f"Tag={tag}, Status={status}, Length={self.length}"


class TrustProvisioningResponse(CmdResponse):
    """McuBoot Trust Provisioning response format class.

    Handles response data from trust provisioning operations in McuBoot protocol,
    including parsing of response values and payload data extraction.
    """

    def __init__(self, header: CmdHeader, raw_data: bytes) -> None:
        """Initialize the Trust-Provisioning response object.

        Parses the raw response data and extracts parameter values from the binary format.

        :param header: Header for the response containing metadata and parameter count.
        :param raw_data: Response data in binary format to be unpacked.
        """
        super().__init__(header, raw_data)
        _, *values = unpack(f"<{self.header.params_count}I", raw_data)
        self.values: list[int] = list(values)

    def __str__(self) -> str:
        """Get string representation of the response object.

        Returns formatted string containing response tag and status information.

        :return: Formatted string with tag and status details.
        """
        tag = ResponseTag.get_label(self.header.tag)
        status = self._get_status_label()
        return f"Tag={tag}, Status={status}"

    def get_payload_data(self, offset: int = 0) -> Optional[bytes]:
        """Get the payload from the response.

        Converts response values to bytes starting from specified offset. Each value is converted
        to 4-byte little-endian format and concatenated.

        :param offset: Offset of integer unit in data to start conversion from.
        :return: Concatenated bytes from response values, or None if insufficient data.
        """
        if len(self.values) < 2:
            return None
        blocks = [x.to_bytes(length=4, byteorder="little") for x in self.values[offset:]]
        return b"".join(blocks)


class NoResponse(CmdResponse):
    """SPSDK MBoot NoResponse command representation.

    This class represents a special internal case when no response is provided
    by the target device during MBoot communication. It extends CmdResponse to
    handle scenarios where the target fails to respond to issued commands.
    """

    def __init__(self, cmd_tag: int) -> None:
        """Create a NoResponse to a command that was issued, indicated by its tag.

        :param cmd_tag: Tag of the command that preceded the no-response from target.
        """
        header = CmdHeader(tag=cmd_tag, flags=0, reserved=0, params_count=0)
        raw_data = pack("<L", StatusCode.NO_RESPONSE.tag)
        super().__init__(header, raw_data)


def parse_cmd_response(data: bytes, offset: int = 0) -> CmdResponse:
    """Parse command response from raw data bytes.

    The method parses the command header to identify the response type and creates
    the appropriate response object based on the tag. If the response type is not
    recognized, it returns a generic CmdResponse object.

    :param data: Input data in bytes containing the command response
    :param offset: The offset position in input data to start parsing from
    :return: Parsed command response object of appropriate type
    """
    known_response: dict[int, Type[CmdResponse]] = {
        ResponseTag.GENERIC.tag: GenericResponse,
        ResponseTag.GET_PROPERTY.tag: GetPropertyResponse,
        ResponseTag.READ_MEMORY.tag: ReadMemoryResponse,
        ResponseTag.FLASH_READ_RESOURCE.tag: FlashReadResourceResponse,
        ResponseTag.FLASH_READ_ONCE.tag: FlashReadOnceResponse,
        ResponseTag.KEY_BLOB_RESPONSE.tag: ReadMemoryResponse,
        ResponseTag.KEY_PROVISIONING_RESPONSE.tag: KeyProvisioningResponse,
        ResponseTag.TRUST_PROVISIONING_RESPONSE.tag: TrustProvisioningResponse,
    }
    header = CmdHeader.parse(data, offset)
    if header.tag in known_response:
        return known_response[header.tag](header, data[CmdHeader.SIZE :])

    return CmdResponse(header, data[CmdHeader.SIZE :])
