#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2021-2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""Module used for generation SecureBinary V4.0 ."""
import logging
from datetime import datetime
from struct import calcsize, pack, unpack, unpack_from
from typing import Any, Optional, cast

from typing_extensions import Self

from spsdk.crypto.hash import EnumHashAlgorithm, get_hash, get_hash_length
from spsdk.exceptions import SPSDKError, SPSDKValueError
from spsdk.image.ahab.ahab_container import AHABContainerV2
from spsdk.image.ahab.ahab_data import AHABSignHashAlgorithm, create_chip_config
from spsdk.image.ahab.ahab_iae import ImageArrayEntryV2
from spsdk.image.mbi.utils import get_ahab_supported_hashes, get_mbi_ahab_validation_schemas
from spsdk.sbfile.sb31.images import SecureBinary31Commands
from spsdk.utils.abstract import BaseClass
from spsdk.utils.abstract_features import FeatureBaseClass
from spsdk.utils.config import Config
from spsdk.utils.database import DatabaseManager, get_schema_file
from spsdk.utils.family import FamilyRevision, get_db, update_validation_schema_family
from spsdk.utils.misc import align, align_block
from spsdk.utils.verifier import Verifier, VerifierResult

logger = logging.getLogger(__name__)


########################################################################################################################
# Secure Boot Image Class (Version 3.1)
########################################################################################################################
class SecureBinary4Descr(BaseClass):
    """SecureBinary V4.0 descriptor.

    Structure definition for SB4.0 image descriptor with specific header
    format and metadata (4 bytes values are in little endian):
        4-byte magic
        4-byte formatVersion
        4-byte blockCount
        4-byte maxBlockSize
        4-byte nextBlockSize
        4-byte reserved
        4-byte timestamp[2]
        byte description[16]
        byte nextBlockHash[48]
        byte oemShareBlob[64]

    maxBlockSize: maximal size of the data block used in SB4 file. In case that SB4 uses various data block sizes,
        the field contains the size of the largest data block. The size is meant as size of complete block
        (the same definition as nextBlockSize)

    oemShareBlob[64]: contains OEM share blob. This field is used for Device HSM SB4 file only.
        For other types it is filed by zeros
    """

    DESCRIPTION_LENGTH = 16
    HEADER_FORMAT = f"<4s2H4LQ{DESCRIPTION_LENGTH}s"
    HEADER_SIZE = calcsize(HEADER_FORMAT)
    MAGIC = b"sbv4"
    FORMAT_VERSION = "4.0"
    MANIFEST_FORMAT = f"{HEADER_FORMAT}48s64s"
    MANIFEST_SIZE = calcsize(MANIFEST_FORMAT)
    SUPPORTED_HASHES = ["sha384"]

    def __init__(
        self,
        description: Optional[str] = None,
        timestamp: Optional[int] = None,
        hash_type: Optional[EnumHashAlgorithm] = None,  # left here for backward compatibility
    ) -> None:
        """Initialize the SecureBinary V4.0 Header.

        Creates a new header instance with specified hash type and optional description and timestamp.

        :param hash_type: Hash type used in commands binary block
        :param description: Custom description up to 16 characters long, defaults to None
        :param timestamp: Timestamp (number of seconds since Jan 1st, 2000), if None use current time
        :raises SPSDKValueError: If hash type is not supported
        """
        if hash_type and hash_type.label.lower() not in self.SUPPORTED_HASHES:
            raise SPSDKValueError(f"Invalid hash type: {hash_type}")

        self.hash_type = EnumHashAlgorithm.SHA384
        self.block_count = 0
        self.timestamp = timestamp or int(datetime.now().timestamp())
        self.original_description = description
        self.description = self._adjust_description(description)
        self.block1_hash = bytes(48)
        self.block1_length = 0
        self.max_block_size = 0
        self.oem_share_block = bytes(64)

    def _adjust_description(self, description: Optional[str] = None) -> bytes:
        """Format the description.

        Adjusts the description to fit the fixed-length field by truncating if too long or
        padding with zeros if too short. If no description is provided, returns a zero-filled byte array.

        :param description: Text description to format
        :return: Formatted description as a fixed-length byte array
        """
        if not description:
            return bytes(self.DESCRIPTION_LENGTH)
        desc = bytes(description, encoding="ascii")
        desc = desc[: self.DESCRIPTION_LENGTH]
        desc += bytes(self.DESCRIPTION_LENGTH - len(desc))
        return desc

    def __repr__(self) -> str:
        """Get string representation of the object.

        :return: String representation of the object
        """
        return f"SB4.0 Header, Timestamp: {self.timestamp}"

    def __str__(self) -> str:
        """Get detailed information about SB v4.0 header as a string.

        :return: Formatted string with header information
        """
        info = str()
        info += f" Magic:                       {self.MAGIC.decode('ascii')}\n"
        info += f" Version:                     {self.FORMAT_VERSION}\n"
        info += f" Block count:                 {self.block_count}\n"
        info += f" Max block size:              {self.max_block_size}\n"
        info += f" Block 1 size:                {self.block1_length}\n"
        info += f" Timestamp:                   {self.timestamp}\n"
        info += f" Description:                 {self.description.decode('ascii')}\n"
        info += f" Block 1 hash:                {self.block1_hash.hex()}\n"
        info += f" OEM share block:             {self.oem_share_block.hex()}\n"
        return info

    def update(self, commands: "SecureBinary4Commands") -> None:
        """Update the volatile fields in header using command block data.

        Updates the block count, hash, and length fields in the header based on the
        provided commands block.

        :param commands: SB4.0 Commands block
        """
        self.block_count = commands.block_count
        self.block1_hash = commands.final_hash
        self.block1_length = commands.block1_size
        self.max_block_size = (
            commands.block1_size
        )  # This will be updated when the variable block size will be used

    def export(self) -> bytes:
        """Serialize the SB file header to bytes.

        :return: Binary representation of the header
        """
        major_format_version, minor_format_version = [
            int(v) for v in self.FORMAT_VERSION.split(".")
        ]
        return pack(
            self.MANIFEST_FORMAT,
            self.MAGIC,
            minor_format_version,
            major_format_version,
            self.block_count,
            self.max_block_size,
            self.block1_length,
            0,
            self.timestamp,
            self.description,
            self.block1_hash,
            self.oem_share_block,
        )

    @classmethod
    def parse(cls, data: bytes, hash_type: EnumHashAlgorithm = EnumHashAlgorithm.SHA384) -> Self:
        """Parse binary data into a SecureBinary V4.0 Header object.

        Extracts header information from raw binary data and initializes a new header object.

        :param data: Binary data containing the header information
        :param hash_type: Hash algorithm used for header validation
        :return: Initialized SecureBinary V4.0 Header object
        :raises SPSDKError: When header data is invalid or cannot be parsed
        """
        if len(data) < cls.MANIFEST_SIZE:
            raise SPSDKError("Invalid input header binary size.")
        (
            magic,
            minor_version,
            major_version,
            block_count,
            max_block_size,
            block_size,
            _,
            timestamp,
            description_raw,
            block1_hash,
            oem_share_block,
        ) = unpack_from(cls.MANIFEST_FORMAT, data[: cls.MANIFEST_SIZE])
        if magic != cls.MAGIC:
            raise SPSDKError("Magic doesn't match")
        if major_version != 4 and minor_version != 0:
            raise SPSDKError(f"Unable to parse SB version {major_version}.{minor_version}")

        description = description_raw.decode("utf-8").replace("\x00", "")

        obj = cls(
            description=description,
            timestamp=timestamp,
        )
        obj.block_count = block_count
        obj.max_block_size = max_block_size
        obj.block1_length = block_size
        obj.block1_hash = block1_hash
        obj.oem_share_block = oem_share_block
        return obj

    def validate(self) -> None:
        """Validate the settings of class members.

        :raises SPSDKError: Invalid configuration of SB4.0 header blob class members.
        """
        if self.block_count is None or self.block_count < 0:
            raise SPSDKError("Invalid SB4.0 header block count.")
        if self.hash_type is None or self.hash_type.label.lower() not in self.SUPPORTED_HASHES:
            raise SPSDKError("Invalid SB4.0 header hash type.")
        if self.block1_length is None or self.block1_length < 4 + 4 + 32:
            raise SPSDKError("Invalid SB4.0 header block size.")
        if self.max_block_size is None or self.max_block_size < self.block1_length:
            raise SPSDKError("Invalid SB4.0 header max block size.")
        if self.timestamp is None:
            raise SPSDKError("Invalid SB4.0 header timestamp.")
        if self.description is None or len(self.description) != 16:
            raise SPSDKError("Invalid SB4.0 header image description.")


class SecureBinary4Commands(SecureBinary31Commands):
    """Blob containing SB4.0 commands."""

    FEATURE = DatabaseManager.SB40
    SB_COMMANDS_NAME = "SB4.0"
    SUPPORTED_HASHES = [EnumHashAlgorithm.SHA384]

    @classmethod
    def parse_block_header(
        cls,
        block_data: bytes,
        offset: int,
        block_size: int,
        block_hash: bytes,
        hash_type: Optional[EnumHashAlgorithm] = EnumHashAlgorithm.SHA384,
    ) -> tuple[int, int, bytes, bytes]:
        """Parse the block header from the input data and verify its integrity.

        :param block_data: Binary data of the block
        :param offset: Offset in the data where the header begins
        :param block_size: Size of the block in bytes
        :param block_hash: Expected hash of the block for verification
        :param hash_type: Hash algorithm used for block hashing
        :return: Tuple containing block number, next block size, next block hash, and encrypted block data
        :raises SPSDKError: When the block hash verification fails
        """
        if hash_type != EnumHashAlgorithm.SHA384:
            raise SPSDKError(f"Unsupported hash type: {hash_type}")
        hash_length = get_hash_length(hash_type)

        # Extract block header information - SB4.0 has an additional 4-byte field for next_block_size
        block_number, next_block_size, next_block_hash, encrypted_block = unpack(
            f"<LL{hash_length}s{block_size - hash_length - 8}s",
            block_data[offset : offset + block_size],
        )

        # Verify block integrity by checking hash
        # In SB4.0, the full block includes block_number, next_block_size, next_block_hash, and encrypted_block
        full_block = block_data[offset : offset + block_size]

        calculated_hash = get_hash(full_block, hash_type)
        if calculated_hash != block_hash:
            raise SPSDKError(
                f"Block hash verification failed for block {block_number}. "
                f"Expected: {block_hash.hex()}, Got: {calculated_hash.hex()}"
            )

        return block_number, next_block_size, next_block_hash, encrypted_block

    def process_cmd_blocks_to_export(self, data_blocks: list[bytes]) -> bytes:
        """Process given data blocks for export.

        Processes and packages command blocks for export, updating internal tracking counters.

        :param data_blocks: List of binary data blocks to process
        :return: Processed binary data ready for export
        """
        next_block_hash = bytes(get_hash_length(self.hash_type))
        next_block_size = 0

        processed_blocks = []
        for block_number, block_data in reversed(list(enumerate(data_blocks, start=1))):
            encrypted_block = self._encrypt_block(block_number, block_data)
            full_block = pack(
                f"<LL{len(next_block_hash)}s{len(encrypted_block)}s",
                block_number,
                next_block_size,
                next_block_hash,
                encrypted_block,
            )

            next_block_hash = get_hash(full_block, self.hash_type)
            next_block_size = len(full_block)
            processed_blocks.append(full_block)

        self.final_hash = next_block_hash
        self.block1_size = next_block_size
        final_data = b"".join(reversed(processed_blocks))
        return final_data


class SecureBinary4(FeatureBaseClass):
    """Secure Binary SB4.0 class."""

    FEATURE = DatabaseManager.SB40

    PCK_SIZES = [256, 128]

    SB4_BLOCK_ALIGNMENT = 4

    def __init__(
        self,
        family: FamilyRevision,
        container: AHABContainerV2,
        sb_commands: SecureBinary4Commands,
        description: Optional[str] = None,
    ) -> None:
        """Initialize Secure Binary v4.0 data container.

        :param family: Family revision information.
        :param container: AHAB Container v2 instance.
        :param sb_commands: Secure Binary commands.
        :param description: Custom description up to 16 characters long, defaults to None
        """
        self.family = family
        self.description = description
        self.container = container
        self.sb_commands = sb_commands
        self.sb_descriptor = SecureBinary4Descr(
            description=self.description,
            timestamp=self.sb_commands.timestamp,
        )

    @classmethod
    def get_commands_validation_schemas(cls, family: FamilyRevision) -> list[dict[str, Any]]:
        """Create the list of validation schemas for commands.

        :param family: Family description.
        :return: List of validation schemas.
        """
        sb3_sch_cfg = get_schema_file(DatabaseManager.SB31)
        db = get_db(family)
        schemas: list[dict[str, Any]] = [sb3_sch_cfg["sb3_commands"]]
        # remove unused command for current family
        supported_commands = db.get_list(cls.FEATURE, "supported_commands")
        list_of_commands: list[dict] = schemas[0]["properties"]["commands"]["items"]["oneOf"]
        schemas[0]["properties"]["commands"]["items"]["oneOf"] = [
            command
            for command in list_of_commands
            if list(command["properties"].keys())[0] in supported_commands
        ]
        supports_compression = db.get_bool(cls.FEATURE, "supports_compression")
        if not supports_compression:
            load_cmd = schemas[0]["properties"]["commands"]["items"]["oneOf"][1]
            load_cmd["properties"]["load"]["properties"]["compress"]["skip_in_template"] = True
            load_cmd["properties"]["load"]["properties"]["sectorSize"]["skip_in_template"] = True

        return schemas

    @classmethod
    def get_validation_schemas(cls, family: FamilyRevision) -> list[dict[str, Any]]:
        """Create the list of validation schemas for the SB4.0 container.

        :param family: Family description.
        :return: List of validation schemas.
        """
        mbi_sch_cfg = get_mbi_ahab_validation_schemas(
            create_chip_config(family, feature=SecureBinary4.FEATURE, base_key=["ahab"])
        )
        sb4_sch_cfg = get_schema_file(DatabaseManager.SB40)
        sch_cfg = get_schema_file("general")["family"]
        update_validation_schema_family(sch_cfg["properties"], cls.get_supported_families(), family)

        schemas: list[dict[str, Any]] = [sch_cfg]
        schemas.extend(
            [sb4_sch_cfg[x] for x in ["sb4", "sb4_description", "sb4_output", "sb4_test"]]
        )
        schemas.append(mbi_sch_cfg["ahab_sign_support"])
        schemas.append(mbi_sch_cfg["ahab_sign_support_add_image_hash_type"])
        schemas.append(mbi_sch_cfg["ahab_sign_support_add_core_id"])

        schemas.extend(cls.get_commands_validation_schemas(family))

        return schemas

    @classmethod
    def load_from_config(cls, config: Config) -> Self:
        """Create an instance of SecureBinary4 from configuration.

        Constructs and initializes a SecureBinary4 object using the provided configuration,
        setting up the AHAB container, image descriptors, and command blocks.

        :param config: Input standard configuration.
        :return: Instance of SecureBinary4 class
        """
        family = FamilyRevision.load_from_config(config)
        description = config.get_str("description", "")

        hash_type = cast(
            EnumHashAlgorithm,
            ImageArrayEntryV2.FLAGS_HASH_ALGORITHM_TYPE.from_label(
                config.get_str(
                    "image_hash_type",
                    get_ahab_supported_hashes(family)[0].label,
                )
            ),
        )

        block_hash_type = EnumHashAlgorithm.SHA384

        # Add commands into the SB3 object
        sb_commands = SecureBinary4Commands.load_from_config(config, hash_type=block_hash_type)
        sb_descr = SecureBinary4Descr(
            description=description, timestamp=sb_commands.timestamp, hash_type=block_hash_type
        )
        chip_config = create_chip_config(family, feature=cls.FEATURE, base_key=["ahab"])
        ahab = AHABContainerV2(chip_config)
        ahab.load_from_config_generic(config)
        core_id = chip_config.core_ids.from_label(
            config.get_str("core_id", chip_config.core_ids.labels()[0])
        )

        data_iae_flags = ImageArrayEntryV2.create_flags(
            image_type=ImageArrayEntryV2.get_image_types(ahab.chip_config, core_id.tag)
            .from_label("secure_binary_4")
            .tag,
            core_id=core_id.tag,
            hash_type=cast(AHABSignHashAlgorithm, hash_type),
        )
        data_image = ImageArrayEntryV2(
            chip_config=ahab.chip_config,
            image=sb_descr.export(),
            image_offset=0,
            load_address=0,
            entry_point=0,
            flags=data_iae_flags,
            image_name="Secure Binary 4.0",
        )

        ahab.image_array.append(data_image)

        # Create SB4.0 object
        return cls(family=family, container=ahab, sb_commands=sb_commands, description=description)

    def get_config(self, data_path: str = "./") -> Config:
        """Create configuration of the SecureBinary4 feature.

        Generates a configuration object representing the current state of the SecureBinary4 instance.

        :param data_path: Path to store the data files of configuration.
        :raises NotImplementedError: This method is not yet implemented.
        """
        ret = self.container._create_config(0, data_path=data_path)
        ret["family"] = self.family.name
        ret["revision"] = self.family.revision
        ret["description"] = self.sb_descriptor.original_description
        ret["containerOutputFile"] = "sb4.bin"

        ret.update(self.sb_commands.get_config(data_path))
        return ret

    def verify(self) -> Verifier:
        """Verify the settings of SecureBinary4 class members.

        Performs comprehensive validation of all components of the SecureBinary4 instance,
        including container, image array, descriptor, commands, and family information.

        :return: Verifier object with verification results
        """
        ret = Verifier("SB4.0 Feature Verification")

        # Validate the container
        if self.container is None:
            ret.add_record(
                name="AHAB Container", result=VerifierResult.ERROR, value="Missing AHAB container"
            )
        else:
            ret.add_child(self.container.verify(), "AHAB Container")

        # Validate the image array has at least one entry for the SB4 descriptor
        if len(self.container.image_array) != 1:
            ret.add_record(
                name="Image Array",
                result=VerifierResult.ERROR,
                value="AHAB container must have one image entry",
            )
        else:
            ret.add_record(
                name="Image Array",
                result=VerifierResult.SUCCEEDED,
                value="Contains one image entries",
            )

        # Validate the SB header descriptor
        try:
            self.sb_descriptor.validate()
            ret.add_record(name="SB4.0 Header", result=VerifierResult.SUCCEEDED, value="Valid")
        except SPSDKError as e:
            ret.add_record(
                name="SB4.0 Header", result=VerifierResult.ERROR, value=f"Invalid: {str(e)}"
            )

        # Validate the commands
        if self.sb_commands is None:
            ret.add_record(
                name="SB4.0 Commands", result=VerifierResult.ERROR, value="Missing commands object"
            )
        elif not isinstance(self.sb_commands, SecureBinary4Commands):
            ret.add_record(
                name="SB4.0 Commands Type",
                result=VerifierResult.ERROR,
                value=f"Invalid commands type: {type(self.sb_commands).__name__}",
            )
        else:
            try:
                self.sb_commands.validate()
                ret.add_record(
                    name="SB4.0 Commands", result=VerifierResult.SUCCEEDED, value="Valid"
                )
            except SPSDKError as e:
                ret.add_record(
                    name="SB4.0 Commands", result=VerifierResult.ERROR, value=f"Invalid: {str(e)}"
                )

        # Validate family
        if self.family is None:
            ret.add_record(
                name="Family Specification",
                result=VerifierResult.ERROR,
                value="Missing family specification",
            )
        else:
            ret.add_record(
                name="Family Specification",
                result=VerifierResult.SUCCEEDED,
                value=f"Valid: {self.family}",
            )

        # Validate hash type consistency between container and header
        if hasattr(self.container, "image_array") and self.container.image_array:
            container_hash = self.container.image_array[0].get_hash_from_flags(
                self.container.image_array[0].flags
            )
            if container_hash != self.sb_descriptor.hash_type:
                ret.add_record(
                    name="Hash Algorithm Consistency",
                    result=VerifierResult.ERROR,
                    value=(
                        f"Mismatch between container ({container_hash})"
                        f" and SB header ({self.sb_descriptor.hash_type})"
                    ),
                )
            else:
                ret.add_record(
                    name="Hash Algorithm Consistency",
                    result=VerifierResult.SUCCEEDED,
                    value=f"Consistent: {container_hash.label}",
                )

        return ret

    def export(self) -> bytes:
        """Generate binary output of SB4.0 file.

        Assembles and exports the complete SecureBinary 4.0 file by combining the AHAB container,
        SB descriptor, and command blocks.

        :return: Content of SB4.0 file in bytes
        """
        final_data = bytes()

        sb3_commands_data = self.sb_commands.export()
        # HEADER OF SB 4.0 FILE
        self.sb_descriptor.update(self.sb_commands)

        sb_descriptor_data = self.sb_descriptor.export()
        self.container.image_array[0].image = sb_descriptor_data
        self.container.update_fields()
        self.container.image_array[0].image_offset = align(
            self.container.header_length(), alignment=self.SB4_BLOCK_ALIGNMENT
        )
        self.container.update_fields()
        self.container.sign_itself()

        final_data = align_block(self.container.export(), alignment=self.SB4_BLOCK_ALIGNMENT)
        final_data += align_block(sb_descriptor_data, alignment=self.SB4_BLOCK_ALIGNMENT)
        final_data += sb3_commands_data

        return final_data

    def __repr__(self) -> str:
        """Get string representation of the SecureBinary4 object.

        :return: Short string representation of the object
        """
        return f"SB4.0, TimeStamp: {self.sb_commands.timestamp}"

    def __str__(self) -> str:
        """Create detailed string information about SB4.0 loaded file.

        Includes information about both the SB header and commands blob.

        :return: Text information about SB4.0
        """
        ret = ""

        ret += "SB4.0 header:\n"
        ret += str(self.sb_descriptor)

        ret += "SB4.0 commands blob :\n"
        ret += str(self.sb_commands)

        return ret

    @classmethod
    def parse(
        cls,
        data: bytes,
        family: Optional[FamilyRevision] = None,
        pck: Optional[str] = None,
        kdk_access_rights: int = 0,
    ) -> Self:
        """Deserialize object from bytes array.

        Parse a binary SB4.0 file and construct a SecureBinary4 object.

        :param data: Binary data to parse
        :param family: Family revision information, defaults to None
        :param pck: Part Common Key needed for decryption, defaults to None
        :param kdk_access_rights: Key Derivation Key access rights, defaults to 0
        :return: Constructed SecureBinary4 object
        :raises SPSDKError: When parsing fails or data is invalid
        """
        assert family

        chip_config = create_chip_config(family, feature=cls.FEATURE, base_key=["ahab"])
        # Parse AHAB container first
        container = AHABContainerV2.parse(data, chip_config=chip_config, offset=0)

        # Get the image array entry that contains SB descriptor data
        if not container.image_array or len(container.image_array) < 1:
            raise SPSDKError("Invalid AHAB container: missing image array entry for SB4 descriptor")

        sb_image_entry = container.image_array[0]
        # Calculate the offset where SB descriptor is located
        sb_desc_offset = sb_image_entry.image_offset

        # The data block hash type is always SHA384 for SB4 files
        hash_type = EnumHashAlgorithm.SHA384

        # Parse SB descriptor
        sb_desc_data = data[sb_desc_offset : sb_desc_offset + SecureBinary4Descr.MANIFEST_SIZE]
        sb_descriptor = SecureBinary4Descr.parse(sb_desc_data, hash_type=hash_type)

        # Calculate the offset where commands data starts
        commands_offset = sb_desc_offset + align(
            len(sb_desc_data), alignment=cls.SB4_BLOCK_ALIGNMENT
        )

        # Extract description from descriptor
        description = sb_descriptor.description.decode("ascii").rstrip("\x00")

        # Parse commands data
        commands_data = data[commands_offset:]
        sb_commands = SecureBinary4Commands.parse(
            data=commands_data,
            family=family,
            block_size=sb_descriptor.block1_length,
            pck=pck,
            block1_hash=sb_descriptor.block1_hash,
            hash_type=hash_type,
            kdk_access_rights=kdk_access_rights,
            timestamp=sb_descriptor.timestamp,
        )
        # Create and return SB4 object
        sb4_obj = cls(
            family=family, container=container, sb_commands=sb_commands, description=description
        )

        return sb4_obj
