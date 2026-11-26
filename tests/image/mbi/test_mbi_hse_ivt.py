#!/usr/bin/env python
#
# Copyright 2026 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""Tests of HSE Image Vector Table (IVT) used by MCX E3 Master Boot Images.

The tests cover the IVT binary layout including the multicore fields (start addresses and
boot configuration of additional Cortex-M7 cores), extended fields (XRDC MDAC configuration,
recovery application) and round trip of the MBI configuration, export and parse.
"""

import os
import struct

import pytest

from spsdk.exceptions import SPSDKError
from spsdk.image.mbi.mbi import MasterBootImage
from spsdk.image.mbi.mbi_mixin_hse import BootConfig, Ivt, Mbi_MixinHseIvt
from spsdk.utils.config import Config
from spsdk.utils.family import FamilyRevision
from spsdk.utils.misc import write_file

APP_START = 0x0040_1000
CM7_1_START = 0x0050_0000


def _app_data() -> bytes:
    """Create a dummy application with a valid-looking vector table.

    :return: Application binary.
    """
    return struct.pack("<II", 0x2040_8000, APP_START + 0x401) + bytes(range(256)) * 4


def _mbi_config(tmpdir: str, family: str, **kwargs: object) -> Config:
    """Create plain XIP MBI configuration.

    :param tmpdir: Temporary directory for the application binary.
    :param family: Chip family name.
    :param kwargs: Additional configuration values.
    :return: Configuration object.
    """
    app_path = os.path.join(tmpdir, "app.bin")
    write_file(_app_data(), app_path, mode="wb")
    cfg = Config(
        {
            "family": family,
            "outputImageExecutionTarget": "xip",
            "outputImageAuthenticationType": "plain",
            "masterBootOutputFile": os.path.join(tmpdir, "mbi.bin"),
            "inputImageFile": app_path,
            "appStartAddress": hex(APP_START),
        }
    )
    cfg.update(kwargs)
    cfg.config_dir = tmpdir
    return cfg


def test_ivt_default_layout() -> None:
    """Test that IVT with default values keeps the original single core layout."""
    ivt = Ivt(FamilyRevision("mcxe327"))
    ivt.app_start_addr = APP_START
    ivt.lc_config_addr = 0x0040_2000
    ivt.hse_fw_addr = 0x0040_3000
    ivt.app_boot_header_addr = 0x0040_0FC0
    data = ivt.export()
    assert len(data) == Ivt.SIZE == 256
    expected = struct.pack(
        "<IIIIIIIIIIIII204s",
        Ivt.DEFAULT_IVT_MARKER,
        0x1,
        0,
        APP_START,
        0,
        0,
        0,
        0,
        0,
        0x0040_2000,
        0,
        0x0040_3000,
        0x0040_0FC0,
        bytes(204),
    )
    assert data == expected


def test_ivt_multicore_layout() -> None:
    """Test placement of the multicore and extended fields in the IVT."""
    ivt = Ivt(FamilyRevision("mcxe327"))
    ivt.app_start_addr = APP_START
    ivt.cores_start_addr = [0x0050_0000, 0x0060_0000, 0x0070_0000]
    ivt.boot_config.cm7_enable = [True, True, True, True]
    ivt.boot_config.app_swt_init = True
    ivt.lc_config_addr = 0x0040_2000
    ivt.xrdc_mdac_config_addr = 0x0040_4000
    ivt.recovery_app_start_addr = 0x2040_0000
    ivt.recovery_app_length = 0x1000
    data = ivt.export()

    def word(offset: int) -> int:
        return int.from_bytes(data[offset : offset + 4], "little")

    assert word(0x00) == 0x5AA5_5AA5
    assert word(0x04) == 0b1_0010_0111  # CM7_0/1/2 enable, APP_SWT_INIT, CM7_3 enable
    assert word(0x0C) == APP_START
    assert word(0x14) == 0x0050_0000
    assert word(0x1C) == 0x0060_0000
    assert word(0x24) == 0x0040_2000
    assert word(0x28) == 0x0070_0000
    assert word(0x38) == 0x0040_4000
    assert word(0x40) == 0x2040_0000
    assert word(0x44) == 0x1000

    parsed = Ivt.parse(data, FamilyRevision("mcxe327"))
    assert parsed.cores_start_addr == ivt.cores_start_addr
    assert parsed.boot_config.cm7_enable == [True, True, True, True]
    assert parsed.boot_config.app_swt_init
    assert parsed.xrdc_mdac_config_addr == 0x0040_4000
    assert parsed.recovery_app_start_addr == 0x2040_0000
    assert parsed.recovery_app_length == 0x1000
    assert parsed.export() == data
    assert "CM7_3 Start Address: 0x00700000" in str(parsed)


@pytest.mark.parametrize(
    "value,enables,boot_seq,swt",
    [
        (0x001, [True, False, False, False], False, False),
        (0x003, [True, True, False, False], False, False),
        (0x009, [True, False, False, False], True, False),
        (0x121, [True, False, False, True], False, True),
        (0x106, [False, True, True, True], False, False),
    ],
)
def test_boot_config_bits(value: int, enables: list[bool], boot_seq: bool, swt: bool) -> None:
    """Test boot configuration word bit fields.

    :param value: Boot configuration word value.
    :param enables: Expected CM7 cores enable flags.
    :param boot_seq: Expected BOOT_SEQ flag.
    :param swt: Expected APP_SWT_INIT flag.
    """
    boot_cfg = BootConfig(value)
    assert boot_cfg.cm7_enable == enables
    assert boot_cfg.cm7_0_enable == enables[0]
    assert boot_cfg.boot_seq == boot_seq
    assert boot_cfg.app_swt_init == swt
    assert boot_cfg.value == value


def test_ivt_verify_enabled_core_without_address() -> None:
    """Test that enabled additional core without start address is reported as error."""
    ivt = Ivt(FamilyRevision("mcxe327"))
    ivt.app_start_addr = APP_START
    ivt.boot_config.cm7_enable[1] = True
    with pytest.raises(SPSDKError):
        ivt.verify().validate()


@pytest.mark.parametrize(
    "family,cores,extended",
    [
        ("mcxe31b", [], True),
        ("mcxe327", [1], True),
        ("mcxe32b", [1], True),
    ],
)
def test_hse_ivt_validation_schemas(family: str, cores: list[int], extended: bool) -> None:
    """Test that the IVT schemas reflect the cores and fields available on the family.

    :param family: Chip family name.
    :param cores: Expected additional cores.
    :param extended: Expected support of extended IVT fields.
    """
    schemas = Mbi_MixinHseIvt.mix_get_validation_schemas(FamilyRevision(family))
    properties: dict = {}
    for schema in schemas:
        properties.update(schema["properties"])
    for core in range(1, Ivt.CORES_COUNT):
        assert (f"cm7_{core}StartAddress" in properties) == (core in cores)
        assert (f"cm7_{core}Enable" in properties) == (core in cores)
    assert ("xrdcMdacConfigAddr" in properties) == extended
    assert ("recoveryAppStartAddress" in properties) == extended


@pytest.mark.parametrize("family", ["mcxe315", "mcxe31b", "mcxe327", "mcxe32b"])
@pytest.mark.parametrize("auth_type", ["plain", "smr", "signed"])
def test_mbi_hse_template_sections(family: str, auth_type: str) -> None:
    """Test that all MCX E3 families and image types offer the same IVT settings sections.

    :param family: Chip family name.
    :param auth_type: Output image authentication type.
    """
    mbi_cls = MasterBootImage.get_mbi_class(
        {
            "family": family,
            "outputImageExecutionTarget": "xip",
            "outputImageAuthenticationType": auth_type,
        }
    )
    schemas = mbi_cls.get_validation_schemas(FamilyRevision(family))
    titles = [schema["title"] for schema in schemas if "title" in schema]
    assert titles.count("HSE IVT Settings") == 1
    assert titles.count("HSE IVT Extended Settings") == 1
    assert "Application Boot Header Settings" not in titles


@pytest.mark.parametrize("family", ["mcxe327", "mcxe32b"])
def test_mbi_multicore_round_trip(tmpdir: str, family: str) -> None:
    """Test MBI export/parse/get_config round trip with multicore IVT settings.

    :param tmpdir: Temporary directory.
    :param family: Chip family name.
    """
    cfg = _mbi_config(
        tmpdir,
        family,
        appSwtInit=True,
        cm7_1StartAddress=hex(CM7_1_START),
        xrdcMdacConfigAddr="0x00404000",
        recoveryAppStartAddress="0x20400000",
        recoveryAppLength="0x2000",
    )
    mbi = MasterBootImage.load_from_config(cfg)
    mbi.validate()
    data = mbi.export()
    assert int.from_bytes(data[0x04:0x08], "little") == 0x23
    assert int.from_bytes(data[0x14:0x18], "little") == CM7_1_START

    parsed = MasterBootImage.parse(data, FamilyRevision(family))
    assert parsed.export() == data
    parsed_cfg = parsed.get_config(str(tmpdir))
    assert parsed_cfg["cm7_1StartAddress"] == hex(CM7_1_START)
    assert parsed_cfg["cm7_1Enable"] is True
    assert parsed_cfg["appSwtInit"] is True
    assert parsed_cfg["xrdcMdacConfigAddr"] == "0x404000"
    assert parsed_cfg["recoveryAppStartAddress"] == "0x20400000"
    assert parsed_cfg["recoveryAppLength"] == "0x2000"

    # Build the image again from the parsed configuration
    parsed_cfg["inputImageFile"] = cfg["inputImageFile"]
    parsed_cfg.config_dir = str(tmpdir)
    assert MasterBootImage.load_from_config(parsed_cfg).export() == data


def test_mbi_multicore_core_disabled(tmpdir: str) -> None:
    """Test that the additional core can have start address with clock kept gated.

    :param tmpdir: Temporary directory.
    """
    cfg = _mbi_config(tmpdir, "mcxe327", cm7_1StartAddress=hex(CM7_1_START), cm7_1Enable=False)
    data = MasterBootImage.load_from_config(cfg).export()
    assert int.from_bytes(data[0x04:0x08], "little") == 0x1
    assert int.from_bytes(data[0x14:0x18], "little") == CM7_1_START
    parsed_cfg = MasterBootImage.parse(data, FamilyRevision("mcxe327")).get_config(str(tmpdir))
    assert parsed_cfg["cm7_1Enable"] is False


def test_mbi_single_core_unchanged(tmpdir: str) -> None:
    """Test that MBI without multicore settings has no additional IVT fields set.

    :param tmpdir: Temporary directory.
    """
    data = MasterBootImage.load_from_config(_mbi_config(tmpdir, "mcxe327")).export()
    assert int.from_bytes(data[0x04:0x08], "little") == 0x1
    assert data[0x10:0x24] == bytes(0x14)
    assert data[0x28:0x100] == bytes(0xD8)
    parsed_cfg = MasterBootImage.parse(data, FamilyRevision("mcxe327")).get_config(str(tmpdir))
    assert "cm7_1StartAddress" not in parsed_cfg
    assert "xrdcMdacConfigAddr" not in parsed_cfg


@pytest.mark.parametrize(
    "input_enable, config_enable, expected_boot_cfg",
    [
        # enable flag inherited from the input IVT
        (True, None, 0x3),
        (False, None, 0x1),
        # explicitly configured enable flag overrides the input IVT
        (True, False, 0x1),
        (False, True, 0x3),
    ],
)
def test_mbi_multicore_enable_with_imported_ivt(
    tmpdir: str, input_enable: bool, config_enable: bool | None, expected_boot_cfg: int
) -> None:
    """Test that configured core enable flag is kept when the start address comes from input IVT.

    :param tmpdir: Temporary directory.
    :param input_enable: CM7_1 enable flag in the input image IVT.
    :param config_enable: CM7_1 enable flag in the configuration, None if not defined.
    :param expected_boot_cfg: Expected boot configuration word of the output image.
    """
    input_cfg = _mbi_config(
        tmpdir, "mcxe327", cm7_1StartAddress=hex(CM7_1_START), cm7_1Enable=input_enable
    )
    input_image = os.path.join(tmpdir, "input_mbi.bin")
    write_file(MasterBootImage.load_from_config(input_cfg).export(), input_image, mode="wb")

    cfg = _mbi_config(tmpdir, "mcxe327")
    cfg["inputImageFile"] = input_image
    if config_enable is not None:
        cfg["cm7_1Enable"] = config_enable
    mbi = MasterBootImage.load_from_config(cfg)
    mbi.validate()
    data = mbi.export()
    assert int.from_bytes(data[0x04:0x08], "little") == expected_boot_cfg
    assert int.from_bytes(data[0x14:0x18], "little") == CM7_1_START
