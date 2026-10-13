#!/usr/bin/env python
#
# Copyright 2022-2026 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""Test module for SPSDK BinaryImage utility class.

This module contains comprehensive unit tests for the BinaryImage class and related
functionality from spsdk.utils.binary_image, covering binary image manipulation,
file format support, and validation operations.
"""

import io
import os
from typing import Any

import pytest

from spsdk.exceptions import SPSDKError, SPSDKOverlapError, SPSDKValueError
from spsdk.utils.binary_image import BinaryImage, BinaryPattern
from spsdk.utils.config import Config


def test_binary_image_sort_sub_images() -> None:
    """Test binary image sub-image sorting functionality.

    Validates that sub-images within a BinaryImage are properly sorted by offset
    when added in non-sequential order. Creates a main binary image with zero
    pattern and adds three sub-images at different offsets (0x2, 0x4, 0x6) in
    non-sequential order, then verifies the final exported binary has the correct
    sorted structure.
    """
    image = BinaryImage(name="main", size=8, pattern=BinaryPattern("zeros"))

    image_0x2 = BinaryImage(name="0x2", offset=0x2, size=0x1, pattern=BinaryPattern("0x2"))
    image_0x4 = BinaryImage(name="0x4", offset=0x4, size=0x1, pattern=BinaryPattern("0x4"))
    image_0x6 = BinaryImage(name="0x6", offset=0x6, size=0x1, pattern=BinaryPattern("0x6"))

    image.add_image(image_0x2)
    image.add_image(image_0x6)
    image.add_image(image_0x4)

    image.validate()

    assert image.size == 8
    assert image.export() == b"\x00\x00\x02\x00\x04\x00\x06\x00"


def test_binary_image_join_sub_images() -> None:
    """Test joining sub-images functionality in BinaryImage class.

    This test verifies that the BinaryImage.join_images() method correctly merges
    sub-images into the main binary data and clears the sub_images list. It creates
    a main image with zero pattern and adds three sub-images at different offsets,
    then validates the joining operation produces the expected binary output.

    :raises AssertionError: If the binary output doesn't match expected values or sub-images aren't properly joined.
    """
    image = BinaryImage(name="main", size=8, pattern=BinaryPattern("zeros"))

    image_0x2 = BinaryImage(name="0x2", offset=0x2, size=0x1, pattern=BinaryPattern("0x2"))
    image_0x4 = BinaryImage(name="0x4", offset=0x4, size=0x1, pattern=BinaryPattern("0x4"))
    image_0x6 = BinaryImage(name="0x6", offset=0x6, size=0x1, pattern=BinaryPattern("0x6"))

    image.add_image(image_0x2)
    image.add_image(image_0x6)
    image.add_image(image_0x4)

    image.validate()

    assert image.export() == b"\x00\x00\x02\x00\x04\x00\x06\x00"

    assert len(image.sub_images) == 3

    image.join_images()

    assert len(image.sub_images) == 0

    assert image.binary == b"\x00\x00\x02\x00\x04\x00\x06\x00"
    assert image.export() == b"\x00\x00\x02\x00\x04\x00\x06\x00"


def test_binary_image_pattern() -> None:
    """Test BinaryPattern class functionality with different pattern types.

    Validates that BinaryPattern correctly generates binary data for various
    pattern types including zeros, ones, random, and incremental patterns.
    Ensures proper block size handling and expected output formats.

    :raises AssertionError: If any pattern generates unexpected binary data.
    """
    assert BinaryPattern("zeros").get_block(4) == b"\x00\x00\x00\x00"
    assert BinaryPattern("ones").get_block(4) == b"\xff\xff\xff\xff"
    assert len(BinaryPattern("rand").get_block(4)) == 4
    assert BinaryPattern("inc").get_block(4) == b"\x00\x01\x02\x03"


def test_binary_image_invalid_pattern() -> None:
    """Test that BinaryPattern raises SPSDKValueError for invalid pattern strings.

    Verifies that the BinaryPattern constructor properly validates input patterns
    and raises the appropriate exception when given an invalid pattern string.

    :raises SPSDKValueError: When an invalid pattern string is provided to BinaryPattern constructor.
    """
    with pytest.raises(SPSDKValueError):
        BinaryPattern("invalid")


def test_binary_image_draw() -> None:
    """Test the draw functionality of the BinaryImage class.

    This test verifies that the BinaryImage.draw() method correctly generates
    visual representations with and without color formatting. It creates a main
    binary image with embedded sub-images at specific offsets and validates
    that ANSI color codes are present in colored output and absent in non-colored output.

    :raises AssertionError: If the draw method doesn't produce expected color formatting behavior.
    """
    image = BinaryImage(name="main", size=8, pattern=BinaryPattern("zeros"))

    image_0x2 = BinaryImage(name="0x2", offset=0x2, size=0x1, pattern=BinaryPattern("0x2"))
    image_0x4 = BinaryImage(name="0x4", offset=0x4, size=0x1, pattern=BinaryPattern("0x4"))
    image_0x6 = BinaryImage(name="0x6", offset=0x6, size=0x1, pattern=BinaryPattern("0x6"))

    image.add_image(image_0x2)
    image.add_image(image_0x6)
    image.add_image(image_0x4)

    assert "\x1b[" in image.draw()
    assert "\x1b[" not in image.draw(no_color=True)


def test_binary_image_draw_invalid() -> None:
    """Test BinaryImage draw method with overlapping regions.

    This test verifies that the draw method properly handles and visualizes
    overlapping binary images by checking for the presence of error color codes
    in the output. The test creates a main image with two overlapping sub-images
    and confirms that the visualization indicates the conflict with red coloring.

    :raises AssertionError: If the draw output doesn't contain the expected error color code.
    """
    image = BinaryImage(name="main", size=8, pattern=BinaryPattern("zeros"))

    image_0x2 = BinaryImage(name="0x2", offset=0x2, size=0x4, pattern=BinaryPattern("0x2"))
    image_0x4 = BinaryImage(name="0x4", offset=0x4, size=0x1, pattern=BinaryPattern("0x4"))

    image.add_image(image_0x2)
    image.add_image(image_0x4)

    assert "\x1b[31m" in image.draw()


@pytest.mark.parametrize(
    "path",
    [
        ("images/image.bin"),
        ("images/image.hex"),
        ("images/image.s19"),
        ("images/image.srec"),
    ],
)
def test_load_binary_image(path: str, data_dir: str) -> None:
    """Test loading a binary image from file path.

    Verifies that a binary image can be successfully loaded from the specified file path
    and validates the loaded binary image properties including type and non-zero length.

    :param path: Relative path to the binary image file.
    :param data_dir: Directory path containing test data files.
    """
    binary = BinaryImage.load_binary_image(os.path.join(data_dir, path))
    assert binary
    assert isinstance(binary, BinaryImage)
    assert len(binary) > 0


@pytest.mark.parametrize(
    "path,execution_start_address",
    [
        ("images/image.bin", None),
        ("images/image.hex", "0x6000231D"),
        ("images/image.s19", "0x8E37D"),
        ("images/image.srec", "0x8001159"),
    ],
)
def test_execution_start_address(
    path: str, execution_start_address: str | None, data_dir: str
) -> None:
    """Test execution start address of a binary image.

    Loads a binary image from the specified path and verifies that its execution
    start address matches the expected value. If no expected address is provided,
    verifies that the execution start address is None.

    :param path: Relative path to the binary image file within the data directory.
    :param execution_start_address: Expected execution start address
        as hexadecimal string, or None if no address expected.
    :param data_dir: Base directory path containing test data files.
    """
    binary = BinaryImage.load_binary_image(os.path.join(data_dir, path))
    if execution_start_address is not None:
        assert binary.execution_start_address == int(execution_start_address, 16)
    else:
        assert binary.execution_start_address is None


@pytest.mark.parametrize(
    "path,error_msg",
    [
        (
            "images/image_corrupted.s19",
            (
                "Error loading file: expected crc 'D3' in record "
                "S21407F41001020100010600000200000000000000D4, but got 'D4'"
            ),
        )
    ],
)
def test_load_binary_image_invalid_s19(path: str, error_msg: str, data_dir: str) -> None:
    """Test loading binary image with invalid S19 file format.

    This test verifies that BinaryImage.load_binary_image properly raises
    SPSDKError when attempting to load an invalid S19 file with the expected
    error message.

    :param path: Relative path to the invalid S19 file in the data directory.
    :param error_msg: Expected error message pattern to match in the raised exception.
    :param data_dir: Absolute path to the test data directory.
    :raises SPSDKError: Always raised due to invalid S19 file format.
    """
    with pytest.raises(SPSDKError, match=error_msg):
        BinaryImage.load_binary_image(os.path.join(data_dir, path))


def test_load_binary_image_invalid(data_dir: str) -> None:
    """Test loading binary image with invalid file path.

    Verifies that BinaryImage.load_binary_image raises SPSDKError when attempting
    to load from a non-existent or invalid file path.

    :param data_dir: Directory path containing test data files.
    """
    with pytest.raises(SPSDKError):
        BinaryImage.load_binary_image(os.path.join(data_dir, "invalid_file"))


def test_binary_image_load_elf(data_dir: str) -> None:
    """Test loading and merging of ELF binary image files.

    This test verifies the correct loading of a problematic ELF file and validates
    its properties including size and offset. It also tests the ability to merge
    multiple binary images by adding an S19 format image to the loaded ELF image.

    :param data_dir: Path to the directory containing test data files.
    """
    binary = BinaryImage.load_binary_image(os.path.join(data_dir, "images/image_0x80002000.elf"))
    assert binary
    assert isinstance(binary, BinaryImage)
    assert len(binary) > 0
    assert binary.size == 19368
    assert binary.offset == 0x8000_2000
    binary.add_image(BinaryImage.load_binary_image(os.path.join(data_dir, "images/image.s19")))
    assert binary.size == 582818


def test_execution_address_is_preserved_in_exported_image(tmpdir: Any, data_dir: str) -> None:
    """Test that execution address is preserved when exporting and reloading binary images.

    This test verifies that the execution start address remains intact when a binary
    image is exported to a different format (S19) and then reloaded. It ensures
    data integrity during format conversion operations.

    :param tmpdir: Temporary directory for test file operations.
    :param data_dir: Directory containing test data files.
    """
    elf_binary = BinaryImage.load_binary_image(
        os.path.join(data_dir, "images/image_0x80002000.elf")
    )
    assert elf_binary.execution_start_address == 0x80002305
    s19_path = os.path.join(tmpdir, "image_0x80002000.s19")
    elf_binary.save_binary_image(s19_path, "S19")
    s19_binary = BinaryImage.load_binary_image(s19_path)
    assert s19_binary.execution_start_address == 0x80002305


# ---- ELF write tests ----


def test_save_elf_minimal_elf32(tmpdir: Any) -> None:
    """Test that a 32-bit minimal ELF can be saved and has correct magic/architecture."""
    img = BinaryImage(name="test", offset=0x20000000)
    img.binary = b"\xde\xad\xbe\xef" * 256
    img.execution_start_address = 0x20000000

    out = os.path.join(str(tmpdir), "out32.elf")
    img.save_binary_image(out, file_format="ELF")

    with open(out, "rb") as f:
        raw = f.read()

    assert raw[:4] == b"\x7fELF", "Missing ELF magic"
    assert raw[4] == 1, "Expected EI_CLASS=1 (32-bit)"
    assert raw[5] == 1, "Expected little-endian"


def test_save_elf_minimal_elf64(tmpdir: Any) -> None:
    """Test that a 64-bit minimal ELF is generated when address > 32-bit range."""
    img = BinaryImage(name="test", offset=0x100000000)
    img.binary = b"\xaa\xbb" * 128
    img.execution_start_address = 0x100000000

    out = os.path.join(str(tmpdir), "out64.elf")
    img.save_binary_image(out, file_format="ELF")

    with open(out, "rb") as f:
        raw = f.read()

    assert raw[:4] == b"\x7fELF", "Missing ELF magic"
    assert raw[4] == 2, "Expected EI_CLASS=2 (64-bit)"


def test_save_elf_roundtrip(tmpdir: Any) -> None:
    """Test ELF save/reload round-trip preserves size and entry point."""
    img = BinaryImage(name="test", offset=0x20000000)
    img.binary = b"\x01\x02\x03\x04" * 512
    img.execution_start_address = 0x20000001

    out = os.path.join(str(tmpdir), "roundtrip.elf")
    img.save_binary_image(out, file_format="ELF")

    reloaded = BinaryImage.load_binary_image(out)
    assert reloaded.size == img.size
    assert reloaded.execution_start_address == 0x20000001


def test_save_elf_patch_fallback_no_source(tmpdir: Any, caplog: Any) -> None:
    """ELF_PATCH with no source_elf_file should fall back to plain ELF with a warning."""
    import logging  # pylint: disable=import-outside-toplevel

    img = BinaryImage(name="test", offset=0x20000000)
    img.binary = b"\xcc" * 256
    img.execution_start_address = 0x20000000

    out = os.path.join(str(tmpdir), "fallback.elf")
    with caplog.at_level(logging.WARNING):
        img.save_binary_image(out, file_format="ELF_PATCH", source_elf_file=None)

    assert os.path.isfile(out)
    with open(out, "rb") as f:
        assert f.read(4) == b"\x7fELF"
    assert any("Falling back" in r.message for r in caplog.records)


def test_save_elf_patch_fallback_non_elf_source(tmpdir: Any, caplog: Any) -> None:
    """ELF_PATCH with non-ELF source_elf_file should fall back to plain ELF with a warning."""
    import logging  # pylint: disable=import-outside-toplevel

    img = BinaryImage(name="test", offset=0x20000000)
    img.binary = b"\xdd" * 128

    fake_src = os.path.join(str(tmpdir), "not_elf.bin")
    with open(fake_src, "wb") as f:
        f.write(b"\x00\x01\x02\x03")

    out = os.path.join(str(tmpdir), "fallback_non_elf.elf")
    with caplog.at_level(logging.WARNING):
        img.save_binary_image(out, file_format="ELF_PATCH", source_elf_file=fake_src)

    assert os.path.isfile(out)
    with open(out, "rb") as f:
        assert f.read(4) == b"\x7fELF"
    assert any("Falling back" in r.message for r in caplog.records)


def test_save_elf_from_real_elf_source(data_dir: str, tmpdir: Any) -> None:
    """Round-trip: load real ELF, save as ELF, reload — size and entry must match.

    :param data_dir: Directory containing test data files.
    :param tmpdir: Pytest temp directory.
    """
    src = os.path.join(data_dir, "images/image_0x80002000.elf")
    original = BinaryImage.load_binary_image(src)

    out = os.path.join(str(tmpdir), "real_minimal.elf")
    original.save_binary_image(out, file_format="ELF")

    reloaded = BinaryImage.load_binary_image(out)
    assert reloaded.size == original.size
    assert reloaded.execution_start_address == original.execution_start_address


def test_save_elf_patch_with_real_elf(data_dir: str, tmpdir: Any) -> None:
    """ELF_PATCH with a real ELF source: verify entry point and data integrity.

    :param data_dir: Directory containing test data files.
    :param tmpdir: Pytest temp directory.
    """
    pytest.importorskip("lief")

    src = os.path.join(data_dir, "images/image_0x80002000.elf")
    original = BinaryImage.load_binary_image(src)

    out = os.path.join(str(tmpdir), "real_patch.elf")
    original.save_binary_image(out, file_format="ELF_PATCH", source_elf_file=src)

    reloaded = BinaryImage.load_binary_image(out)
    assert reloaded.execution_start_address == original.execution_start_address

    orig_data = bytes(original.binary or b"")
    orig_start = original.offset
    reloaded_bytes = b""
    if reloaded.sub_images:
        for sub in reloaded.sub_images:
            if sub.offset == orig_start:
                reloaded_bytes = bytes(sub.binary or b"")
                break
    else:
        reloaded_bytes = bytes(reloaded.binary or b"")

    assert orig_data == reloaded_bytes, "Primary segment data mismatch after ELF_PATCH"


def test_collect_segments_uses_absolute_address() -> None:
    """Test that nested sub-images are collected at their absolute address.

    Regression: sub-images must be emitted at their absolute address (base offset
    of the parent plus their relative offset), not at the relative offset alone.
    Otherwise ELF/ELF_PATCH output places load segments at address 0 instead of
    the real flash address the image links to.
    """
    base = 0x2000_0000
    parent = BinaryImage(name="parent", offset=base, size=0x200, pattern=BinaryPattern("zeros"))
    payload = BinaryImage(name="payload", offset=0x0, size=0x10, binary=b"\xaa" * 0x10)
    tail = BinaryImage(name="tail", offset=0x100, size=0x8, binary=b"\xbb" * 0x8)
    parent.add_image(payload)
    parent.add_image(tail)

    segments = parent._collect_segments()

    addresses = [addr for addr, _ in segments]
    assert addresses == [base + 0x0, base + 0x100]
    assert segments[0][1] == b"\xaa" * 0x10
    assert segments[1][1] == b"\xbb" * 0x8


def test_save_elf_nested_image_absolute_addresses(tmpdir: Any) -> None:
    """Test that ELF output writes nested sub-images at absolute load addresses.

    Regression for wrong PT_LOAD p_vaddr (0x0) when the image is built as a parent
    carrying the flash base offset with children at relative offsets.
    """
    base = 0x2000_0000
    parent = BinaryImage(name="parent", offset=base, size=0x200, pattern=BinaryPattern("zeros"))
    parent.add_image(BinaryImage(name="payload", offset=0x0, size=0x10, binary=b"\xaa" * 0x10))
    parent.add_image(BinaryImage(name="tail", offset=0x100, size=0x8, binary=b"\xbb" * 0x8))

    out = os.path.join(str(tmpdir), "nested.elf")
    parent.save_binary_image(out, file_format="ELF")

    reloaded = BinaryImage.load_binary_image(out)
    # The reloaded image must expose the absolute base address, never 0x0.
    addresses = (
        [sub.absolute_address for sub in reloaded.sub_images]
        if reloaded.sub_images
        else [reloaded.offset]
    )
    assert all(addr >= base for addr in addresses)
    assert min(addresses) == base


def test_save_elf_patch_high_base_no_bogus_segment(tmpdir: Any) -> None:
    """ELF_PATCH must not append load segments below the flash base address.

    The MBI image tree is built 0-based (``MasterBootImage.export_image`` does not
    carry the flash-base offset), while the source ELF links at a high flash base
    (e.g. 0x2000_0000). When the image has a tail extension (e.g. TZM/CRC) not
    covered by an existing PT_LOAD, the patcher used to append the image data at its
    0-based address, creating a bogus duplicate PT_LOAD at vaddr 0x0. The raw binary
    then spanned two address spaces and became huge/un-flashable. The exporter must
    rebase the 0-based image onto the source ELF's load base, patch the covered
    region in place, and append the tail at its absolute address.
    """
    elffile = pytest.importorskip("elftools.elf.elffile")

    base = 0x2000_0000
    app_size = 0x100
    tail_size = 0x8

    # 1. Source ELF: a single PT_LOAD at the flash base (simulates the toolchain output).
    src_img = BinaryImage(name="src", offset=base, binary=b"\xa5" * app_size)
    source_elf = os.path.join(str(tmpdir), "source.elf")
    src_img.save_binary_image(source_elf, file_format="ELF")

    # 2. Image tree built 0-based (as MasterBootImage.export_image does): a top image at
    #    offset 0 with a covered payload + an uncovered tail extension.
    parent = BinaryImage(name="mbi")
    parent.add_image(BinaryImage(name="code", offset=0x0, binary=b"\x5a" * app_size))
    parent.add_image(BinaryImage(name="tail", offset=app_size, binary=b"\x11" * tail_size))

    patched = os.path.join(str(tmpdir), "patched.elf")
    parent.save_binary_image(patched, file_format="ELF_PATCH", source_elf_file=source_elf)

    with open(patched, "rb") as f:
        elf = elffile.ELFFile(io.BytesIO(f.read()))
        loads = [
            (seg["p_vaddr"], seg["p_filesz"])
            for seg in elf.iter_segments()
            if seg["p_type"] == "PT_LOAD" and seg["p_filesz"] > 0
        ]

    # No load segment may sit below the flash base (this is the 0x0 bogus-segment bug).
    assert all(vaddr >= base for vaddr, _ in loads), f"Load segment below flash base: {loads}"
    # The tail extension must be appended at its absolute (rebased) address.
    assert (base + app_size, tail_size) in loads, f"Tail not at absolute address: {loads}"
    # The patched ELF must not be bloated by padding across address spaces.
    assert os.path.getsize(patched) < os.path.getsize(source_elf) + 0x1000


def test_save_elf_patch_absolute_subregion_not_shifted(tmpdir: Any) -> None:
    """ELF_PATCH must not shift an already-absolute image sub-region below the ELF base.

    Regression for SPSDK-5724: the source ELF may link at a base (e.g. 0x8000_0000) with the
    image data placed at a higher sub-address (e.g. 0x8000_2000, after a vector/header region).
    The rebase must only lift a 0-based image up; it must never shift an already-absolute image
    down to the ELF base (which corrupted the ELF and dropped the entry point).
    """
    elffile = pytest.importorskip("elftools.elf.elffile")

    elf_base = 0x8000_0000
    sub_addr = 0x8000_2000
    data = b"\x5a" * 0x80

    # Source ELF whose single PT_LOAD spans the base through past the sub-region.
    src_img = BinaryImage(name="src", offset=elf_base, binary=b"\xa5" * 0x3000)
    source_elf = os.path.join(str(tmpdir), "source.elf")
    src_img.save_binary_image(source_elf, file_format="ELF")

    # Image already at the absolute sub-address (not 0-based).
    img = BinaryImage(name="img", offset=sub_addr, binary=data)
    patched = os.path.join(str(tmpdir), "patched.elf")
    img.save_binary_image(patched, file_format="ELF_PATCH", source_elf_file=source_elf)

    with open(patched, "rb") as f:
        elf = elffile.ELFFile(io.BytesIO(f.read()))
        loads = [
            (seg["p_vaddr"], seg["p_filesz"])
            for seg in elf.iter_segments()
            if seg["p_type"] == "PT_LOAD" and seg["p_filesz"] > 0
        ]
        # The data must have been patched in place at its absolute sub-address.
        seg = next(s for s in elf.iter_segments() if s["p_type"] == "PT_LOAD")
        patched_bytes = seg.data()[sub_addr - elf_base : sub_addr - elf_base + len(data)]

    # The image was inside the source PT_LOAD, so no new segment is added and nothing moves down.
    assert loads == [(elf_base, 0x3000)], f"Segment layout changed unexpectedly: {loads}"
    assert patched_bytes == data, "Image data was not patched at its absolute address"


def _build_parent_with_children() -> BinaryImage:
    """Create a parent BinaryImage with three ordered sub-images for reuse in tests.

    :return: Parent BinaryImage of size 8 with sub-images at offsets 0x2, 0x4 and 0x6.
    """
    image = BinaryImage(name="main", size=8, pattern=BinaryPattern("zeros"))
    image.add_image(BinaryImage(name="0x2", offset=0x2, size=0x1, pattern=BinaryPattern("0x2")))
    image.add_image(BinaryImage(name="0x4", offset=0x4, size=0x1, pattern=BinaryPattern("0x4")))
    image.add_image(BinaryImage(name="0x6", offset=0x6, size=0x1, pattern=BinaryPattern("0x6")))
    return image


def test_find_sub_image_found_and_missing() -> None:
    """Test find_sub_image returns the matching sub-image and raises when missing.

    :raises SPSDKValueError: When the requested sub-image name does not exist.
    """
    image = _build_parent_with_children()
    assert image.find_sub_image("0x4").offset == 0x4
    with pytest.raises(SPSDKValueError):
        image.find_sub_image("does_not_exist")


def test_append_image_sets_offset_to_length() -> None:
    """Test append_image places the appended image at the current parent length."""
    parent = BinaryImage(name="parent", size=4, pattern=BinaryPattern("zeros"))
    child = BinaryImage(name="child", size=2, binary=b"\xaa\xbb")
    parent.append_image(child)
    assert child.offset == 4
    assert child.parent is parent


def test_image_name_and_absolute_address_with_parent() -> None:
    """Test hierarchical image_name and absolute_address across the parent chain."""
    image = _build_parent_with_children()
    child = image.find_sub_image("0x6")
    assert child.image_name == "main=>0x6"
    assert child.absolute_address == 0x6
    assert image.image_name == "main"
    assert image.absolute_address == 0


def test_aligned_start_and_length() -> None:
    """Test aligned_start floor alignment and aligned_length ceil computation."""
    image = BinaryImage(name="img", size=10, offset=6)
    assert image.aligned_start(4) == 4
    # end = 6 + 10 = 16 -> aligned_end 16, aligned_start 4 -> 12
    assert image.aligned_length(4) == 12


def test_get_image_by_absolute_address() -> None:
    """Test get_image_by_absolute_address returns nested image or raises when out of range.

    :raises SPSDKValueError: When the address does not fit in the image address space.
    """
    image = _build_parent_with_children()
    found = image.get_image_by_absolute_address(0x4)
    assert found.name == "0x4"
    # An address inside parent but not in any child returns the parent itself
    assert image.get_image_by_absolute_address(0x0).name == "main"
    with pytest.raises(SPSDKValueError):
        image.get_image_by_absolute_address(0x100)


def test_validate_negative_offset() -> None:
    """Test validate raises for a negative image offset.

    :raises SPSDKValueError: When the offset is negative.
    """
    image = BinaryImage(name="img", size=4)
    image.offset = -1
    with pytest.raises(SPSDKValueError):
        image.validate()


def test_validate_sub_image_does_not_fit() -> None:
    """Test validate raises when a sub-image exceeds the parent boundaries.

    :raises SPSDKOverlapError: When the sub-image does not fit into the parent.
    """
    parent = BinaryImage(name="parent", size=4, pattern=BinaryPattern("zeros"))
    parent.add_image(BinaryImage(name="too_big", offset=0, size=8))
    with pytest.raises(SPSDKOverlapError):
        parent.validate()


def test_validate_sub_images_overlap() -> None:
    """Test validate raises when two sibling sub-images overlap.

    :raises SPSDKOverlapError: When two sub-images overlap each other.
    """
    parent = BinaryImage(name="parent", size=16, pattern=BinaryPattern("zeros"))
    parent.add_image(BinaryImage(name="a", offset=0, size=4))
    parent.add_image(BinaryImage(name="b", offset=2, size=4))
    with pytest.raises(SPSDKOverlapError):
        parent.validate()


def test_min_offset_empty_and_update_offsets() -> None:
    """Test min_offset defaults to zero and update_offsets rebases sub-image offsets."""
    empty = BinaryImage(name="empty")
    assert empty.min_offset == 0

    parent = BinaryImage(name="parent")
    parent.add_image(BinaryImage(name="a", offset=4, size=2))
    parent.add_image(BinaryImage(name="b", offset=8, size=2))
    assert parent.min_offset == 4
    parent.update_offsets()
    assert parent.offset == 4
    assert [child.offset for child in parent.sub_images] == [0, 4]


def test_len_uses_size_or_sub_images() -> None:
    """Test __len__ returns explicit size or computes it from sub-images."""
    sized = BinaryImage(name="sized", size=32)
    assert len(sized) == 32

    auto = BinaryImage(name="auto", alignment=4)
    auto.add_image(BinaryImage(name="a", offset=0, size=5, binary=b"\x01\x02\x03\x04\x05"))
    # max_size 5 aligned to 4 -> 8
    assert len(auto) == 8


def test_export_empty_returns_empty_bytes() -> None:
    """Test export returns empty bytes for an empty image with no content."""
    image = BinaryImage(name="empty")
    assert image.export() == b""


def test_export_returns_direct_binary() -> None:
    """Test export shortcut returns the stored binary when it matches the image size."""
    image = BinaryImage(name="img", size=4, binary=b"\x01\x02\x03\x04")
    assert image.export() == b"\x01\x02\x03\x04"


def test_export_merge_error_for_oversized_sub_image() -> None:
    """Test export raises when a sub-image cannot be merged into the parent buffer.

    :raises SPSDKValueError: When the sub-image data is larger than the parent slice.
    """
    parent = BinaryImage(name="parent", size=4, pattern=BinaryPattern("zeros"))
    parent.add_image(BinaryImage(name="big", offset=0, size=8, binary=b"\x01" * 8))
    with pytest.raises(SPSDKValueError):
        parent.export()


def test_iter_blocks_invalid_block_size() -> None:
    """Test iter_blocks raises for a non-positive block size.

    :raises SPSDKValueError: When block_size is less than or equal to zero.
    """
    image = BinaryImage(name="img", size=4, binary=b"\x01\x02\x03\x04")
    with pytest.raises(SPSDKValueError):
        list(image.iter_blocks(block_size=0))


def test_iter_blocks_empty_image() -> None:
    """Test iter_blocks yields nothing for an empty image."""
    image = BinaryImage(name="empty")
    assert list(image.iter_blocks()) == []


def test_iter_blocks_direct_binary() -> None:
    """Test iter_blocks streams a direct binary image in the requested block size."""
    image = BinaryImage(name="img", binary=b"\x01" * 10)
    blocks = list(image.iter_blocks(block_size=4))
    assert b"".join(blocks) == b"\x01" * 10
    assert [len(b) for b in blocks] == [4, 4, 2]


def test_iter_blocks_with_sub_images_and_pattern() -> None:
    """Test iter_blocks overlays sub-images on top of the parent pattern per block."""
    parent = BinaryImage(name="parent", size=16, pattern=BinaryPattern("zeros"))
    parent.add_image(BinaryImage(name="sub", offset=4, size=4, binary=b"\xaa" * 4))
    result = b"".join(parent.iter_blocks(block_size=8))
    assert result == b"\x00\x00\x00\x00\xaa\xaa\xaa\xaa" + b"\x00" * 8


def test_save_binary_image_invalid_format() -> None:
    """Test save_binary_image raises for an unsupported output format.

    :raises SPSDKValueError: When the file format is not recognized.
    """
    image = BinaryImage(name="img", size=4, binary=b"\x01\x02\x03\x04")
    with pytest.raises(SPSDKValueError):
        image.save_binary_image("dummy.out", file_format="INVALID")


def test_save_binary_image_bin_with_offset(tmp_path: Any) -> None:
    """Test save_binary_image prepends offset padding for the BIN format.

    :param tmp_path: Temporary directory provided by pytest.
    """
    image = BinaryImage(name="img", size=2, offset=4, pattern=BinaryPattern("zeros"))
    image.binary = b"\x01\x02"
    out = os.path.join(tmp_path, "out.bin")
    image.save_binary_image(out, file_format="BIN")
    with open(out, "rb") as f:
        data = f.read()
    assert data == b"\x00\x00\x00\x00\x01\x02"


def test_detect_file_format(tmp_path: Any) -> None:
    """Test detect_file_format identifies SPARSE, ELF and BIN payloads.

    :param tmp_path: Temporary directory provided by pytest.
    """
    sparse_path = os.path.join(tmp_path, "img.sparse")
    with open(sparse_path, "wb") as f:
        f.write((0xED26FF3A).to_bytes(4, "little") + b"\x00" * 8)
    assert BinaryImage.detect_file_format(sparse_path) == "SPARSE"

    elf_path = os.path.join(tmp_path, "img.elf")
    with open(elf_path, "wb") as f:
        f.write(b"\x7fELF" + b"\x00" * 8)
    assert BinaryImage.detect_file_format(elf_path) == "ELF"

    bin_path = os.path.join(tmp_path, "img.bin")
    with open(bin_path, "wb") as f:
        f.write(b"\x01\x02\x03\x04")
    assert BinaryImage.detect_file_format(bin_path) == "BIN"


def test_detect_file_format_read_error() -> None:
    """Test detect_file_format raises SPSDKError for an unreadable path.

    :raises SPSDKError: When the file cannot be opened.
    """
    with pytest.raises(SPSDKError):
        BinaryImage.detect_file_format(os.path.join("non", "existing", "file.bin"))


def test_load_from_config_binary_block() -> None:
    """Test load_from_config builds sub-images from binary_block region definitions."""
    cfg = Config(
        {
            "name": "Root",
            "size": 16,
            "pattern": "zeros",
            "alignment": 1,
            "regions": [
                {
                    "binary_block": {
                        "size": 4,
                        "offset": 0,
                        "pattern": "0xaa",
                        "name": "block1",
                    }
                }
            ],
        }
    )
    image = BinaryImage.load_from_config(cfg)
    assert image.name == "Root"
    assert len(image.sub_images) == 1
    block = image.find_sub_image("block1")
    assert block.export() == b"\xaa\xaa\xaa\xaa"


def test_gap_dont_care_pattern_non_constant_returns_none() -> None:
    """Test _gap_dont_care_pattern returns None for non-constant patterns."""
    assert BinaryImage(name="rnd", pattern=BinaryPattern("rand"))._gap_dont_care_pattern() is None
    assert BinaryImage(name="inc", pattern=BinaryPattern("inc"))._gap_dont_care_pattern() is None
    constant = BinaryImage(name="zero", pattern=BinaryPattern("zeros"))
    assert constant._gap_dont_care_pattern() == b"\x00\x00\x00\x00"
    assert BinaryImage(name="none")._gap_dont_care_pattern() is None


def test_export_sparse_and_load_sparse_roundtrip() -> None:
    """Test export_sparse and load_sparse preserve the exported binary content."""
    parent = BinaryImage(name="parent", size=4096 * 2, pattern=BinaryPattern("zeros"))
    parent.add_image(BinaryImage(name="raw", offset=0, size=4096, binary=b"\x5a" * 4096))
    sparse = parent.export_sparse(calculate_crc=True)
    restored = BinaryImage.load_sparse(sparse)
    assert restored.export() == parent.export()


def test_save_and_reload_sparse_file(tmp_path: Any) -> None:
    """Test saving to and reloading from the SPARSE file format.

    :param tmp_path: Temporary directory provided by pytest.
    """
    parent = BinaryImage(name="parent", size=4096 * 2, pattern=BinaryPattern("zeros"))
    parent.add_image(BinaryImage(name="raw", offset=0, size=4096, binary=b"\x5a" * 4096))
    out = os.path.join(tmp_path, "img.sparse")
    parent.save_binary_image(out, file_format="SPARSE")
    assert BinaryImage.detect_file_format(out) == "SPARSE"
    reloaded = BinaryImage.load_binary_image(out)
    assert reloaded.export() == parent.export()


def test_get_min_draw_width_accounts_for_children() -> None:
    """Test get_min_draw_width grows with sub-images and can exclude them."""
    parent = BinaryImage(name="p", size=64, pattern=BinaryPattern("zeros"))
    child = BinaryImage(name="child_with_a_very_long_descriptive_name", offset=0, size=8)
    parent.add_image(child)
    with_children = parent.get_min_draw_width(include_sub_images=True)
    without_children = parent.get_min_draw_width(include_sub_images=False)
    assert with_children >= without_children


def test_draw_width_too_short_raises() -> None:
    """Test draw raises when the requested width is smaller than the minimal width.

    :raises SPSDKValueError: When the provided width is too small.
    """
    image = BinaryImage(name="img", size=8, pattern=BinaryPattern("zeros"))
    with pytest.raises(SPSDKValueError):
        image.draw(width=1)


def test_info_contains_key_sections() -> None:
    """Test info renders the header, size and visual representation sections."""
    image = _build_parent_with_children()
    image.description = "sample image"
    image.execution_start_address = 0x2
    output = image.info(no_color=True)
    assert "BINARY IMAGE INFORMATION" in output
    assert "VISUAL REPRESENTATION" in output
    assert "sample image" in output
    assert "Sub-images Count:        3" in output
