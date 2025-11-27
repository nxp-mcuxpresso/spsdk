#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2021-2023,2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""SPSDK Boot Descriptor (BD) compiler test suite.

This module contains comprehensive tests for the BD file compiler functionality,
which is used to parse and compile boot data files for secure boot operations.
The tests cover BD file parsing, lexical analysis, statement parsing, expression
evaluation, keystore operations, section handling, and error conditions.
"""

from typing import Any, Optional

import pytest

import spsdk.sbfile.sb2.sly_bd_lexer as bd_lexer
import spsdk.sbfile.sb2.sly_bd_parser as bd_parser
from spsdk.exceptions import SPSDKError
from spsdk.sbfile.sb2.sb_21_helper import SB21Helper


def test_parser() -> None:
    """Test BD file parser functionality with comprehensive configuration.

    Tests the BDParser's ability to parse a complete BD (Boot Data) configuration file
    containing options, sources, keyblobs, constants, and sections with various commands
    including encryption, key wrapping, loading, and memory operations. Validates that
    the parsed result matches the expected structured dictionary format.

    :raises SPSDKError: When BD file parsing fails due to syntax or validation errors.
    """
    """"""
    bd_file = r"""
# This BD configuration file serves as a minimal working example
# to test the python parser
    options {
        flags = 0x8; // bd file format: 0x8 encrypted + signed (always 0x8)
        buildNumber = 0x1;
        productVersion = "1.00.00";
        componentVersion = "1.00.00";
        secureBinaryVersion = "2.1";
    }
    sources {
        myImage = "data/sb_sources/output_images/application_signed.bin"; // Put location of Signed or UnSigned image input
        key_store = "data/sb_sources/key_store/key_store_rt5xx.bin";
        fcb_block = "data/sb_sources/input_images/rt500_oct_flash_fcb.bin";
    }
    keyblob (0) {
        (
            start = 0x08001000,
            end = 0x082013ff,
            key = "00112233445566778899001122334455",
            counter = "1122334455667788",
            byteSwap = false
        )
    }
    keyblob (1) {
        (
            start = 0x08201400,
            end = 0x082017FF,
            key = "aabbccddeeffaabbccddeeffaabbccdd",
            counter = "1122334455667788",
            byteSwap = false
        )
    }
    keyblob (2) {
        (
            start = 0x08201800,
            end = 0x08201BFF,
            key = "aabbccddeeffaabbccddeeffaabbcc11",
            counter = "1122334455667788",
            byteSwap = false
        )
    }
    keyblob (3) {
        (
            start = 0x08201C00,
            end = 0x08201FFF,
            key = "aabbccddeeffaabbccddeeffaabbcc22",
            counter = "1122334455667788",
            byteSwap = false
        )
    }

    constants {
        c1 = 1234;
        c2 = 0x80;
        c3 = 1 > 5;
    }

    section (0) {
        keystore_from_nv @9 0x08000800;
        load 0xc0403006 > 0x10C000; // Memory config word for Octal Flash
        enable @0x9 0x10C000;
        erase 0x8000000..0x8300000;  //0x8040000 Erase 3MB 0x300000 block at first ,
        keystore_to_nv @9 0x08000800;

        encrypt (0){
            load myImage > 0x08001000;
        }

        keywrap (0) {
            load {{00000000000000000000000000000000}} > 0x08000000;
        }

        keywrap (1) {
            load {{00000000000000000000000000000000}} > 0x08000100;
        }

        keywrap (2) {
            load {{00000000000000000000000000000000}} > 0x08000200;
        }

        keywrap (3) {
            load {{00000000000000000000000000000000}} > 0x08000300;
        }

        //load 0xf000000f > 0x10d000;
        //enable @0x9 0x10d000;       // Load new FCB by boot ROM code
        load fcb_block > 0x08000400;  // Load FCB block manually (workaround)

        load key_store > 0x08000800;  // Key Store will be copied to external Flash, offset 0x800

    }
    """

    expected_result = {
        "options": {
            "flags": 0x8,
            "buildNumber": 0x1,
            "productVersion": "1.00.00",
            "componentVersion": "1.00.00",
            "secureBinaryVersion": "2.1",
        },
        "sources": {
            "myImage": "data/sb_sources/output_images/application_signed.bin",
            "key_store": "data/sb_sources/key_store/key_store_rt5xx.bin",
            "fcb_block": "data/sb_sources/input_images/rt500_oct_flash_fcb.bin",
        },
        "keyblobs": [
            {
                "keyblob_id": 0,
                "keyblob_content": [
                    {
                        "start": 0x08001000,
                        "end": 0x082013FF,
                        "key": "00112233445566778899001122334455",
                        "counter": "1122334455667788",
                        "byteSwap": 0,
                    },
                ],
            },
            {
                "keyblob_id": 1,
                "keyblob_content": [
                    {
                        "start": 0x08201400,
                        "end": 0x082017FF,
                        "key": "aabbccddeeffaabbccddeeffaabbccdd",
                        "counter": "1122334455667788",
                        "byteSwap": 0,
                    }
                ],
            },
            {
                "keyblob_id": 2,
                "keyblob_content": [
                    {
                        "start": 0x08201800,
                        "end": 0x08201BFF,
                        "key": "aabbccddeeffaabbccddeeffaabbcc11",
                        "counter": "1122334455667788",
                        "byteSwap": 0,
                    }
                ],
            },
            {
                "keyblob_id": 3,
                "keyblob_content": [
                    {
                        "start": 0x08201C00,
                        "end": 0x08201FFF,
                        "key": "aabbccddeeffaabbccddeeffaabbcc22",
                        "counter": "1122334455667788",
                        "byteSwap": 0,
                    }
                ],
            },
        ],
        "sections": [
            {
                "section_id": 0,
                "options": {},
                "commands": [
                    {"keystore_from_nv": {"mem_opt": 9, "address": 0x08000800}},
                    {"fill": {"pattern": 0xC0403006, "address": 0x10C000}},
                    {"enable": {"mem_opt": 0x9, "address": 0x10C000}},
                    {"erase": {"address": 0x8000000, "length": 0x300000}},
                    {"keystore_to_nv": {"mem_opt": 9, "address": 0x08000800}},
                    {
                        "encrypt": {
                            "keyblob_id": 0,
                            "address": 0x08001000,
                            "file": "data/sb_sources/output_images/application_signed.bin",
                        }
                    },
                    {
                        "keywrap": {
                            "keyblob_id": 0,
                            "address": 0x08000000,
                            "values": "00000000000000000000000000000000",
                        }
                    },
                    {
                        "keywrap": {
                            "keyblob_id": 1,
                            "address": 0x08000100,
                            "values": "00000000000000000000000000000000",
                        }
                    },
                    {
                        "keywrap": {
                            "keyblob_id": 2,
                            "address": 0x08000200,
                            "values": "00000000000000000000000000000000",
                        }
                    },
                    {
                        "keywrap": {
                            "keyblob_id": 3,
                            "address": 0x08000300,
                            "values": "00000000000000000000000000000000",
                        }
                    },
                    {
                        "load": {
                            "file": "data/sb_sources/input_images/rt500_oct_flash_fcb.bin",
                            "address": 0x08000400,
                        }
                    },
                    {
                        "load": {
                            "file": "data/sb_sources/key_store/key_store_rt5xx.bin",
                            "address": 0x08000800,
                        }
                    },
                ],
            }
        ],
    }

    parser = bd_parser.BDParser()

    try:
        result = parser.parse(bd_file)
        exception_thrown = False
        assert expected_result == result
    except SPSDKError:
        exception_thrown = True

    assert not exception_thrown


keyblobs = [
    {
        "keyblob_id": 1,
        "keyblob_content": [
            {
                "start": 0x08001000,
                "end": 0x08001FFF,
                "key": "11223344556677889900112233445566",
                "counter": "1234",
            }
        ],
    },
    {
        "keyblob_id": 0,
        "keyblob_content": [
            {
                "start": 0x08002000,
                "end": 0x08002FFF,
                "key": "22334455667788990011223344556611",
                "counter": "1234",
            }
        ],
    },
    {"keyblob_id": 2, "keyblob_content": []},
]


encrypt: dict[str, dict[str, Any]] = {"encrypt": {}}


def test_keyblob_validation() -> None:
    """Test keyblob validation functionality in SB21Helper.

    Validates that the SB21Helper._validate_keyblob method correctly handles
    valid keyblob indices and properly raises SPSDKError for invalid indices.
    Tests both successful validation cases and error handling.

    :raises SPSDKError: When keyblob validation fails with invalid index.
    """
    sb_helper = SB21Helper()
    kb = sb_helper._validate_keyblob(keyblobs, 0)

    assert kb is not None

    kb = sb_helper._validate_keyblob(keyblobs, 3)

    try:
        kb = sb_helper._validate_keyblob(keyblobs, 2)
        assert False
    except SPSDKError:
        assert True


def test_parser_return_none() -> None:
    """Test that BDParser raises SPSDKError when parsing invalid input.

    Verifies that the BDParser.parse() method properly raises an SPSDKError
    exception when given nonsensical input text that cannot be parsed.

    :raises SPSDKError: Expected exception when parsing fails due to invalid input.
    """
    text = r"""nonsense"""

    parser = bd_parser.BDParser()

    try:
        retval = parser.parse(text=text)
        exception_thrown = False
        assert retval is not None
    except SPSDKError:
        exception_thrown = True

    assert exception_thrown


def test_variable_str() -> None:
    """Test string representation of Variable object.

    Verifies that the Variable object's __str__ method returns the expected
    string format with comma-separated values for name, option, and value.
    """
    var = bd_lexer.Variable("my_file", "option", "c:\\path\\to\\file.txt")

    expected_str = "my_file, option, c:\\path\\to\\file.txt"

    assert expected_str == var.__str__()


@pytest.mark.parametrize(
    "input_text, throws_exception",
    [
        (
            r"""sources {
            source1 = "some_file.txt" (id =2,id2 = 3);
        }""",
            True,
        ),
        (
            r"""sources {
            source1 = "some_file.txt" (id = 0);
        }""",
            True,
        ),
        (
            r"""sources {
            source1 = "some_file.txt" ();
        }""",
            True,
        ),
        (
            r"""sources {
            source1 = "some_file.txt";
        }""",
            False,
        ),
    ],
)
def test_source_def_attr_list(input_text: str, throws_exception: bool) -> None:
    """Test that parser stops parsing when attribute lists in sources block are used.

    Attribute lists in sources block are not supported for now, so the parser
    should throw an exception when encountering them.

    :param input_text: Input text to be parsed by the BD parser.
    :param throws_exception: Flag indicating whether an exception should be thrown during parsing.
    :raises SPSDKError: When parser encounters unsupported attribute lists in sources block.
    """
    parser = bd_parser.BDParser()

    try:
        retval = parser.parse(text=input_text)
        exception_thrown = False
        assert retval is not None
    except SPSDKError:
        exception_thrown = True

    assert exception_thrown == throws_exception


@pytest.mark.parametrize(
    "input_text, throws_exception, extern",
    [
        (
            r"""sources {
           source = extern(0);
       }""",
            True,
            None,
        ),
        (
            r"""sources {
           source = extern(0);
       }""",
            False,
            ["some_file.txt"],
        ),
    ],
)
def test_extern(input_text: str, throws_exception: bool, extern: Optional[list[str]]) -> None:
    """Test that BD parser handles extern() function calls correctly.

    Validates that the parser properly stops execution when extern() function
    references non-existing entries and throws appropriate exceptions.

    :param input_text: BD script text content to parse.
    :param throws_exception: Expected exception behavior flag.
    :param extern: Optional list of external entry names to reference.
    :raises SPSDKError: When parser encounters invalid extern references.
    """
    parser = bd_parser.BDParser()

    try:
        retval = parser.parse(text=input_text, extern=extern)
        exception_thrown = False
        assert retval is not None
    except SPSDKError:
        exception_thrown = True

    assert exception_thrown == throws_exception


@pytest.mark.parametrize(
    "input_text, throws_exception",
    [
        (
            r"""section (0;) {

        }""",
            False,
        ),
        (
            r"""section (1;id=5) {

        }""",
            False,
        ),
        (
            r"""section (1;id=5, bla=7) {

        }""",
            False,
        ),
    ],
)
def test_section_option_list(input_text: str, throws_exception: bool) -> None:
    """Test section option list parsing functionality.

    This test verifies that the BD parser correctly handles section option lists
    and throws exceptions when expected based on the input configuration.

    :param input_text: The BD file content text to be parsed by the parser.
    :param throws_exception: Flag indicating whether an exception is expected to be thrown during parsing.
    """
    parser = bd_parser.BDParser()

    try:
        retval = parser.parse(text=input_text)
        exception_thrown = False
        assert retval is not None
    except SPSDKError:
        exception_thrown = True

    assert exception_thrown == throws_exception


@pytest.mark.parametrize(
    "input_text, throws_exception",
    [
        (
            r"""
        sources {
            my_file = "file.txt";
        }
        section (2) <= my_file;""",
            True,
        )
    ],
)
def test_section_content1(input_text: str, throws_exception: bool) -> None:
    """Test BD parser section content parsing with exception handling.

    This test method validates the BD parser's ability to parse input text and
    verifies whether exceptions are thrown as expected. It checks both successful
    parsing scenarios and error conditions.

    :param input_text: The input text to be parsed by the BD parser.
    :param throws_exception: Flag indicating whether an exception is expected to be thrown during parsing.
    :raises AssertionError: When the actual exception behavior doesn't match the expected behavior.
    """
    parser = bd_parser.BDParser()

    try:
        retval = parser.parse(text=input_text)
        exception_thrown = False
        assert retval is not None
    except SPSDKError:
        exception_thrown = True

    assert exception_thrown == throws_exception


@pytest.mark.parametrize(
    "input_text, throws_exception",
    [
        (
            r"""
        sources {
            my_file = "some_file.txt";
        }
        section (2) {
            from my_file {

            }
        }""",
            True,
        )
    ],
)
def test_from_statement(input_text: str, throws_exception: bool) -> None:
    """Test parsing of from statement with exception handling.

    This test function verifies that the BDParser correctly handles from statements
    by parsing the input text and checking whether an exception is thrown as expected.

    :param input_text: The text containing from statement to be parsed by BDParser.
    :param throws_exception: Flag indicating whether an exception is expected to be thrown.
    :raises AssertionError: When the actual exception behavior doesn't match the expected behavior.
    """
    parser = bd_parser.BDParser()

    try:
        retval = parser.parse(text=input_text)
        exception_thrown = False
        assert retval is not None
    except SPSDKError:
        exception_thrown = True

    assert exception_thrown == throws_exception


@pytest.mark.parametrize(
    "input_text, throws_exception",
    [
        (
            r"""section (2) {
            if (true) {

            }
        }""",
            True,
        ),
        (
            r"""section (2) {
            if (false) {

            }
            else {

            }
        }""",
            True,
        ),
        (
            r"""
        section (3) {
            if (false) {

            } else if true {

            } else {

            }
        }""",
            True,
        ),
    ],
)
def test_if_stmt(input_text: str, throws_exception: bool) -> None:
    """Test if statement parsing with expected exception behavior.

    This test function verifies that the BD parser correctly handles if statements
    by parsing the input text and checking whether an exception is thrown as expected.

    :param input_text: The BD script text containing if statement to be parsed.
    :param throws_exception: Expected exception behavior - True if exception should be thrown, False otherwise.
    :raises AssertionError: When the actual exception behavior doesn't match the expected behavior.
    """
    parser = bd_parser.BDParser()

    try:
        retval = parser.parse(text=input_text)
        exception_thrown = False
        assert retval is not None
    except SPSDKError:
        exception_thrown = True

    assert exception_thrown == throws_exception


@pytest.mark.parametrize(
    "input_text, throws_exception",
    [
        (
            r"""sources {
            my_file = "test_file.txt";
        }
        section (0) {
            load my_file > 0x0;
        }""",
            False,
        ),
        (
            r"""sources {
            my_file = "test_file.txt";
        }
        section (1) {
            load file > 0x0;
        }""",
            True,
        ),
        (
            r"""section (2) {
            load "my_file.txt" > 0x0;
        }""",
            False,
        ),
        (
            r"""section (3) {
            load $.some_name > 0x0;
        }""",
            True,
        ),
        (
            r"""section (4) {
            load $.some_name, $.other_name > 0x0;
        }""",
            True,
        ),
        (
            r"""sources {
            my_file = "test_file.bin";
        }
        section (5) {
            load $.some_name, $.other_name from my_file;
        }""",
            True,
        ),
        (
            r"""section (6) {
            load {{00 aa bb cc ff}} > 0x0;
        }""",
            False,
        ),
        (
            r"""section (7) {
            load {{00 aa bb cc ff}} > .;
        }""",
            True,
        ),
        (
            r"""section (8) {
            load 0x00005555 > 0x0;
        }""",
            False,
        ),
        (
            r"""
        options {
            ident = "some_file.txt";
        }
        section (9) {
            load ident > 0x0;
        }""",
            True,
        ),
        (
            r"""
        section (10) {
            load ident > 0x0;
        }""",
            True,
        ),
        (
            r"""section (11) {
                load "some_file.txt";
            }""",
            True,
        ),
        (
            r"""section (12) {
                load ifr 0x10 > 0x50;
            }""",
            False,
        ),
        (
            r"""sources {
            s13_file = "test_file.bin";
        }
        section (13) {
            load ~ $.some_name from s13_file;
        }""",
            True,
        ),
        (
            r"""sources {
            s14_file = "test_file.bin";
        }
        section (14) {
            load s14_file? : some_identifier;
        }""",
            True,
        ),
    ],
)
def test_load_data(input_text: str, throws_exception: bool) -> None:
    """Test BD parser data loading functionality.

    This test function validates the BD parser's ability to parse input text
    and verifies that exceptions are thrown when expected. It checks both
    successful parsing scenarios and error conditions.

    :param input_text: The input text to be parsed by the BD parser.
    :param throws_exception: Flag indicating whether an exception is expected to be thrown during parsing.
    """
    parser = bd_parser.BDParser()

    try:
        retval = parser.parse(text=input_text)
        exception_thrown = False
        assert retval is not None
    except SPSDKError:
        exception_thrown = True

    assert exception_thrown == throws_exception


@pytest.mark.parametrize(
    "input_text, throws_exception",
    [
        (
            r"""
            section(0) {
                keystore_from_nv @9 0x08000800;
            }
            """,
            False,
        ),
        (
            r"""
            section(1) {
                keystore_to_nv @9 0x08000800;
            }
            """,
            False,
        ),
        (
            r"""
            constants {
                id1 = 5;
            }
            section(2) {
                keystore_to_nv id1 0x08000800;
            }
            """,
            False,
        ),
        (
            r"""
            constants {
                id1 = 5;
            }
            section(2) {
                keystore_to_nv 0x08000800;
            }
            """,
            False,
        ),
    ],
)
def test_keystore_from_to_nv(input_text: str, throws_exception: bool) -> None:
    """Test keystore from/to non-volatile memory operations.

    This test verifies the BD parser's ability to handle keystore operations
    with non-volatile memory, checking both successful parsing and expected
    exception scenarios.

    :param input_text: The BD script text to be parsed by the BD parser.
    :param throws_exception: Flag indicating whether the parsing should throw an exception.
    :raises SPSDKError: When parsing fails and throws_exception is True.
    """
    parser = bd_parser.BDParser()

    try:
        retval = parser.parse(text=input_text)
        exception_thrown = False
        assert retval is not None
    except SPSDKError:
        exception_thrown = True

    assert exception_thrown == throws_exception


@pytest.mark.parametrize(
    "input_text, throws_exception",
    [
        (
            r"""section (0) {
                erase all;
            }
            """,
            False,
        )
    ],
)
def test_erase_all(input_text: str, throws_exception: bool) -> None:
    """Test erase all command parsing functionality.

    This test verifies that the BD parser correctly handles erase all commands,
    checking both successful parsing scenarios and cases that should throw exceptions.

    :param input_text: The BD script text content to be parsed by the parser.
    :param throws_exception: Flag indicating whether parsing should raise an exception.
    """
    parser = bd_parser.BDParser()

    try:
        retval = parser.parse(text=input_text)
        exception_thrown = False
        assert retval is not None
    except SPSDKError:
        exception_thrown = True

    assert exception_thrown == throws_exception


@pytest.mark.parametrize(
    "input_text, throws_exception",
    [
        (
            r"""
            section(0) {
                call some_ident;
            }
            """,
            False,
        ),
        (
            r"""
            section(1) {
                call some_ident ();
            }
            """,
            False,
        ),
        (
            r"""
            section(2) {
                jump some_ident (5);
            }
            """,
            False,
        ),
        (
            r"""
            sources {
                f3 = "file.txt";
            }
            section(3) {
                call f3;
            }
            """,
            True,
        ),
        (
            r"""
            sources {
                f4 = "file.txt";
            }
            section(4) {
                call f4? : some_id;
            }
            """,
            True,
        ),
    ],
)
def test_call_stmt(input_text: str, throws_exception: bool) -> None:
    """Test BD parser call statement parsing functionality.

    This test function validates that the BD parser correctly handles call statements
    by parsing input text and verifying whether exceptions are thrown as expected.

    :param input_text: The BD script text containing call statement to be parsed
    :param throws_exception: Expected boolean indicating if parsing should raise an exception
    :raises AssertionError: When the actual exception behavior doesn't match expected behavior
    """
    parser = bd_parser.BDParser()

    try:
        retval = parser.parse(text=input_text)
        exception_thrown = False
        assert retval is not None
    except SPSDKError:
        exception_thrown = True

    assert exception_thrown == throws_exception


@pytest.mark.parametrize(
    "input_text, throws_exception",
    [
        (
            r"""
                section (0) {
                    jump_sp 5 5;
                }
            """,
            False,
        )
    ],
)
def test_jump_sp_stmt(input_text: str, throws_exception: bool) -> None:
    """Test jump stack pointer statement parsing functionality.

    This test verifies that the BD parser correctly handles jump stack pointer
    statements, validating both successful parsing scenarios and expected
    exception cases.

    :param input_text: The BD script text containing jump SP statement to parse.
    :param throws_exception: Flag indicating whether parsing should raise an exception.
    :raises SPSDKError: When parsing fails and throws_exception is True.
    """
    parser = bd_parser.BDParser()

    try:
        retval = parser.parse(text=input_text)
        exception_thrown = False
        assert retval is not None
    except SPSDKError:
        exception_thrown = True

    assert exception_thrown == throws_exception


@pytest.mark.parametrize(
    "input_text, throws_exception",
    [
        (
            r"""
                section (0) {
                    reset;
                }
            """,
            False,
        )
    ],
)
def test_reset_stmt(input_text: str, throws_exception: bool) -> None:
    """Test parsing of reset statement with exception handling.

    This test function validates the BDParser's ability to parse reset statements
    and verifies whether the parsing operation throws an exception as expected.

    :param input_text: The input text containing reset statement to be parsed
    :param throws_exception: Flag indicating whether an exception is expected during parsing
    :raises AssertionError: When the actual exception behavior doesn't match the expected behavior
    """
    parser = bd_parser.BDParser()

    try:
        retval = parser.parse(text=input_text)
        exception_thrown = False
        assert retval is not None
    except SPSDKError:
        exception_thrown = True

    assert exception_thrown == throws_exception


@pytest.mark.parametrize(
    "input_text, throws_exception",
    [
        (
            r"""
            sources {
                s0 = "some_source.bin";
            }
            section (0) {
                from s0 {

                }
            }
            """,
            True,
        ),
        (
            r"""
            sources {
                s1 = "some_source.bin";
            }
            section (1) {
                from s1 {
                    load $.ocram.*;
                }
            }
            """,
            True,
        ),
        (
            r"""
            sources {
                s2 = "some_source.bin";
            }
            section (2) {
                from s2 {
                    erase all;
                    restart;
                }
            }
            """,
            True,
        ),
        (
            r"""
            sources {
                s3 = "some_source.bin";
            }
            section (3) {
                from s3 {
                    if 1 {
                        erase all;
                        reset;
                    }
                }
            }
            """,
            True,
        ),
    ],
)
def test_from_stmt(input_text: str, throws_exception: bool) -> None:
    """Test parsing of BD (Boot Data) statements with exception handling.

    This test function verifies that the BD parser correctly processes input text
    and throws exceptions when expected. It validates both successful parsing
    scenarios and error conditions.

    :param input_text: The BD statement text to be parsed by the parser.
    :param throws_exception: Flag indicating whether an exception is expected during parsing.
    :raises AssertionError: When the actual exception behavior doesn't match the expected behavior.
    """
    parser = bd_parser.BDParser()

    try:
        retval = parser.parse(text=input_text)
        exception_thrown = False
        assert retval is not None
    except SPSDKError:
        exception_thrown = True

    assert exception_thrown == throws_exception


@pytest.mark.parametrize(
    "input_text, throws_exception",
    [
        (
            r"""
            section (0) {
                mode 1;
            }
            """,
            True,
        )
    ],
)
def test_mode_stmt(input_text: str, throws_exception: bool) -> None:
    """Test parsing of mode statement with exception handling.

    This test function verifies that the BD parser correctly handles mode statements
    and throws exceptions when expected. It parses the input text and compares
    whether an exception was thrown against the expected behavior.

    :param input_text: The BD script text containing mode statement to parse.
    :param throws_exception: Expected exception behavior - True if exception should be thrown, False otherwise.
    :raises AssertionError: When the actual exception behavior doesn't match expected behavior.
    """
    parser = bd_parser.BDParser()

    try:
        retval = parser.parse(text=input_text)
        exception_thrown = False
        assert retval is not None
    except SPSDKError:
        exception_thrown = True

    assert exception_thrown == throws_exception


@pytest.mark.parametrize(
    "input_text, throws_exception",
    [
        (
            r"""
            section (0) {
                info "hello world";
            }
            """,
            True,
        ),
        (
            r"""
            section (0) {
                warning "hello world";
            }
            """,
            True,
        ),
        (
            r"""
            section (0) {
                error "hello world";
            }
            """,
            True,
        ),
    ],
)
def test_message_type(input_text: str, throws_exception: bool) -> None:
    """Test BD parser message type handling with exception validation.

    This test function validates that the BD parser correctly handles different
    input text formats and throws exceptions when expected. It parses the input
    text and verifies whether an SPSDKError exception is thrown matches the
    expected behavior.

    :param input_text: Input text to be parsed by the BD parser.
    :param throws_exception: Expected exception behavior - True if an exception should be thrown, False otherwise.
    :raises AssertionError: When the actual exception behavior doesn't match the expected behavior.
    """
    parser = bd_parser.BDParser()

    try:
        retval = parser.parse(text=input_text)
        exception_thrown = False
        assert retval is not None
    except SPSDKError:
        exception_thrown = True

    assert exception_thrown == throws_exception


@pytest.mark.parametrize(
    "input_text, throws_exception",
    [
        (
            r"""options {
                id = 1 < 1;
            }""",
            False,
        ),
        (
            r"""options {
                id = 1 <= 1;
            }""",
            False,
        ),
        (
            r"""options {
                id = 1 > 1;
            }""",
            False,
        ),
        (
            r"""options {
                id = 1 >= 1;
            }""",
            False,
        ),
        (
            r"""options {
                id = 1 == 1;
            }""",
            False,
        ),
        (
            r"""options {
                id = 1 != 1;
            }""",
            False,
        ),
        (
            r"""options {
                id = 1 && 1;
            }""",
            False,
        ),
        (
            r"""options {
                id = 1 || 1;
            }""",
            False,
        ),
        (
            r"""options {
                id = (1 > 1);
            }""",
            False,
        ),
        (
            r"""options {
                id = defined(id1);
            }""",
            False,
        ),
        (
            r"""sources {
                my_file = "test.txt";
            }
            options {
                id = id2 (my_file);
            }""",
            True,
        ),
        (
            r"""sources {
                my_file = "test.txt";
            }
            options {
                id = !1;
            }""",
            False,
        ),
    ],
)
def test_bool_expr(input_text: str, throws_exception: bool) -> None:
    """Test boolean expression parsing in BD parser.

    This test function validates that the BD parser correctly handles boolean expressions,
    either parsing them successfully or throwing expected exceptions based on the input.

    :param input_text: The boolean expression text to be parsed by the BD parser.
    :param throws_exception: Flag indicating whether the parsing should throw an exception.
    :raises AssertionError: When the actual exception behavior doesn't match expected behavior.
    """
    parser = bd_parser.BDParser()

    try:
        retval = parser.parse(text=input_text)
        exception_thrown = False
        assert retval is not None
    except SPSDKError:
        exception_thrown = True

    assert exception_thrown == throws_exception


@pytest.mark.parametrize(
    "input_text, throws_exception",
    [
        (
            r"""constants {
                id = 1 + 1;
            }""",
            False,
        ),
        (
            r"""constants {
                id = 1 - 1;
            }""",
            False,
        ),
        (
            r"""constants {
                id = 1 * 2;
            }""",
            False,
        ),
        (
            r"""constants {
                id = 4 / 2;
            }""",
            False,
        ),
        (
            r"""constants {
                id = 5 % 2;
            }""",
            False,
        ),
        (
            r"""constants {
                id = 1 != 1;
            }""",
            False,
        ),
        (
            r"""constants {
                id = 1 << 1;
            }""",
            False,
        ),
        (
            r"""constants {
                id = 8 >> 1;
            }""",
            False,
        ),
        (
            r"""constants {
                id = 1 & 1;
            }""",
            False,
        ),
        (
            r"""constants {
                id = 1 | 1;
            }""",
            False,
        ),
        (
            r"""constants {
                id = 10 ^ 1;
            }""",
            False,
        ),
        (
            r"""constants {
                id = 10.w;
                id = 10.b;
                id = 10.h;
            }""",
            False,
        ),
        (
            r"""constants {
                id = 10.w;
                id = 10.b;
                id = 10.h;
            }
            }""",
            True,
        ),
    ],
)
def test_expr(input_text: str, throws_exception: bool) -> None:
    """Test expression parsing with expected exception behavior.

    This test function validates that the BDParser correctly parses input text
    and throws exceptions when expected. It verifies both successful parsing
    scenarios and error conditions.

    :param input_text: The input text to be parsed by BDParser.
    :param throws_exception: Flag indicating whether an SPSDKError exception is expected.
    :raises AssertionError: When the actual exception behavior doesn't match the expected behavior.
    """
    parser = bd_parser.BDParser()

    try:
        retval = parser.parse(text=input_text)
        exception_thrown = False
        assert retval is not None
    except SPSDKError:
        exception_thrown = True

    assert exception_thrown == throws_exception


@pytest.mark.parametrize(
    "input_text, throws_exception",
    [
        (
            r"""
            sources {
                s0 = "some_file.txt";
            }
            section (0) {
                load sizeof (s0? : some_ident) > 0x0;
            }
            """,
            True,
        ),
        (
            r"""
            section (1) {
                load sizeof (some_id) > 0x0;
            }
            """,
            True,
        ),
    ],
)
def test_sizeof(input_text: str, throws_exception: bool) -> None:
    """Test sizeof operator parsing functionality.

    This test verifies that the BD parser correctly handles sizeof operator
    expressions and validates whether exceptions are thrown as expected.

    :param input_text: BD script text containing sizeof operator to parse
    :param throws_exception: Expected exception behavior - True if parsing should raise SPSDKError
    :raises AssertionError: When actual exception behavior doesn't match expected behavior
    """
    parser = bd_parser.BDParser()

    try:
        retval = parser.parse(text=input_text)
        exception_thrown = False
        assert retval is not None
    except SPSDKError:
        exception_thrown = True

    assert exception_thrown == throws_exception


@pytest.mark.parametrize(
    "input_text, throws_exception",
    [
        (
            r"""constants {
                opt = -1;
                id = +2;
            }""",
            False,
        )
    ],
)
def test_unary_expr(input_text: str, throws_exception: bool) -> None:
    """Test unary expression parsing functionality.

    This test function validates the BDParser's ability to parse unary expressions
    and verifies whether exceptions are thrown as expected based on the input.

    :param input_text: The text input to be parsed by the BDParser
    :param throws_exception: Flag indicating whether an exception is expected to be thrown
    """
    parser = bd_parser.BDParser()

    try:
        retval = parser.parse(text=input_text)
        exception_thrown = False
        assert retval is not None
    except SPSDKError:
        exception_thrown = True

    assert exception_thrown == throws_exception


def test_csf_sections() -> None:
    """Test CSF sections parsing in BD file compiler.

    Validates that the BD parser correctly processes CSF (Command Sequence File) sections
    with various security-related configurations including header settings, engine
    configuration, and unlock features. The test verifies proper parsing of options,
    constants, and multiple section types with their respective parameters.

    :raises SPSDKError: When BD file parsing fails due to invalid syntax or configuration.
    """
    """"""
    bd_file = r"""
    options {
        flags = 0x08;
        startAddress = 0x30000000;
        ivtOffset = 0x1000;
        initialLoadSize = 0x2000;
        entryPointAddress = 0x300024e1;
    }


    constants {
        SEC_CSF_HEADER              = 20;
        SEC_CSF_INSTALL_SRK         = 21;
        SEC_CSF_INSTALL_CSFK        = 22;
        SEC_CSF_INSTALL_NOCAK       = 23;
        SEC_CSF_AUTHENTICATE_CSF    = 24;
        SEC_CSF_INSTALL_KEY         = 25;
        SEC_CSF_AUTHENTICATE_DATA   = 26;
        SEC_CSF_INSTALL_SECRET_KEY  = 27;
        SEC_CSF_DECRYPT_DATA        = 28;
        SEC_NOP                     = 29;
        SEC_SET_MID                 = 30;
        SEC_SET_ENGINE              = 31;
        SEC_INIT                    = 32;
        SEC_UNLOCK                  = 33;
    }

    section (SEC_CSF_HEADER;
        Header_Version="4.2",
        Header_HashAlgorithm="sha256",
        Header_Engine="ANY",
        Header_EngineConfiguration=0,
        Header_CertificateFormat="x509",
        Header_SignatureFormat="CMS"
        )
    {
    }

    section (SEC_SET_ENGINE;
        SetEngine_HashAlgorithm = "sha256",
        SetEngine_Engine = "ANY",
        SetEngine_EngineConfiguration = "0")
    {
    }

    section (SEC_UNLOCK;
        Unlock_Engine = "SNVS",
        Unlock_Features = "ZMK WRITE"
        )
    {
    }
    """

    expected_result = {
        "options": {
            "flags": 8,
            "startAddress": 805306368,
            "ivtOffset": 4096,
            "initialLoadSize": 8192,
            "entryPointAddress": 805315809,
        },
        "sections": [
            {
                "section_id": 20,
                "options": [
                    {"Header_Version": "4.2"},
                    {"Header_HashAlgorithm": "sha256"},
                    {"Header_Engine": "ANY"},
                    {"Header_EngineConfiguration": 0},
                    {"Header_CertificateFormat": "x509"},
                    {"Header_SignatureFormat": "CMS"},
                ],
                "commands": [],
            },
            {
                "section_id": 31,
                "options": [
                    {"SetEngine_HashAlgorithm": "sha256"},
                    {"SetEngine_Engine": "ANY"},
                    {"SetEngine_EngineConfiguration": "0"},
                ],
                "commands": [],
            },
            {
                "section_id": 33,
                "options": [{"Unlock_Engine": "SNVS"}, {"Unlock_Features": "ZMK WRITE"}],
                "commands": [],
            },
        ],
    }

    parser = bd_parser.BDParser()

    try:
        result = parser.parse(bd_file)
        exception_thrown = False
        assert expected_result == result
    except SPSDKError:
        exception_thrown = True
    assert not exception_thrown


# TODO document from_stmt - change syntax to SOURCE_NAME
# TODO describe format of section name
# TODO load_data ::= int_const_expr identifier is not allowed!!!
