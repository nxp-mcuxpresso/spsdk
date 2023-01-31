#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2021-2023 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

import pytest

import spsdk
import spsdk.sbfile.sb2.sly_bd_lexer as bd_lexer
import spsdk.sbfile.sb2.sly_bd_parser as bd_parser
from spsdk.sbfile.sb2.sb_21_helper import _validate_keyblob


def test_parser():
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
                    {"keystore_from_nv": {"mem_opt": 9, "address": 0x08000800, "length": 1}},
                    {"fill": {"pattern": 0xC0403006, "address": 0x10C000, "length": 1}},
                    {"enable": {"mem_opt": 0x9, "address": 0x10C000}},
                    {"erase": {"address": 0x8000000, "length": 0x300000}},
                    {"keystore_to_nv": {"mem_opt": 9, "address": 0x08000800, "length": 1}},
                    {
                        "encrypt": {
                            "keyblob_id": 0,
                            "load": {
                                "address": 0x08001000,
                                "file": "data/sb_sources/output_images/application_signed.bin",
                                "length": 1,
                            },
                        }
                    },
                    {
                        "keywrap": {
                            "keyblob_id": 0,
                            "load": {
                                "address": 0x08000000,
                                "values": "00000000000000000000000000000000",
                            },
                        }
                    },
                    {
                        "keywrap": {
                            "keyblob_id": 1,
                            "load": {
                                "address": 0x08000100,
                                "values": "00000000000000000000000000000000",
                            },
                        }
                    },
                    {
                        "keywrap": {
                            "keyblob_id": 2,
                            "load": {
                                "address": 0x08000200,
                                "values": "00000000000000000000000000000000",
                            },
                        }
                    },
                    {
                        "keywrap": {
                            "keyblob_id": 3,
                            "load": {
                                "address": 0x08000300,
                                "values": "00000000000000000000000000000000",
                            },
                        }
                    },
                    {
                        "load": {
                            "file": "data/sb_sources/input_images/rt500_oct_flash_fcb.bin",
                            "address": 0x08000400,
                            "length": 1,
                        }
                    },
                    {
                        "load": {
                            "file": "data/sb_sources/key_store/key_store_rt5xx.bin",
                            "address": 0x08000800,
                            "length": 1,
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
    except spsdk.SPSDKError:
        exception_thrown = True

    assert exception_thrown == False


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


encrypt = {"encrypt": {}}


def test_keyblob_validation():
    kb = _validate_keyblob(keyblobs, 0)

    assert kb != None

    kb = _validate_keyblob(keyblobs, 3)

    try:
        kb = _validate_keyblob(keyblobs, 2)
        assert False
    except:
        assert True


def test_parser_return_none():
    """Test verifies, that on error an exception is raised."""
    text = r"""nonsense"""

    parser = bd_parser.BDParser()

    try:
        retval = parser.parse(text=text)
        exception_thrown = False
        assert retval is not None
    except spsdk.SPSDKError:
        exception_thrown = True

    assert exception_thrown == True


def test_variable_str():
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
def test_source_def_attr_list(input_text, throws_exception):
    """Test, that parser stops parsing when attribute lists in sources block
    are used, as these are not supported for now."""
    parser = bd_parser.BDParser()

    try:
        retval = parser.parse(text=input_text)
        exception_thrown = False
        assert retval is not None
    except spsdk.SPSDKError:
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
def test_extern(input_text, throws_exception, extern):
    """Test, that parser stops when extern() function is used and tries to
    reference a non-existing entry."""
    parser = bd_parser.BDParser()

    try:
        retval = parser.parse(text=input_text, extern=extern)
        exception_thrown = False
        assert retval is not None
    except spsdk.SPSDKError:
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
            True,
        ),
        (
            r"""section (1;id=5, bla=7) {

        }""",
            True,
        ),
    ],
)
def test_section_option_list(input_text, throws_exception):
    parser = bd_parser.BDParser()

    try:
        retval = parser.parse(text=input_text)
        exception_thrown = False
        assert retval is not None
    except spsdk.SPSDKError:
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
def test_section_content1(input_text, throws_exception):
    parser = bd_parser.BDParser()

    try:
        retval = parser.parse(text=input_text)
        exception_thrown = False
        assert retval is not None
    except spsdk.SPSDKError:
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
def test_from_statement(input_text, throws_exception):
    parser = bd_parser.BDParser()

    try:
        retval = parser.parse(text=input_text)
        exception_thrown = False
        assert retval is not None
    except spsdk.SPSDKError:
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
def test_if_stmt(input_text, throws_exception):
    parser = bd_parser.BDParser()

    try:
        retval = parser.parse(text=input_text)
        exception_thrown = False
        assert retval is not None
    except spsdk.SPSDKError:
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
def test_load_data(input_text, throws_exception):
    parser = bd_parser.BDParser()

    try:
        retval = parser.parse(text=input_text)
        exception_thrown = False
        assert retval is not None
    except spsdk.SPSDKError:
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
def test_keystore_from_to_nv(input_text, throws_exception):
    parser = bd_parser.BDParser()

    try:
        retval = parser.parse(text=input_text)
        exception_thrown = False
        assert retval is not None
    except spsdk.SPSDKError:
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
def test_erase_all(input_text, throws_exception):
    parser = bd_parser.BDParser()

    try:
        retval = parser.parse(text=input_text)
        exception_thrown = False
        assert retval is not None
    except spsdk.SPSDKError:
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
def test_call_stmt(input_text, throws_exception):
    parser = bd_parser.BDParser()

    try:
        retval = parser.parse(text=input_text)
        exception_thrown = False
        assert retval is not None
    except spsdk.SPSDKError:
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
def test_jump_sp_stmt(input_text, throws_exception):
    parser = bd_parser.BDParser()

    try:
        retval = parser.parse(text=input_text)
        exception_thrown = False
        assert retval is not None
    except spsdk.SPSDKError:
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
def test_reset_stmt(input_text, throws_exception):
    parser = bd_parser.BDParser()

    try:
        retval = parser.parse(text=input_text)
        exception_thrown = False
        assert retval is not None
    except spsdk.SPSDKError:
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
def test_from_stmt(input_text, throws_exception):
    parser = bd_parser.BDParser()

    try:
        retval = parser.parse(text=input_text)
        exception_thrown = False
        assert retval is not None
    except spsdk.SPSDKError:
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
def test_mode_stmt(input_text, throws_exception):
    parser = bd_parser.BDParser()

    try:
        retval = parser.parse(text=input_text)
        exception_thrown = False
        assert retval is not None
    except spsdk.SPSDKError:
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
def test_message_type(input_text, throws_exception):
    parser = bd_parser.BDParser()

    try:
        retval = parser.parse(text=input_text)
        exception_thrown = False
        assert retval is not None
    except spsdk.SPSDKError:
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
def test_bool_expr(input_text, throws_exception):
    parser = bd_parser.BDParser()

    try:
        retval = parser.parse(text=input_text)
        exception_thrown = False
        assert retval is not None
    except spsdk.SPSDKError:
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
def test_expr(input_text, throws_exception):
    parser = bd_parser.BDParser()

    try:
        retval = parser.parse(text=input_text)
        exception_thrown = False
        assert retval is not None
    except spsdk.SPSDKError:
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
def test_sizeof(input_text, throws_exception):
    parser = bd_parser.BDParser()

    try:
        retval = parser.parse(text=input_text)
        exception_thrown = False
        assert retval is not None
    except spsdk.SPSDKError:
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
def test_unary_expr(input_text, throws_exception):
    parser = bd_parser.BDParser()

    try:
        retval = parser.parse(text=input_text)
        exception_thrown = False
        assert retval is not None
    except spsdk.SPSDKError:
        exception_thrown = True

    assert exception_thrown == throws_exception


# TODO document from_stmt - change syntax to SOURCE_NAME
# TODO describe format of section name
# TODO load_data ::= int_const_expr identifier is not allowed!!!
