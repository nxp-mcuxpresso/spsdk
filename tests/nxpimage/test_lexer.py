#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2021-2023 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

import pytest

from spsdk.sbfile.sb2.sly_bd_lexer import BDLexer, Variable


class myToken:
    def __init__(self, t, value):
        self._values = {"type": t, "value": value}

    def __getitem__(self, item):
        return self._values[item]


def test_lexer():
    test_string = r"""
    false no true yes
    // some comment
    /* multiline
    comment
    */
    # bash style comment
    1.h 2.w 3.b
    _identifier identifier2 id3nt1f13r id_En_t1_f13R
    @9 @0x008
    10K 0x80 0X1122 'abc'
    $section.section_name $section.[abc] $section* $section[^abc]?
    {{00 aa bb 11}} {{22Af1C}}
    +-*/%|&~^<<>>||&&!<><=>===!=
    "string literal"
    ..
    =
    ,.;:
    {}()
    ?
    $
    1_invalid
    """

    expected_tokens = [
        myToken("INT_LITERAL", 0),
        myToken("INT_LITERAL", 0),
        myToken("INT_LITERAL", 1),
        myToken("INT_LITERAL", 1),
        myToken("INT_LITERAL", 1),
        myToken("PERIOD", "."),
        myToken("INT_SIZE", "h"),
        myToken("INT_LITERAL", 2),
        myToken("PERIOD", "."),
        myToken("INT_SIZE", "w"),
        myToken("INT_LITERAL", 3),
        myToken("PERIOD", "."),
        myToken("INT_SIZE", "b"),
        myToken("IDENT", "_identifier"),
        myToken("IDENT", "identifier2"),
        myToken("IDENT", "id3nt1f13r"),
        myToken("IDENT", "id_En_t1_f13R"),
        myToken("@", "@"),
        myToken("INT_LITERAL", 9),
        myToken("@", "@"),
        myToken("INT_LITERAL", 8),
        myToken("INT_LITERAL", 10240),
        myToken("INT_LITERAL", 128),
        myToken("INT_LITERAL", 4386),
        myToken("INT_LITERAL", 6382179),
        myToken("SECTION_NAME", "$section.section_name"),
        myToken("SECTION_NAME", "$section.[abc]"),
        myToken("SECTION_NAME", "$section*"),
        myToken("SECTION_NAME", "$section[^abc]?"),
        myToken("BINARY_BLOB", "00aabb11"),
        myToken("BINARY_BLOB", "22Af1C"),
        myToken("PLUS", "+"),
        myToken("MINUS", "-"),
        myToken("TIMES", "*"),
        myToken("DIVIDE", "/"),
        myToken("MOD", "%"),
        myToken("OR", "|"),
        myToken("AND", "&"),
        myToken("NOT", "~"),
        myToken("XOR", "^"),
        myToken("LSHIFT", "<<"),
        myToken("RSHIFT", ">>"),
        myToken("LOR", "||"),
        myToken("LAND", "&&"),
        myToken("LNOT", "!"),
        myToken("LT", "<"),
        myToken("GT", ">"),
        myToken("LE", "<="),
        myToken("GE", ">="),
        myToken("EQ", "=="),
        myToken("NE", "!="),
        myToken("STRING_LITERAL", '"string literal"'),
        myToken("RANGE", ".."),
        myToken("ASSIGN", "="),
        myToken("COMMA", ","),
        myToken("PERIOD", "."),
        myToken("SEMI", ";"),
        myToken("COLON", ":"),
        myToken("LBRACE", "{"),
        myToken("RBRACE", "}"),
        myToken("LPAREN", "("),
        myToken("RPAREN", ")"),
        myToken("QUESTIONMARK", "?"),
        myToken("DOLLAR", "$"),
        myToken("ERROR", "1"),
        myToken("IDENT", "_invalid"),
    ]

    lexer = BDLexer()

    for index, token in enumerate(lexer.tokenize(test_string)):
        print(
            token.type, expected_tokens[index]["type"], token.value, expected_tokens[index]["value"]
        )
        assert (
            token.type == expected_tokens[index]["type"]
            and token.value == expected_tokens[index]["value"]
        )


@pytest.mark.parametrize(
    "input_text, expected_result",
    [
        (r"""source_name""", myToken("SOURCE_NAME", "source_name")),
    ],
)
def test_source_name(input_text, expected_result):
    lexer = BDLexer()
    lexer._sources.append(Variable("source_name", "source", ""))

    tokgen = lexer.tokenize(text=input_text)

    t = next(tokgen)
    assert t.type == expected_result["type"]
    assert t.value == expected_result["value"]
