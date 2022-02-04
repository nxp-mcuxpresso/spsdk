#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2022 NXP
#
# SPDX-License-Identifier: BSD-3-Clause
# Script for generation of table
import yaml
import itertools
import os
from typing import Dict, List
from spsdk.exceptions import SPSDKValueError
from spsdk.utils.misc import get_key_by_val
from spsdk.image.mbimg import DEVICE_FILE

from pytablewriter import RstGridTableWriter

TARGET = 0
AUTHENTICATION = 1

DOC_PATH = os.path.dirname(os.path.realpath(__file__))
TABLE_DIR = os.path.join(DOC_PATH, "apps")
TABLE_FILE = os.path.join(TABLE_DIR, "table.inc")


def parse_database(database: str) -> Dict:
    """Parse YAML database and returns dict

    :param database: path to devices database
    :type database: str
    :return: dict with parsed YAML
    :rtype: Dict
    """
    with open(database, "r") as stream:
        device_cfg = yaml.safe_load(stream)
    return device_cfg


def get_targets(device_cfg: Dict) -> List[str]:
    """Get list of all targets from device databse

    :param device_cfg: dict with device database
    :type device_cfg: Dict
    :return: list with all targets
    :rtype: List[str]
    """
    targets = []
    for _, val in device_cfg["map_tables"]["targets"].items():
        targets.append(val[0])
    return targets


def get_authentications(device_cfg: Dict) -> List[str]:
    """Get all authentication types from the device database

    :param device_cfg: dict with device database
    :type device_cfg: Dict
    :return: list of all authentication types
    :rtype: List[str]
    """
    authentications = []
    for _, val in device_cfg["map_tables"]["authentication"].items():
        authentications.append(val[0])
    return authentications


def get_families(device_cfg: Dict) -> List[str]:
    """Get all families from the device database

    :param device_cfg: dict with device database
    :type device_cfg: Dict
    :return: list of all families
    :rtype: List[str]
    """
    families = []
    for key, _ in device_cfg["devices"].items():
        families.append(key)
    return families


def get_table_header(combinations: List[tuple]) -> List[str]:
    """Create header for the table

    :param combinations: combinations of targets x authentication type
    :type combinations: List[tuple]
    :return: list of header to be used with pytablewriter
    :rtype: List[str]
    """
    header = [i[TARGET] for i in combinations]
    header.insert(0, "Targets")

    return header


def write_table(header: List[str], values: List[List[str]]):
    """Write RST table to file using pytablewriter

    :param header: table header
    :type header: List[str]
    :param values: values to be writter
    :type values: List[List[str]]
    """
    writer = RstGridTableWriter(
        table_name="Supported devices",
        headers=header,
        value_matrix=values,
    )
    # writer.write_table()
    if not os.path.exists(TABLE_DIR):
        os.makedirs(TABLE_DIR)

    with open(TABLE_FILE, "w") as f:
        writer.stream = f
        writer.write_table()


def process_table(device_cfg: Dict):
    """Create table with matrix of supported devices
    vs image target and authentication types for the
    purpose of documentation

    :param device_cfg: device database
    :type device_cfg: Dict
    """
    targets = get_targets(device_cfg)
    authentications = get_authentications(device_cfg)
    families = get_families(device_cfg)
    print("Processing devices table")
    combinations = list(itertools.product(targets, authentications))
    value_matrix = []
    for f in families:
        submatrix = []
        submatrix.append(f)
        for c in combinations:
            try:
                target = get_key_by_val(c[TARGET], device_cfg["map_tables"]["targets"])
                authentication = get_key_by_val(
                    c[AUTHENTICATION], device_cfg["map_tables"]["authentication"]
                )
                family = f
                cls_name = device_cfg["devices"][family]["images"][target][authentication]
                reference = f":ref:`{cls_name}`"
                submatrix.append(reference)
            except (KeyError, SPSDKValueError):
                submatrix.append("N/A")
                continue
        value_matrix.append(submatrix)

    auth_list = [f"*{i[AUTHENTICATION]}*" for i in combinations]
    auth_list.insert(0, "*Authentication*")
    value_matrix.insert(0, auth_list)
    header = get_table_header(combinations)
    write_table(header, value_matrix)
    print("Table has been written")


def main():
    device_cfg = parse_database(DEVICE_FILE)
    process_table(device_cfg)


if __name__ == "__main__":
    main()
