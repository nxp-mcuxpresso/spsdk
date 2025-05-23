#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause
import os
import pytest
from cookiecutter.main import cookiecutter

TEMPLATES = [
    "cookiecutter-spsdk-debug-probe-plugin.zip",
    "cookiecutter-spsdk-device-interface-plugin.zip",
    "cookiecutter-spsdk-sp-plugin.zip",
    "cookiecutter-spsdk-wpc-service-plugin.zip",
]


@pytest.mark.parametrize("template", TEMPLATES)
def test_cookiecutter_templates(pytestconfig, tmpdir, template: str):
    template_path = pytestconfig.rootpath.joinpath("examples", "plugins", "templates", template)
    project_dir = cookiecutter(
        str(template_path),
        no_input=True,
        output_dir=str(tmpdir),
    )
    assert os.path.isdir(project_dir)
    assert os.path.isfile(os.path.join(project_dir, "pyproject.toml"))
