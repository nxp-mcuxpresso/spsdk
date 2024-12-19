#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2019-2024 NXP
#
# SPDX-License-Identifier: BSD-3-Clause
#
# Configuration file for the Sphinx documentation builder.
#
# This file only contains a selection of the most common options. For a full
# list see the documentation:
# https://www.sphinx-doc.org/en/master/usage/configuration.html

# -- Path setup --------------------------------------------------------------

import datetime
import logging
import os
import sys

import spsdk

# If extensions (or modules to document with autodoc) are in another directory,
# add these directories to sys.path here. If the directory is relative to the
# documentation root, use os.path.abspath to make it absolute, like shown here.
#

sys.path.insert(0, os.path.abspath(".."))
sys.path.append(os.path.abspath("exts"))

sys.setrecursionlimit(1500)
logging.basicConfig(level=logging.INFO)

# -- Project information -----------------------------------------------------

project = "SPSDK"
copyright = f"2019-{datetime.datetime.now().year}, NXP"
author = "NXP"

# The full version, including alpha/beta/rc tags
# version = f"{spsdk.__version__} {spsdk.__release__}"
version = f"{spsdk.__version__}"

# -- General configuration ---------------------------------------------------
master_doc = "index"
# source_suffix = {
#     ".rst": "restructuredtext",
#     ".md": "markdown",
# }

autoclass_content = "both"
suppress_warnings = ["autosectionlabel.*", "myst.header"]

autodoc_mock_imports = ["ftd2xx"]

# we don't want to execute notebooks during docs build because many of them require HW boards
nbsphinx_execute = "never"
nb_execution_mode = "off"

# Add any Sphinx extension module names here, as strings. They can be
# extensions coming with Sphinx (named 'sphinx.ext.*') or your custom
# ones.
extensions = [
    "copy_examples",
    "generate_schemas",
    "generate_table",
    "generate_apps_img",
    "generate_readme",
    "generate_project_struct_doc",
    "sphinx.ext.autodoc",
    "sphinx.ext.autosectionlabel",
    # 'sphinx_autodoc_annotation',
    "sphinx_autodoc_typehints",
    "sphinx.ext.todo",
    # "myst_parser",
    "sphinx_click",
    "nbsphinx",
    # "nbsphinx_link",
    "myst_nb",
]


# Add any paths that contain templates here, relative to this directory.
templates_path = ["_templates"]

# List of patterns, relative to source directory, that match files and
# directories to ignore when looking for source files.
# This pattern also affects html_static_path and html_extra_path.
exclude_patterns = ["_build", "Thumbs.db", ".DS_Store"]


# -- Options for HTML output -------------------------------------------------

# The theme to use for HTML and HTML Help pages.  See the documentation for
# a list of builtin themes.
#
html_theme = "sphinx_book_theme"
html_logo = "_static/images/nxp_logo.svg"
html_theme_options = {
    "repository_url": "https://github.com/nxp-mcuxpresso/spsdk",
    "use_repository_button": True,
    "collapse_navigation": True,
    # "sticky_navigation": True,
    "navigation_depth": 4,
    # "display_version": False,
    # "prev_next_buttons_location": None,
}

# Add any paths that contain custom static files (such as style sheets) here,
# relative to this directory. They are copied after the builtin static files,
# so a file named "default.css" will overwrite the builtin "default.css".
html_static_path = ["_static"]

# These paths are either relative to html_static_path
# or fully qualified paths (eg. https://...)
html_css_files = [
    "custom.css",
]

html_extra_path = ["html_schemas"]

# Myst extensions
myst_enable_extensions = ["html_image"]
