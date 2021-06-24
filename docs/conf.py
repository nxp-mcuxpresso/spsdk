# Configuration file for the Sphinx documentation builder.
#
# This file only contains a selection of the most common options. For a full
# list see the documentation:
# https://www.sphinx-doc.org/en/master/usage/configuration.html

# -- Path setup --------------------------------------------------------------

# If extensions (or modules to document with autodoc) are in another directory,
# add these directories to sys.path here. If the directory is relative to the
# documentation root, use os.path.abspath to make it absolute, like shown here.
#
import os
import sys
import spsdk

from recommonmark.transform import AutoStructify

sys.path.insert(0, os.path.abspath(".."))
sys.setrecursionlimit(1500)

# -- Project information -----------------------------------------------------

project = "SPSDK"
copyright = "2019-2021, NXP"
author = "NXP"

# The full version, including alpha/beta/rc tags
# version = f"{spsdk.__version__} {spsdk.__release__}"
version = f"{spsdk.__version__}"

# -- General configuration ---------------------------------------------------
master_doc = "index"
source_suffix = {
    ".rst": "restructuredtext",
    ".md": "markdown",
}
autodoc_mock_imports = ["hidapi", "hid"]

autoclass_content = "both"


# Add any Sphinx extension module names here, as strings. They can be
# extensions coming with Sphinx (named 'sphinx.ext.*') or your custom
# ones.
extensions = [
    "sphinx.ext.autodoc",
    "sphinx.ext.autosectionlabel",
    # 'sphinx_autodoc_annotation',
    "sphinx_autodoc_typehints",
    "sphinx.ext.todo",
    "recommonmark",
    "sphinx_click",
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
html_theme = "sphinx_rtd_theme"
html_logo = "_static/images/nxp_logo.jpg"
html_theme_options = {
    "collapse_navigation": True,
    "sticky_navigation": True,
    "navigation_depth": 4,
    "display_version": False,
    "prev_next_buttons_location": None,
}

# Add any paths that contain custom static files (such as style sheets) here,
# relative to this directory. They are copied after the builtin static files,
# so a file named "default.css" will overwrite the builtin "default.css".
html_static_path = ["_static"]

# These paths are either relative to html_static_path
# or fully qualified paths (eg. https://...)
html_css_files = [
    "css/nxp.css",
]

# app setup hook
def setup(app):
    app.add_config_value(
        "recommonmark_config",
        {
            "auto_toc_tree_section": "Contents",
            "enable_eval_rst": True,
        },
        True,
    )
    app.add_transform(AutoStructify)
