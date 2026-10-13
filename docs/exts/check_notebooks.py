#!/usr/bin/env python
#
# Copyright 2026 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""SPSDK documentation build extension checking that notebooks are in a toctree.

This Sphinx extension fails the documentation build if any Jupyter notebook
(``*.ipynb``) source file is not referenced from a ``toctree`` (i.e. it is not
reachable from the documentation index). This prevents notebooks from being
silently omitted from the rendered documentation.

A notebook can be intentionally excluded from this check by marking it with the
``:orphan:`` file-wide metadata field.
"""

from typing import Any

from sphinx.application import Sphinx
from sphinx.environment import BuildEnvironment
from sphinx.errors import SphinxError

NOTEBOOK_SUFFIX = ".ipynb"


def check_notebooks_in_toctree(app: Sphinx, env: BuildEnvironment) -> None:
    """Verify that every notebook document is referenced from a toctree.

    This is connected to the ``env-check-consistency`` event. It collects every
    notebook document known to the build environment and raises an error if any
    of them is not included in a toctree, unless the notebook is explicitly
    marked as ``:orphan:``.

    :param app: The Sphinx application object.
    :param env: The Sphinx build environment.
    :raises SphinxError: If one or more notebooks are not referenced by any toctree.
    """
    # Build the set of documents that are reachable through any toctree.
    included = set()
    for includes in env.toctree_includes.values():
        included.update(includes)

    root_doc = env.config.root_doc

    missing = []
    for docname in sorted(env.found_docs):
        if not env.doc2path(docname, base=False).endswith(NOTEBOOK_SUFFIX):
            continue
        if docname == root_doc:
            continue
        if "orphan" in env.metadata.get(docname, {}):
            continue
        if docname not in included:
            missing.append(docname)

    if missing:
        listed = "\n".join(f"  - {docname}{NOTEBOOK_SUFFIX}" for docname in missing)
        raise SphinxError(
            "The following Jupyter notebook(s) are not referenced from any toctree "
            "(index). Add each notebook to an appropriate 'index.rst' toctree, or "
            "mark it with the ':orphan:' metadata field to exclude it intentionally:\n"
            f"{listed}"
        )


def setup(app: Sphinx) -> dict[str, Any]:
    """Set up the Sphinx extension checking notebooks are in a toctree.

    :param app: The Sphinx application object used for extension registration.
    :return: Extension metadata dictionary.
    """
    app.connect("env-check-consistency", check_notebooks_in_toctree)
    return {
        "parallel_read_safe": True,
        "parallel_write_safe": True,
    }
