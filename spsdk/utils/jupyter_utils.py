#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2024-2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""SPSDK Jupyter notebook utilities.

This module provides helper functions and utilities specifically designed
for use within Jupyter notebooks in the SPSDK context, including formatting,
display, and interactive features.
"""

import base64
import difflib
import logging
import re
import textwrap

from spsdk.crypto.hash import EnumHashAlgorithm, get_hash
from spsdk.exceptions import SPSDKNotImplementedError
from spsdk.utils.misc import load_configuration, load_text

logger = logging.getLogger(__name__)

try:
    import ipywidgets as widgets
    from IPython import get_ipython
    from IPython.display import HTML

    class YamlDiffWidget(widgets.VBox):
        """Jupyter widget for displaying YAML configuration differences.

        This widget provides an interactive interface for comparing user YAML configurations
        with template files, highlighting differences and displaying contextual comments.
        The widget supports toggling between different views and downloading configurations.

        :cvar MAX_LINE_LENGTH: Maximum line length for display formatting (160 characters).
        """

        MAX_LINE_LENGTH = 160  # make it 160 because comments are smaller

        def __init__(
            self,
            config: str = "diff_config.yaml",
        ) -> None:
            """Initialize the YamlDiffWidget.

            Creates a widget for displaying YAML configuration differences with interactive
            controls for toggling diff view and downloading configuration files.

            :param config: Path to YAML configuration file containing template, user config,
                           and optional comments for diff display.
            """
            super().__init__()

            self.config = config
            self.unique_id = get_hash(config.encode(), EnumHashAlgorithm.MD5).hex()

            diff_comments = load_configuration(config)
            custom_command: str = diff_comments.get("custom_command", "")
            if custom_command:
                self.execute_jupyter_cell(custom_command)
            self.template_yaml: str = load_text(diff_comments["template_yaml"])
            self.user_cfg_path = diff_comments["user_cfg"]
            self.user_cfg = load_text(diff_comments["user_cfg"])
            self.comments_dict: dict[str, str] = diff_comments.get("comments", {})

            # Initialize the widget with the diff content

            self.diff_widget = widgets.HTML()
            self.user_config_widget = self.show_user_config()

            self.toggle_button = widgets.Button(description="Show Diff")
            self.toggle_button.on_click(self.toggle_view)

            self.config_download_button = widgets.HTML(self.get_config_download_button_html())

            self.current_view = "hide"
            self.create_diff()

            self.children = [
                widgets.HTML("## Configuration"),
                self.toggle_button,
                self.user_config_widget,
                self.config_download_button,
            ]

        def __copy__(self):  # type: ignore
            """Implement shallow copy operation.

            This method is intentionally not implemented as copying this object
            is not supported.

            :raises SPSDKNotImplementedError: Always raised as copying is not supported.
            """
            raise SPSDKNotImplementedError()

        def __deepcopy__(self, memo):  # type: ignore
            """Prevent deep copying of this object.

            This method is intentionally not implemented to avoid deep copying operations
            on this object type, which may contain resources that should not be duplicated.

            :param memo: Dictionary used by deepcopy to track already copied objects.
            :raises SPSDKNotImplementedError: Always raised as deep copying is not supported.
            """
            raise SPSDKNotImplementedError()

        def toggle_view(self) -> None:
            """Toggle between different configuration views.

            Switches between three view states: diff view showing configuration differences,
            user config view displaying user configuration options, and hidden view with
            minimal interface. Updates the widget children and toggle button description
            accordingly.
            """
            if self.current_view == "diff":
                self.children = [
                    widgets.HTML("## User Configuration"),
                    self.toggle_button,
                    self.user_config_widget,
                ]
                self.current_view = "user"
                self.toggle_button.description = "Hide"
            elif self.current_view == "user":
                self.children = [
                    widgets.HTML("## Configuration"),
                    self.toggle_button,
                ]
                self.current_view = "hide"
                self.toggle_button.description = "Show Diff"
            else:
                self.create_diff()
                self.current_view = "diff"
                self.toggle_button.description = "Show User Config"

        def execute_jupyter_cell(self, cell_content: str) -> None:
            """Execute a Jupyter cell with the given content.

            This method attempts to execute code in a Jupyter notebook environment. If not running
            in a Jupyter environment, it prints a notification message instead.

            :param cell_content: The content of the Jupyter cell to execute.
            """
            ip = get_ipython()
            if ip:
                ip.run_cell(cell_content)
            else:
                print("Not in a Jupyter environment")

        @property
        def html(self) -> HTML:
            """Return the HTML representation of the YAML diff.

            :return: HTML widget containing the YAML diff.
            """
            return HTML(self.get_static_html())

        def highlight_yaml(self, line: str) -> str:
            """Apply basic YAML syntax highlighting to a line of text.

            The method processes YAML content by adding HTML span tags with CSS classes for syntax
            highlighting. It handles comments, keys, values, and list items with appropriate styling.

            :param line: The line of text to highlight.
            :return: The highlighted line of text with HTML span tags.
            """
            # Split the line into code and comment parts
            if "#" in line:
                code_part, comment_part = line.split("#", 1)
                comment_part = f'<span class="yaml-commented-line">#{comment_part}</span>'
            else:
                code_part = line
                comment_part = ""

            # Apply highlighting to the code part
            code_part = re.sub(r"^(\s*-\s*)", r'<span class="yaml-key">\1</span>', code_part)
            code_part = re.sub(r"^(\s*-\s*\w+):", r'<span class="yaml-key">\1</span>:', code_part)
            code_part = re.sub(r"^(\s*\w+):", r'<span class="yaml-key">\1</span>:', code_part)
            code_part = re.sub(r": (.+)$", r': <span class="yaml-value">\1</span>', code_part)

            return code_part + comment_part

        def add_comment_bubble(self, line: str) -> str:
            """Add a comment bubble to a line if a matching comment is found in the comments dictionary.

            The method searches for keys from the comments dictionary within the provided line. If a key
            is found and the line contains a colon but no existing comment (no '#'), it adds a styled
            HTML comment bubble to the line and applies text wrapping.

            :param line: The line of text to potentially add a comment to.
            :return: The line with a comment bubble added if applicable, otherwise the original line.
            """
            for key, comment in self.comments_dict.items():
                if key in line and ":" in line and "#" not in line:
                    line = (
                        f'{line} <span style="background-color: #FFFF00; border-radius: 5px;'
                        + f' padding: 2px 6px; margin-left: 5px; font-size: 0.8em;">{comment}</span>'
                    )
                    return textwrap.fill(line, width=self.MAX_LINE_LENGTH)
            return line

        # pylint: disable=line-too-long
        def get_static_html(self) -> str:
            """Generate interactive HTML representation of YAML configuration differences.

            Creates a complete HTML widget with CSS styling and JavaScript functionality that allows
            users to toggle between diff view and user configuration view. The HTML includes styled
            buttons, syntax highlighting for YAML content, and a download button for configuration.

            :return: Complete HTML string with embedded CSS, JavaScript, and content sections.
            """
            header = "<h3>Configuration Differences</h3>"
            button_html = (
                f'<button onclick="toggleView_{self.unique_id}()"'
                + f' id="toggleButton_{self.unique_id}">Show Diff</button>'
            )
            diff_content = self.diff_widget.value
            user_config_content = self.show_user_config().value
            config_download_button_html = self.get_config_download_button_html()

            css = (
                """
            <style>
                .yaml-diff { font-family: monospace; background-color: #f0f0f0; padding: 1em; border: 1px solid #c0c0c0; }
                .yaml-key { color: #0000CC; font-weight: bold; }
                .yaml-value { color: #006600; }
                .yaml-commented-line { color: #008800; }
                .yaml-list-item { color: #660066; }
                .diff-removed { background-color: #ffaaaa; }
                .diff-added { background-color: #aaffaa; }
                .yaml-comment {
                    background-color: #FF8C00;
                    color: #000000;
                    border-radius: 50%;
                    padding: 0 0.3em;
                    margin-left: 0.5em;
                    font-size: 0.8em;
                    cursor: help;
                    font-weight: bold;
                    text-shadow: 1px 1px 1px rgba(255, 255, 255, 0.7);
                }
                """
                + f"#toggleButton_{self.unique_id}"
                + """ {
                    background-color: #4CAF50;
                    border: none;
                    color: white;
                    padding: 10px 20px;
                    text-align: center;
                    text-decoration: none;
                    display: inline-block;
                    font-size: 16px;
                    margin: 4px 2px;
                    cursor: pointer;
                }
            </style>
            """
            )

            javascript = f"""
            <script>
            function toggleView_{self.unique_id}() {{
                var diffView = document.getElementById('diffView_{self.unique_id}');
                var userConfigView = document.getElementById('userConfigView_{self.unique_id}');
                var button = document.getElementById('toggleButton_{self.unique_id}');

                if (diffView.style.display === 'none' && userConfigView.style.display === 'none') {{
                    diffView.style.display = 'block';
                    userConfigView.style.display = 'none';
                    button.textContent = 'Show User Config';
                }} else if (diffView.style.display === 'block') {{
                    diffView.style.display = 'none';
                    userConfigView.style.display = 'block';
                    button.textContent = 'Hide';
                }} else {{
                    diffView.style.display = 'none';
                    userConfigView.style.display = 'none';
                    button.textContent = 'Show Diff';
                }}
            }}
            </script>
            """

            html_content = f"""
            {css}
            {javascript}
            <div class="yaml-diff-container">
            {header}
            {button_html}
            {config_download_button_html}
            <div id="diffView_{self.unique_id}" class="yaml-diff" style="display:none;">{diff_content}</div>
            <div id="userConfigView_{self.unique_id}" class="yaml-diff" style="display:none;">{user_config_content}</div>
            </div>
            """

            return html_content

        def get_config_download_button_html(self) -> str:
            """Generate HTML for configuration file download button.

            Creates an HTML anchor element with embedded base64-encoded configuration
            file content that allows users to download their current configuration
            as a YAML file through the browser.

            :raises FileNotFoundError: When the user configuration file doesn't exist.
            :raises UnicodeDecodeError: When the configuration file contains invalid UTF-8.
            :return: HTML string containing download button with embedded config data.
            """
            with open(self.user_cfg_path, "r", encoding="utf-8") as file:
                user_cfg_content = file.read()
            user_cfg_base64 = base64.b64encode(user_cfg_content.encode()).decode()
            download_button_html = f"""
            <a href="data:text/plain;base64,{user_cfg_base64}" download="user_config.yaml">
                <button style="background-color: #4CAF50; border: none; color: white; padding: 10px 20px; text-align: center; text-decoration: none; display: inline-block; font-size: 16px; margin: 4px 2px; cursor: pointer;">
                    Download Config
                </button>
            </a>
            """
            return download_button_html

        def create_diff(self) -> None:
            """Create and display the difference between the user's YAML and the template YAML.

            This method generates an HTML representation of the differences, with added
            syntax highlighting and comment bubbles. The diff is displayed in the
            diff_widget with removed lines highlighted in red and added lines in green.
            """
            template_lines = self.template_yaml.split("\n")
            user_lines = self.user_cfg.split("\n")

            differ = difflib.Differ()
            diff = list(differ.compare(template_lines, user_lines))

            highlighted_diff = []

            for line in diff:
                if line.startswith(" "):  # Unchanged line
                    highlighted_line = self.highlight_yaml(line[2:])
                    highlighted_diff.append(self.add_comment_bubble(highlighted_line))
                elif line.startswith("- "):  # Line only in template config
                    highlighted_line = self.highlight_yaml(line[2:])
                    if line[2:].strip().startswith("#"):  # Skip commented lines
                        highlighted_diff.append(highlighted_line)
                        continue

                    highlighted_diff.append(
                        f'<span class="diff-removed">{self.add_comment_bubble(highlighted_line)}</span>'
                    )
                elif line.startswith("+ "):  # Line only in user config
                    if line[2:].strip().startswith("#"):  # Skip commented lines
                        continue
                    highlighted_line = self.highlight_yaml(line[2:])
                    highlighted_diff.append(f'<span class="diff-added">{highlighted_line}</span>')

            diff_html = "<br>".join(highlighted_diff)
            self.diff_widget.value = f'<pre class="yaml-diff">{diff_html}</pre>'

        def show_user_config(self) -> widgets.HTML:
            """Display only the user configuration with YAML syntax highlighting.

            The method processes the user configuration by splitting it into lines,
            applying YAML syntax highlighting and comment bubbles to each line,
            then formats the result as HTML for display in Jupyter widgets.

            :return: HTML widget containing the formatted user configuration.
            """
            user_lines = self.user_cfg.split("\n")
            highlighted_lines = [
                self.add_comment_bubble(self.highlight_yaml(line)) for line in user_lines
            ]
            user_config_html = "<br>".join(highlighted_lines)
            return widgets.HTML(f'<pre class="yaml-diff">{user_config_html}</pre>')

except ImportError:
    logger.error(
        "Jupyter extras are not installed. "
        "Please install SPSDK with the 'examples' extras (pip install spsdk[examples])"
    )
