#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# Copyright 2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""SPSDK Docstring Updater for automated docstring management.

This module provides tools for automatically adding, updating, and checking
docstrings in Python source files using external API services. It supports
both interactive and batch processing modes for maintaining consistent
documentation across SPSDK codebase.
"""

import argparse
import ast
import logging
import os
import re
import sys
from pathlib import Path
from typing import Optional, Union

try:
    from cody_api_client import send_prompt_to_cody
except ImportError:
    sys.exit("Could not import send_prompt_to_cody from cody_api_client")

# Configure logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
LOGGER = logging.getLogger(__name__)


class MethodInfo:
    """SPSDK Method Information Container.

    This class represents metadata about a Python method extracted from source code,
    including its signature, body content, location, and existing documentation.
    Used by docstring analysis and update tools to process method definitions.
    """

    def __init__(
        self,
        name: str,
        signature: str,
        body: str,
        start_line: int,
        end_line: int,
        current_docstring: Optional[str] = None,
    ):
        """Initialize a method representation object.

        Creates a new instance to store method information including its name,
        signature, body content, and location within the source file.

        :param name: The name of the method.
        :param signature: The complete method signature including parameters and type hints.
        :param body: The method body content as a string.
        :param start_line: The line number where the method starts in the source file.
        :param end_line: The line number where the method ends in the source file.
        :param current_docstring: The existing docstring of the method, if any.
        """
        self.name = name
        self.signature = signature
        self.body = body
        self.start_line = start_line
        self.end_line = end_line
        self.current_docstring = current_docstring


class DocstringUpdater:
    """SPSDK Docstring Updater for Python source files.

    This class provides automated docstring generation and updating capabilities
    for Python methods and functions within the SPSDK project. It analyzes Python
    source code, identifies methods that need documentation, and generates
    properly formatted docstrings following SPSDK conventions using AI assistance.
    """

    def __init__(self, target_directory: str, dry_run: bool = False):
        """Initialize the docstring updater for SPSDK methods.

        Sets up the target directory path and dry run mode, then gathers
        the SPSDK context information needed for docstring updates.

        :param target_directory: Path to the directory containing files to update.
        :param dry_run: If True, only simulate changes without writing files.
        """
        self.target_directory = Path(target_directory)
        self.dry_run = dry_run
        self.spsdk_context = self._gather_spsdk_context()

    def _gather_spsdk_context(self) -> str:
        """Gather context about SPSDK project structure and conventions.

        This method creates a comprehensive context string that includes project information,
        docstring style guidelines, and examples for use in documentation generation tools.

        :return: Formatted context string containing SPSDK project information and style guidelines.
        """
        context_parts = [
            "SPSDK (Secure Provisioning SDK) Project Context:",
            "",
            "SPSDK is a unified, reliable, and easy-to-use SW library working across",
            "NXP MCU portfolio providing strong foundation from quick customer",
            "prototyping up to production deployment.",
            "",
            "Docstring Style Guidelines:",
            "- Use triple quotes with proper indentation",
            "- Start with a brief one-line description",
            "- Add detailed description if needed (separated by blank line)",
            "- Document all parameters with :param name: description",
            "- Document return values with :return: description",
            "- Document exceptions with :raises ExceptionType: description",
            "- Use proper type hints in function signatures",
            "",
            "Example of good SPSDK docstring:",
            '"""Get common data file path.',
            "",  # <- Empty line after title
            "The method counts also with restricted data source and any other addons.",
            "",  # <- Empty line after description
            ":param path: Relative path in common data folder.",
            ":raises SPSDKValueError: Non existing file path.",
            ":return: Final absolute path to data file.",
            '"""',
        ]
        return "\n".join(context_parts)

    def find_python_files(self) -> list[Path]:
        """Find all Python files in the target directory and subdirectories.

        The method recursively walks through the target directory, filtering out
        common non-source directories like .git, __pycache__, build, dist, etc.
        Only Python files with .py extension that don't start with a dot are included.

        :return: List of Path objects representing found Python files.
        """
        python_files = []

        for root, dirs, files in os.walk(self.target_directory):
            # Skip common non-source directories
            dirs[:] = [
                d
                for d in dirs
                if d
                not in {
                    ".git",
                    "__pycache__",
                    ".pytest_cache",
                    "build",
                    "dist",
                    ".tox",
                    "venv",
                    "env",
                }
            ]

            for file in files:
                if file.endswith(".py") and not file.startswith("."):
                    python_files.append(Path(root) / file)

        LOGGER.info(f"Found {len(python_files)} Python files to process")
        return python_files

    def extract_methods_from_file(self, file_path: Path) -> list[MethodInfo]:
        """Extract all methods from a Python file.

        Parses the given Python file using AST and extracts information about all
        function and async function definitions found in the file.

        :param file_path: Path to the Python file to analyze.
        :raises Exception: Error processing the file (logged and empty list returned).
        :return: List of MethodInfo objects containing details about found methods.
        """
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                content = f.read()

            tree = ast.parse(content)
            methods = []
            lines = content.splitlines()

            for node in ast.walk(tree):
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    method_info = self._extract_method_info(node, lines)
                    if method_info:
                        methods.append(method_info)

            LOGGER.info(f"Found {len(methods)} methods in {file_path}")
            return methods

        except Exception as e:
            LOGGER.error(f"Error processing file {file_path}: {e}")
            return []

    def _extract_method_info(
        self, node: Union[ast.FunctionDef, ast.AsyncFunctionDef], lines: list[str]
    ) -> Optional[MethodInfo]:
        """Extract information about a single method from AST node.

        Parses the AST node to extract method signature, body, line numbers,
        and existing docstring information for documentation analysis.

        :param node: AST node representing a function or async function definition.
        :param lines: List of source code lines from the file being analyzed.
        :return: MethodInfo object containing extracted method details, or None if extraction fails.
        """
        try:
            # Get method signature
            start_line = node.lineno - 1  # Convert to 0-based indexing
            end_line = node.end_lineno - 1 if node.end_lineno else start_line

            # Extract signature (function definition line)
            signature_lines = []
            current_line = start_line
            paren_count = 0
            in_signature = False

            while current_line <= min(end_line, len(lines) - 1):
                line = lines[current_line].strip()
                if "def " in line:
                    in_signature = True

                if in_signature:
                    signature_lines.append(lines[current_line])
                    paren_count += line.count("(") - line.count(")")
                    if paren_count == 0 and ":" in line:
                        break

                current_line += 1

            signature = "\n".join(signature_lines)

            # Extract method body
            body_lines = lines[start_line : end_line + 1]
            body = "\n".join(body_lines)

            # Check for existing docstring
            current_docstring = None
            if (
                node.body
                and isinstance(node.body[0], ast.Expr)
                and isinstance(node.body[0].value, ast.Constant)
                and isinstance(node.body[0].value.value, str)
            ):
                current_docstring = node.body[0].value.value

            return MethodInfo(
                name=node.name,
                signature=signature,
                body=body,
                start_line=start_line + 1,  # Convert back to 1-based for display
                end_line=end_line + 1,
                current_docstring=current_docstring,
            )

        except Exception as e:
            LOGGER.error(f"Error extracting method info for {node.name}: {e}")
            return None

    def generate_docstring_with_cody(
        self, method_info: MethodInfo, file_path: Path
    ) -> Optional[str]:
        """Generate or improve a docstring for a method using Cody API.

        This method sends a prompt to the Cody API containing the method information,
        current docstring (if any), and SPSDK formatting requirements. It processes
        the response to ensure proper SPSDK docstring formatting and removes any
        redundant documentation.

        :param method_info: Information about the method including name, body, and current docstring.
        :param file_path: Path to the file containing the method.
        :raises Exception: When communication with Cody API fails or response processing encounters an error.
        :return: Generated or improved docstring content, or None if current docstring is adequate or generation failed.
        """
        # Prepare the prompt for Cody
        prompt_parts = [
            self.spsdk_context,
            "",
            f"File: {file_path}",
            "",
            "Please analyze the following Python method and provide a proper SPSDK-style docstring.",
            "",
            "Method to analyze:",
            "",
            method_info.body,
            "",
            "",
        ]

        if method_info.current_docstring:
            prompt_parts.extend(
                [
                    "Current docstring:",
                    f'"""{method_info.current_docstring}"""',
                    "",
                    "Please improve this docstring to match SPSDK standards, or indicate if it's already good.",
                    "If the current docstring is already good, return 'DOCSTRING_OK'",
                ]
            )
        else:
            prompt_parts.append(
                "This method has no docstring. Please create one following SPSDK standards."
            )

        prompt_parts.extend(
            [
                "",
                "Requirements:",
                "- Follow the SPSDK docstring format shown in the context",
                "- Include proper parameter documentation with types",
                "- Document return values and exceptions",
                "- Keep descriptions clear and concise",
                "- IMPORTANT: Include empty lines after title and after description",
                "- DO NOT document return value if the function returns None",
                "- Only return the docstring content (without the triple quotes)",
                "- If the current docstring is already good, return 'DOCSTRING_OK', otherwise clean doc string text ",
                "    (no text more like thinking parts etc), because the response will ",
                "    be handled automatically by script ",
                "- MAXIMAL line length from including indent spaces is 100 characters",
            ]
        )

        prompt = "\n".join(prompt_parts)

        LOGGER.info(f"Requesting docstring for method: {method_info.name}")

        try:
            response = send_prompt_to_cody(prompt)
            if response and response.strip():
                # Clean up the response
                cleaned_response = response.strip()

                # Check if Cody says the docstring is already OK
                if "DOCSTRING_OK" in cleaned_response:
                    LOGGER.info(f"Docstring for {method_info.name} is already good")
                    return None

                # Remove any markdown code blocks if present
                # Remove any markdown code blocks if present
                cleaned_response = re.sub(
                    r"```[a-zA-Z]*\n?", "", cleaned_response, flags=re.MULTILINE
                )
                cleaned_response = re.sub(r"```\n?", "", cleaned_response)
                cleaned_response = re.sub(r"^[a-zA-Z]*\n", "", cleaned_response, flags=re.MULTILINE)
                cleaned_response = re.sub(r"\n$", "", cleaned_response)

                # Remove any triple quotes that might be included
                cleaned_response = cleaned_response.replace('"""', "")

                # Ensure proper SPSDK formatting
                cleaned_response = self._ensure_spsdk_formatting(cleaned_response)

                # Remove redundant None return documentation
                cleaned_response = self._remove_redundant_none_return(cleaned_response)

                return cleaned_response.strip()

            LOGGER.error(f"No response from Cody for method: {method_info.name}")
            return None

        except Exception as e:
            LOGGER.error(f"Error getting docstring from Cody for {method_info.name}: {e}")
            return None

    def _remove_redundant_none_return(self, docstring: str) -> str:
        """Remove redundant return documentation for None returns.

        This method filters out documentation lines that explicitly document None return values,
        as these are considered redundant in SPSDK documentation standards.

        :param docstring: The input docstring to process.
        :return: Cleaned docstring with redundant None return documentation removed.
        """
        lines = docstring.split("\n")
        filtered_lines = []

        for line in lines:
            stripped = line.strip()
            # Skip lines that document None returns
            if (
                stripped.startswith(":return: None")
                or stripped.startswith(":returns: None")
                or stripped == ":return: None."
                or stripped == ":returns: None."
                or stripped.lower()
                in [":return: none.", ":returns: none.", ":return: none", ":returns: none"]
            ):
                continue
            filtered_lines.append(line)

        return "\n".join(filtered_lines)

    def _ensure_spsdk_formatting(self, docstring: str) -> str:
        """Ensure the docstring follows SPSDK formatting with proper empty lines.

        This method processes a docstring to add proper empty lines after the title
        and before parameter sections according to SPSDK formatting standards.

        :param docstring: The input docstring to format.
        :return: Formatted docstring with proper SPSDK empty line structure.
        """
        lines = docstring.split("\n")
        if not lines:
            return docstring

        formatted_lines = []
        title = lines[0].strip()
        formatted_lines.append(title)

        # Always add empty line after title
        if len(lines) > 1 and lines[1].strip() != "":
            formatted_lines.append("")

        # Process remaining lines
        description_ended = False

        for line in lines[1:]:
            stripped = line.strip()

            # Detect start of parameters section
            if (
                stripped.startswith(":param")
                or stripped.startswith(":return")
                or stripped.startswith(":raises")
            ):
                if not description_ended and formatted_lines and formatted_lines[-1].strip() != "":
                    # Add empty line before parameters if not already there
                    formatted_lines.append("")
                description_ended = True

            formatted_lines.append(line)

        return "\n".join(formatted_lines)

    def update_method_docstring(
        self, file_path: Path, method_info: MethodInfo, new_docstring: str
    ) -> bool:
        """Update the docstring for a method in the file.

        This method handles the complete process of replacing or inserting a new docstring
        for a specified method. It parses the file to locate the method, handles multi-line
        function signatures, manages existing docstring removal, and inserts the new
        docstring with proper indentation.

        :param file_path: Path to the Python file containing the method to update.
        :param method_info: Information about the method including name, location, and current docstring.
        :param new_docstring: The new docstring content to insert or replace the existing one.
        :raises Exception: File I/O errors or parsing issues during docstring update.
        :return: True if the docstring was successfully updated, False otherwise.
        """
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                lines = f.readlines()

            # Find where to insert/replace the docstring
            method_start = method_info.start_line - 1  # Convert to 0-based

            # Look for the actual function definition line (skip decorators)
            func_def_line = method_start
            for i in range(method_start, min(method_start + 10, len(lines))):
                if "def " in lines[i]:
                    func_def_line = i
                    break

            # Find the ACTUAL end of the function signature (handle multi-line signatures)
            signature_end_line = func_def_line  # Initialize with func_def_line
            paren_count = 0
            found_def = False

            for i in range(func_def_line, min(func_def_line + 20, len(lines))):
                line = lines[i]

                # Count parentheses to track when signature is complete
                if "def " in line:
                    found_def = True

                if found_def:
                    paren_count += line.count("(") - line.count(")")

                    # When parentheses are balanced and we find a colon, signature is complete
                    if paren_count == 0 and ":" in line:
                        signature_end_line = i
                        break

            # If we couldn't find the end properly, fall back to simple detection
            if signature_end_line == func_def_line and ":" not in lines[func_def_line]:
                # Look for the first line with a colon after the def line
                for i in range(func_def_line, min(func_def_line + 20, len(lines))):
                    if ":" in lines[i]:
                        signature_end_line = i
                        break

            # The docstring should go right after the complete function signature
            insert_line = signature_end_line + 1

            # Skip any empty lines after the function signature
            while insert_line < len(lines) and lines[insert_line].strip() == "":
                insert_line += 1

            # Determine indentation from the method definition
            method_line = lines[func_def_line]
            base_indent = len(method_line) - len(method_line.lstrip())
            docstring_indent = " " * (base_indent + 4)  # Add 4 spaces for docstring

            # Format the new docstring
            docstring_lines = []
            docstring_lines.append(f'{docstring_indent}"""{new_docstring.splitlines()[0]}\n')

            # Add remaining lines of docstring
            for line in new_docstring.splitlines()[1:]:
                if line.strip():
                    docstring_lines.append(f"{docstring_indent}{line}\n")
                else:
                    docstring_lines.append(f"{docstring_indent}\n")

            docstring_lines.append(f'{docstring_indent}"""\n')

            # Remove existing docstring if present
            if method_info.current_docstring:
                # Find and remove the existing docstring lines
                quote_count = 0
                remove_start = insert_line
                remove_end = insert_line

                # Look for the start of existing docstring
                for i in range(insert_line, min(insert_line + 20, len(lines))):
                    line = lines[i].strip()
                    if line.startswith('"""') or line.startswith("'''"):
                        remove_start = i
                        quote_count = line.count('"""') + line.count("'''")

                        # If docstring starts and ends on same line
                        if quote_count >= 2:
                            remove_end = i + 1
                            break

                        # Look for closing quotes
                        for j in range(i + 1, min(i + 50, len(lines))):
                            next_line = lines[j].strip()
                            quote_count += next_line.count('"""') + next_line.count("'''")
                            if quote_count >= 2:
                                remove_end = j + 1
                                break
                        break

                # Remove the old docstring lines
                if remove_end > remove_start:
                    del lines[remove_start:remove_end]
                    insert_line = remove_start

            # Insert the new docstring
            for i, docstring_line in enumerate(docstring_lines):
                lines.insert(insert_line + i, docstring_line)

            if not self.dry_run:
                with open(file_path, "w", encoding="utf-8") as f:
                    f.writelines(lines)
                LOGGER.info(f"✅ Updated docstring for {method_info.name} in {file_path}")
            else:
                LOGGER.info(
                    f"🔍 [DRY RUN] Would update docstring for {method_info.name} in {file_path}"
                )
                # In dry run, show where we would insert
                LOGGER.debug(
                    f"Would insert docstring at line {insert_line + 1} for method {method_info.name}"
                )

            return True

        except Exception as e:
            LOGGER.error(f"Error updating docstring for {method_info.name} in {file_path}: {e}")
            return False

    def process_file(self, file_path: Path) -> None:
        """Process a single Python file to update method docstrings.

        This method performs a two-phase operation: first generates all docstrings
        for methods found in the file, then applies the updates from bottom to top
        to preserve line numbers during modification.

        :param file_path: Path to the Python file to process.
        :raises SPSDKError: When file processing or docstring generation fails.
        """
        LOGGER.info(f"Processing file: {file_path}")

        methods = self.extract_methods_from_file(file_path)

        if not methods:
            LOGGER.info(f"No methods found in {file_path}")
            return

        # Phase 1: Generate all docstrings first (no file modifications)
        LOGGER.info(f"Phase 1: Generating docstrings for {len(methods)} methods...")
        docstring_updates = []

        for method_info in methods:
            LOGGER.info(f"Generating docstring for method: {method_info.name}")

            new_docstring = self.generate_docstring_with_cody(method_info, file_path)

            if new_docstring:
                docstring_updates.append((method_info, new_docstring))
                LOGGER.info(f"✅ Generated docstring for {method_info.name}")
            else:
                LOGGER.info(f"⏭️  No changes needed for {method_info.name}")

        # Phase 2: Apply all updates from bottom to top (preserves line numbers)
        if docstring_updates:
            # Sort by line number in descending order (last method first)
            docstring_updates.sort(key=lambda x: x[0].start_line, reverse=True)

            LOGGER.info(
                f"Phase 2: Applying {len(docstring_updates)} docstring updates from bottom to top..."
            )

            for method_info, new_docstring in docstring_updates:
                LOGGER.info(
                    f"Updating docstring for {method_info.name} at line {method_info.start_line}"
                )

                success = self.update_method_docstring(file_path, method_info, new_docstring)
                if success:
                    LOGGER.info(f"✅ Successfully updated {method_info.name}")
                else:
                    LOGGER.error(f"❌ Failed to update {method_info.name}")
        else:
            LOGGER.info("No docstring updates needed for this file")

    def run(self) -> None:
        """Run the docstring updater on all Python files.

        Processes all Python files in the target directory, updating their docstrings
        according to SPSDK standards. Logs progress and handles errors gracefully.
        If the target directory doesn't exist, logs an error and returns early.

        :raises SPSDKError: When critical processing errors occur.
        """
        if not self.target_directory.exists():
            LOGGER.error(f"Target directory does not exist: {self.target_directory}")
            return

        python_files = self.find_python_files()

        if not python_files:
            LOGGER.warning("No Python files found to process")
            return

        LOGGER.info(f"Starting docstring update process for {len(python_files)} files")

        for file_path in python_files:
            try:
                self.process_file(file_path)
            except Exception as e:
                LOGGER.error(f"Error processing file {file_path}: {e}")
                continue

        LOGGER.info("✅ Docstring update process completed")


def main() -> None:
    """Main entry point for the docstring updater tool.

    Parses command line arguments, validates the target path (directory or file), and runs
    the DocstringUpdater to process Python files. Handles user interruption
    and unexpected errors gracefully.

    :raises SystemExit: When path validation fails or unexpected errors occur.
    """
    parser = argparse.ArgumentParser(
        description="Update Python docstrings using Cody API",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
python docstring_updater_methods.py /path/to/spsdk/source
python docstring_updater_methods.py ./spsdk --dry-run
python docstring_updater_methods.py ../project/src --verbose
python docstring_updater_methods.py single_file.py --dry-run
        """,
    )

    parser.add_argument("path", help="Directory or Python file to process")

    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Show what would be changed without making actual changes",
    )

    parser.add_argument("--verbose", "-v", action="store_true", help="Enable verbose logging")

    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    # Validate path
    if not os.path.exists(args.path):
        LOGGER.error(f"Path does not exist: {args.path}")
        sys.exit(1)

    # Check if it's a file or directory
    if os.path.isfile(args.path):
        # Single file processing
        if not args.path.endswith(".py"):
            LOGGER.error(f"File must be a Python file (.py): {args.path}")
            sys.exit(1)

        # Create updater with parent directory
        parent_dir = os.path.dirname(args.path) or "."
        updater = DocstringUpdater(parent_dir, dry_run=args.dry_run)

        try:
            updater.process_file(Path(args.path))
        except KeyboardInterrupt:
            LOGGER.info("Process interrupted by user")
            sys.exit(1)
        except Exception as e:
            LOGGER.error(f"Unexpected error: {e}")
            sys.exit(1)

    elif os.path.isdir(args.path):
        # Directory processing (existing behavior)
        updater = DocstringUpdater(args.path, dry_run=args.dry_run)

        try:
            updater.run()
        except KeyboardInterrupt:
            LOGGER.info("Process interrupted by user")
            sys.exit(1)
        except Exception as e:
            LOGGER.error(f"Unexpected error: {e}")
            sys.exit(1)
    else:
        LOGGER.error(f"Path is neither a file nor a directory: {args.path}")
        sys.exit(1)


if __name__ == "__main__":
    main()
