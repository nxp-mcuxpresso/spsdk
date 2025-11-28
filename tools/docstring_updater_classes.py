#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# Copyright 2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""SPSDK Class Docstring Updater for automated documentation management.

This module provides tools for automatically adding or checking class docstrings
using the Cody API. It analyzes Python source files to identify classes that
need documentation and can generate appropriate docstrings.
"""

import argparse
import ast
import logging
import os
import re
import sys
from pathlib import Path
from typing import Optional

try:
    from cody_api_client import send_prompt_to_cody
except ImportError:
    sys.exit("Could not import send_prompt_to_cody from cody_api_client")

# Configure logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
LOGGER = logging.getLogger(__name__)


class ClassInfo:
    """Container for metadata about a Python class discovered during code analysis.

    This class stores comprehensive information about a Python class including its
    structure, location, inheritance hierarchy, and members. It serves as a data
    transfer object for tools that analyze and process Python class definitions.
    """

    def __init__(
        self,
        name: str,
        signature: str,
        body: str,
        start_line: int,
        end_line: int,
        base_classes: list[str],
        methods: list[str],
        attributes: list[str],
        current_docstring: Optional[str] = None,
    ):
        """Initialize a class instance with metadata and structure information.

        Stores comprehensive information about a class including its signature, body content,
        location in source file, inheritance hierarchy, and contained methods and attributes.

        :param name: Name of the class.
        :param signature: Complete class signature including class declaration.
        :param body: Full body content of the class.
        :param start_line: Line number where the class definition starts.
        :param end_line: Line number where the class definition ends.
        :param base_classes: List of base class names that this class inherits from.
        :param methods: List of method names contained within this class.
        :param attributes: List of attribute names defined in this class.
        :param current_docstring: Existing docstring content if present.
        """
        self.name = name
        self.signature = signature
        self.body = body
        self.start_line = start_line
        self.end_line = end_line
        self.base_classes = base_classes
        self.methods = methods
        self.attributes = attributes
        self.current_docstring = current_docstring


class ClassDocstringUpdater:
    """SPSDK Class Docstring Updater.

    This class provides automated updating of class docstrings in Python files
    to conform with SPSDK documentation standards. It analyzes Python source
    files, extracts class definitions, and generates or updates docstrings
    following SPSDK conventions including proper formatting, structure, and
    content guidelines.
    """

    def __init__(self, target_directory: str, dry_run: bool = False):
        """Initialize the docstring updater for SPSDK classes.

        Sets up the target directory path, dry run mode, and gathers the SPSDK context
        for processing class docstrings according to SPSDK standards.

        :param target_directory: Path to the directory containing files to process.
        :param dry_run: If True, only simulate changes without modifying files.
        """
        self.target_directory = Path(target_directory)
        self.dry_run = dry_run
        self.spsdk_context = self._gather_spsdk_context()

    def _gather_spsdk_context(self) -> str:
        """Gather context about SPSDK project structure and conventions.

        This method collects comprehensive information about SPSDK project standards,
        including class docstring formatting guidelines, examples, and best practices
        for documentation within the SPSDK ecosystem.

        :return: Formatted context string containing SPSDK project information and docstring guidelines.
        """
        context_parts = [
            "SPSDK (Secure Provisioning SDK) Project Context:",
            "",
            "SPSDK is a unified, reliable, and easy-to-use SW library working across",
            "NXP MCU portfolio providing strong foundation from quick customer",
            "prototyping up to production deployment.",
            "",
            "Class Docstring Style Guidelines:",
            "- Use triple quotes with proper indentation",
            "- Start with a brief one-line description of the class purpose",
            "- Add detailed description if needed (separated by blank line)",
            "- Document class variables with :cvar name: description (only if relevant)",
            "- DO NOT document __init__ parameters (:param) - those belong in __init__ method",
            "- DO NOT document instance variables (:ivar) - those belong in __init__ method",
            "- DO NOT document exceptions (:raises) - those belong in individual methods",
            "- Use proper type hints in class definitions",
            "",
            "Example of good SPSDK class docstring:",
            '"""SPSDK Configuration Manager.',
            "",  # <- Empty line after title
            "This class manages configuration data for SPSDK operations including",
            "validation, loading, and processing of configuration files.",
            "",  # <- Empty line after description
            ":cvar DEFAULT_CONFIG: Default configuration template.",
            '"""',
            "",
            "Class docstrings should:",
            "- Explain the class purpose and responsibility",
            "- Describe what the class represents or manages",
            "- Document only class variables (:cvar) if they are important",
            "- Mention key functionality or usage patterns",
            "- Include usage examples for complex classes",
            "- Focus on the class as a whole, not individual method details",
            "- DO NOT document __init__ parameters (:param) - those belong in __init__ method",
            "- DO NOT document instance variables (:ivar) - those belong in __init__ method",
            "- DO NOT document exceptions (:raises) - those belong in individual methods",
        ]
        return "\n".join(context_parts)

    def find_python_files(self) -> list[Path]:
        """Find all Python files in the target directory and subdirectories.

        The method recursively walks through the target directory, excluding common
        non-source directories like .git, __pycache__, build, dist, etc. Only files
        with .py extension that don't start with a dot are included.

        :return: List of Path objects pointing to Python files found in the directory tree.
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

    def extract_classes_from_file(self, file_path: Path) -> list[ClassInfo]:
        """Extract all classes from a Python file.

        Parses the given Python file using AST and extracts information about
        all class definitions found within the file.

        :param file_path: Path to the Python file to analyze.
        :raises SPSDKError: Error processing the file (file not found, parsing errors, etc.).
        :return: List of ClassInfo objects containing details about each class found in the file.
        """
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                content = f.read()

            tree = ast.parse(content)
            classes = []
            lines = content.splitlines()

            for node in ast.walk(tree):
                if isinstance(node, ast.ClassDef):
                    class_info = self._extract_class_info(node, lines)
                    if class_info:
                        classes.append(class_info)

            LOGGER.info(f"Found {len(classes)} classes in {file_path}")
            return classes

        except Exception as e:
            LOGGER.error(f"Error processing file {file_path}: {e}")
            return []

    def _extract_class_info(self, node: ast.ClassDef, lines: list[str]) -> Optional[ClassInfo]:
        """Extract information about a single class from AST node.

        Parses the class definition to extract comprehensive information including
        signature, body content, inheritance hierarchy, methods, and attributes.
        Limits extraction to prevent performance issues with large classes.

        :param node: AST ClassDef node representing the class to analyze.
        :param lines: List of source code lines from the file being processed.
        :raises SPSDKError: Error during class information extraction.
        :return: ClassInfo object containing extracted class details, or None if extraction fails.
        """
        try:
            # Get class signature
            start_line = node.lineno - 1  # Convert to 0-based indexing
            end_line = node.end_lineno - 1 if node.end_lineno else start_line

            # Extract signature (class definition line)
            signature_lines = []
            current_line = start_line
            paren_count = 0
            in_signature = False

            while current_line <= min(end_line, len(lines) - 1):
                line = lines[current_line].strip()
                if "class " in line:
                    in_signature = True

                if in_signature:
                    signature_lines.append(lines[current_line])
                    paren_count += line.count("(") - line.count(")")
                    if ":" in line and (paren_count == 0 or "(" not in line):
                        break

                current_line += 1

            signature = "\n".join(signature_lines)

            # Extract class body (first 50 lines to avoid huge classes)
            body_end = min(end_line + 1, start_line + 50)
            body_lines = lines[start_line:body_end]
            body = "\n".join(body_lines)

            # Extract base classes
            base_classes = []
            for base in node.bases:
                if isinstance(base, ast.Name):
                    base_classes.append(base.id)
                elif isinstance(base, ast.Attribute):
                    base_classes.append(ast.unparse(base))

            # Extract method names
            methods = []
            for item in node.body:
                if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    methods.append(item.name)

            # Extract class attributes (from assignments and annotations)
            attributes = []
            for item in node.body:
                if isinstance(item, ast.Assign):
                    for target in item.targets:
                        if isinstance(target, ast.Name):
                            attributes.append(target.id)
                elif isinstance(item, ast.AnnAssign) and isinstance(item.target, ast.Name):
                    attributes.append(item.target.id)

            # Check for existing docstring
            current_docstring = None
            if (
                node.body
                and isinstance(node.body[0], ast.Expr)
                and isinstance(node.body[0].value, ast.Constant)
                and isinstance(node.body[0].value.value, str)
            ):
                current_docstring = node.body[0].value.value

            return ClassInfo(
                name=node.name,
                signature=signature,
                body=body,
                start_line=start_line + 1,  # Convert back to 1-based for display
                end_line=end_line + 1,
                base_classes=base_classes,
                methods=methods[:10],  # Limit to first 10 methods
                attributes=attributes[:10],  # Limit to first 10 attributes
                current_docstring=current_docstring,
            )

        except Exception as e:
            LOGGER.error(f"Error extracting class info for {node.name}: {e}")
            return None

    def generate_docstring_with_cody(self, class_info: ClassInfo, file_path: Path) -> Optional[str]:
        """Generate or improve a class docstring using Cody API.

        This method constructs a detailed prompt containing class information and sends it
        to the Cody API to generate a proper SPSDK-style docstring. It handles both cases
        where a class has no docstring and where an existing docstring needs improvement.

        :param class_info: Information about the class including name, methods, attributes, and current docstring.
        :param file_path: Path to the file containing the class.
        :raises Exception: When communication with Cody API fails.
        :return: Generated docstring content without triple quotes, or None if docstring is already adequate
            or generation fails.
        """
        # Prepare the prompt for Cody
        prompt_parts = [
            self.spsdk_context,
            "",
            f"File: {file_path}",
            "",
            "Please analyze the following Python class and provide a proper SPSDK-style docstring.",
            "",
            "Class to analyze:",
            "",
            class_info.body,
            "",
            f"Class name: {class_info.name}",
        ]

        if class_info.base_classes:
            prompt_parts.extend(
                [
                    f"Base classes: {', '.join(class_info.base_classes)}",
                ]
            )

        if class_info.methods:
            prompt_parts.extend(
                [
                    f"Key methods: {', '.join(class_info.methods)}",
                ]
            )

        if class_info.attributes:
            prompt_parts.extend(
                [
                    f"Class attributes: {', '.join(class_info.attributes)}",
                ]
            )

        prompt_parts.append("")

        if class_info.current_docstring:
            prompt_parts.extend(
                [
                    "Current docstring:",
                    f'"""{class_info.current_docstring}"""',
                    "",
                    "Please improve this docstring to match SPSDK standards, or indicate if it's already good.",
                    "If the current docstring is already good, return 'DOCSTRING_OK'",
                ]
            )
        else:
            prompt_parts.append(
                "This class has no docstring. Please create one following SPSDK standards."
            )

        prompt_parts.extend(
            [
                "",
                "Requirements:",
                "- Follow the SPSDK class docstring format shown in the context",
                "- Start with a clear, concise description of the class purpose",
                "- Explain what the class represents or manages",
                "- Document only class variables (:cvar) if they are important",
                "- DO NOT include :param documentation (belongs in __init__ method)",
                "- DO NOT include :ivar documentation (belongs in __init__ method)",
                "- DO NOT include :raises documentation (belongs in individual methods)",
                "- Keep descriptions clear and focused on the class responsibility",
                "- IMPORTANT: Include empty lines after title and after description",
                "- Only return the docstring content (without the triple quotes)",
                "- If the current docstring is already good, return 'DOCSTRING_OK', otherwise clean doc string text ",
                "    (no text more like thinking parts etc), because the response will ",
                "    be handled automatically by script ",
                "- Focus on the class purpose and overall functionality",
                "- MAXIMAL line length from including indent spaces is 100 characters",
                "- Preserve RST grid table formatting with proper empty lines before and after tables",
            ]
        )

        prompt = "\n".join(prompt_parts)

        LOGGER.info(f"Requesting docstring for class: {class_info.name}")

        try:
            response = send_prompt_to_cody(prompt)
            if response and response.strip():
                # Clean up the response
                cleaned_response = response.strip()

                # Check if Cody says the docstring is already OK
                if "DOCSTRING_OK" in cleaned_response:
                    LOGGER.info(f"Docstring for {class_info.name} is already good")
                    return None

                # Remove any markdown code blocks if present
                cleaned_response = re.sub(r"^[a-zA-Z]*\n", "", cleaned_response, flags=re.MULTILINE)
                cleaned_response = re.sub(r"\n$", "", cleaned_response)

                # Remove any triple quotes that might be included
                cleaned_response = cleaned_response.replace('"""', "")

                # Ensure proper SPSDK formatting and remove unwanted documentation
                cleaned_response = self._ensure_spsdk_formatting(cleaned_response)
                cleaned_response = self._remove_unwanted_documentation(cleaned_response)

                return cleaned_response.strip()

            LOGGER.error(f"No response from Cody for class: {class_info.name}")
            return None

        except Exception as e:
            LOGGER.error(f"Error getting docstring from Cody for {class_info.name}: {e}")
            return None

    def _remove_unwanted_documentation(self, docstring: str) -> str:
        """Remove unwanted documentation from class docstrings.

        This method filters out parameter, instance variable, exception, and return value
        documentation lines from docstrings, keeping only the main description content.

        :param docstring: The original docstring content to be filtered.
        :return: Cleaned docstring with documentation tags removed.
        """
        lines = docstring.split("\n")
        filtered_lines = []

        for line in lines:
            stripped = line.strip()
            # Skip lines that document parameters, instance variables, exceptions, or returns
            if (
                stripped.startswith(":param")
                or stripped.startswith(":ivar")
                or stripped.startswith(":raises")
                or stripped.startswith(":return")
                or stripped.startswith(":returns")
            ):
                continue
            filtered_lines.append(line)

        return "\n".join(filtered_lines)

    def _ensure_spsdk_formatting(self, docstring: str) -> str:
        """Ensure the docstring follows SPSDK formatting with proper empty lines.

        This method formats a docstring to comply with SPSDK standards by adding
        appropriate empty lines after the title and before documentation sections.
        It specifically handles :cvar documentation sections and ensures proper
        spacing throughout the docstring structure.

        :param docstring: The input docstring to be formatted.
        :return: Formatted docstring with proper SPSDK spacing and structure.
        """
        lines = docstring.split("\n")
        if not lines:
            return docstring

        formatted_lines = []
        title = lines[0].strip()
        formatted_lines.append(title)

        # Always add empty line after title if there's more content
        if len(lines) > 1 and lines[1].strip() != "":
            formatted_lines.append("")

        # Process remaining lines
        description_ended = False

        for line in lines[1:]:
            stripped = line.strip()

            # Detect start of documentation section (only cvar allowed)
            if stripped.startswith(":cvar"):
                if not description_ended and formatted_lines and formatted_lines[-1].strip() != "":
                    # Add empty line before documentation if not already there
                    formatted_lines.append("")
                description_ended = True

            formatted_lines.append(line)

        return "\n".join(formatted_lines)

    def update_class_docstring(
        self, file_path: Path, class_info: ClassInfo, new_docstring: str
    ) -> bool:
        """Update the docstring for a class in the file.

        This method locates the specified class in the source file, finds the appropriate
        position for the docstring (after the class signature), and either inserts a new
        docstring or replaces an existing one. It handles multi-line class definitions,
        decorators, and proper indentation formatting.

        :param file_path: Path to the Python source file to modify.
        :param class_info: Information about the class including name, location, and current docstring.
        :param new_docstring: The new docstring content to insert or replace with.
        :return: True if the docstring was successfully updated, False otherwise.
        """
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                lines = f.readlines()

            # Find where to insert/replace the docstring
            class_start = class_info.start_line - 1  # Convert to 0-based

            # Look for the actual class definition line (skip decorators)
            class_def_line = class_start
            for i in range(class_start, min(class_start + 10, len(lines))):
                if "class " in lines[i]:
                    class_def_line = i
                    break

            # Find the end of the class signature (handle multi-line class definitions)
            signature_end_line = class_def_line
            paren_count = 0
            found_class = False

            for i in range(class_def_line, min(class_def_line + 20, len(lines))):
                line = lines[i]

                if "class " in line:
                    found_class = True

                if found_class:
                    paren_count += line.count("(") - line.count(")")

                    # When parentheses are balanced and we find a colon, signature is complete
                    if ":" in line and (paren_count == 0 or "(" not in line):
                        signature_end_line = i
                        break

            # The docstring should go right after the complete class signature
            insert_line = signature_end_line + 1

            # Skip any empty lines after the class signature
            while insert_line < len(lines) and lines[insert_line].strip() == "":
                insert_line += 1

            # Determine indentation from the class definition
            class_line = lines[class_def_line]
            base_indent = len(class_line) - len(class_line.lstrip())
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
            if class_info.current_docstring:
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
                LOGGER.info(f"✅ Updated docstring for class {class_info.name} in {file_path}")
            else:
                LOGGER.info(
                    f"🔍 [DRY RUN] Would update docstring for class {class_info.name} in {file_path}"
                )
                # In dry run, show where we would insert
                LOGGER.debug(
                    f"Would insert docstring at line {insert_line + 1} for class {class_info.name}"
                )

            return True

        except Exception as e:
            LOGGER.error(
                f"Error updating docstring for class {class_info.name} in {file_path}: {e}"
            )
            return False

    def process_file(self, file_path: Path) -> None:
        """Process a single Python file to update class docstrings.

        Extracts all classes from the specified file, generates new docstrings using AI,
        and applies the updates in two phases: first generating all docstrings, then
        applying updates from bottom to top to preserve line numbers.

        :param file_path: Path to the Python file to process.
        """
        LOGGER.info(f"Processing file: {file_path}")

        classes = self.extract_classes_from_file(file_path)

        if not classes:
            LOGGER.info(f"No classes found in {file_path}")
            return

        # Phase 1: Generate all docstrings first (no file modifications)
        LOGGER.info(f"Phase 1: Generating docstrings for {len(classes)} classes...")
        docstring_updates = []

        for class_info in classes:
            LOGGER.info(f"Generating docstring for class: {class_info.name}")

            new_docstring = self.generate_docstring_with_cody(class_info, file_path)

            if new_docstring:
                docstring_updates.append((class_info, new_docstring))
                LOGGER.info(f"✅ Generated docstring for {class_info.name}")
            else:
                LOGGER.info(f"⏭️  No changes needed for {class_info.name}")

        # Phase 2: Apply all updates from bottom to top (preserves line numbers)
        if docstring_updates:
            # Sort by line number in descending order (last class first)
            docstring_updates.sort(key=lambda x: x[0].start_line, reverse=True)

            LOGGER.info(
                f"Phase 2: Applying {len(docstring_updates)} docstring updates from bottom to top..."
            )

            for class_info, new_docstring in docstring_updates:
                LOGGER.info(
                    f"Updating docstring for {class_info.name} at line {class_info.start_line}"
                )

                success = self.update_class_docstring(file_path, class_info, new_docstring)
                if success:
                    LOGGER.info(f"✅ Successfully updated {class_info.name}")
                else:
                    LOGGER.error(f"❌ Failed to update {class_info.name}")
        else:
            LOGGER.info("No docstring updates needed for this file")

    def run(self) -> None:
        """Run the class docstring updater on all Python files.

        Processes all Python files in the target directory, updating class docstrings
        according to SPSDK standards. Logs progress and handles errors gracefully
        for individual files without stopping the entire process.

        :raises SPSDKError: When critical processing errors occur.
        """
        if not self.target_directory.exists():
            LOGGER.error(f"Target directory does not exist: {self.target_directory}")
            return

        python_files = self.find_python_files()

        if not python_files:
            LOGGER.warning("No Python files found to process")
            return

        LOGGER.info(f"Starting class docstring update process for {len(python_files)} files")

        for file_path in python_files:
            try:
                self.process_file(file_path)
            except Exception as e:
                LOGGER.error(f"Error processing file {file_path}: {e}")
                continue

        LOGGER.info("✅ Class docstring update process completed")


def main() -> None:
    """Main entry point for the docstring updater tool.

    Parses command line arguments and executes the class docstring updating process
    for Python files in the specified directory or single file. Supports dry-run mode for preview
    and verbose logging for detailed output.

    :raises SystemExit: When path validation fails or unexpected errors occur.
    """
    parser = argparse.ArgumentParser(
        description="Update Python class docstrings using Cody API",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
python docstring_updater_classes.py /path/to/spsdk/source
python docstring_updater_classes.py ./spsdk --dry-run
python docstring_updater_classes.py ../project/src --verbose
python docstring_updater_classes.py single_file.py --dry-run
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
        updater = ClassDocstringUpdater(parent_dir, dry_run=args.dry_run)

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
        updater = ClassDocstringUpdater(args.path, dry_run=args.dry_run)

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
