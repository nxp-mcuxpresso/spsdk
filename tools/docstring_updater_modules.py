#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# Copyright 2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""SPSDK Module Docstring Updater for automated documentation management.

This module provides tools for automatically adding or checking module docstrings
across SPSDK codebase using external API services. It analyzes Python modules
and ensures they have proper documentation following SPSDK standards.
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


class ModuleInfo:
    """Python module metadata container.

    This class stores and manages metadata information about a Python module
    including its file path, docstring content, and structural elements like
    imports, classes, functions, and constants.
    """

    def __init__(
        self,
        file_path: Path,
        current_docstring: Optional[str] = None,
        imports: Optional[list[str]] = None,
        classes: Optional[list[str]] = None,
        functions: Optional[list[str]] = None,
        constants: Optional[list[str]] = None,
    ):
        """Initialize module information container.

        Store and manage information about a Python module including file path,
        docstring, and code elements.

        :param file_path: Path to the Python module file.
        :param current_docstring: Existing docstring of the module, if any.
        :param imports: List of import statements found in the module.
        :param classes: List of class names defined in the module.
        :param functions: List of function names defined in the module.
        :param constants: List of constant names defined in the module.
        """
        self.file_path = file_path
        self.current_docstring = current_docstring
        self.imports = imports or []
        self.classes = classes or []
        self.functions = functions or []
        self.constants = constants or []


class ModuleDocstringUpdater:
    """SPSDK Module Docstring Updater.

    This class provides automated updating of module-level docstrings in Python files
    within the SPSDK project. It analyzes existing Python modules, generates appropriate
    SPSDK-compliant docstrings using AI assistance, and updates files while maintaining
    proper formatting and project conventions.
    The updater can operate in dry-run mode for safe preview of changes and includes
    context-aware docstring generation based on module content analysis.
    """

    def __init__(self, target_directory: str, dry_run: bool = False):
        """Initialize the docstring updater for SPSDK modules.

        Sets up the target directory path, dry run mode, and gathers the SPSDK context
        for processing module docstrings.

        :param target_directory: Path to the directory containing modules to process.
        :param dry_run: If True, only simulate changes without modifying files.
        :raises SPSDKError: If target directory is invalid or SPSDK context gathering fails.
        """
        self.target_directory = Path(target_directory)
        self.dry_run = dry_run
        self.spsdk_context = self._gather_spsdk_context()

    def _gather_spsdk_context(self) -> str:
        """Gather context about SPSDK project structure and conventions.

        This method builds a comprehensive context string containing SPSDK project
        information, coding standards, and module docstring formatting guidelines
        that can be used for documentation generation or validation purposes.

        :return: Multi-line string containing SPSDK context information and style guidelines.
        """
        context_parts = [
            "SPSDK (Secure Provisioning SDK) Project Context:",
            "",
            "SPSDK is a unified, reliable, and easy-to-use SW library working across",
            "NXP MCU portfolio providing strong foundation from quick customer",
            "prototyping up to production deployment.",
            "",
            "Module Docstring Style Guidelines:",
            "- Module docstrings should be at the very top of the file (after shebang and encoding)",
            "- Use triple quotes with proper formatting",
            "- Start with a brief one-line description of the module's purpose",
            "- Add detailed description if needed (separated by blank line)",
            "- Describe the main functionality and components",
            "- Mention key classes, functions, or constants if relevant",
            "- Keep it concise but informative",
            "",
            "Example of good SPSDK module docstring:",
            '"""SPSDK Certificate management utilities.',
            "",
            "This module provides functionality for handling X.509 certificates,",
            "certificate chains, and certificate validation in SPSDK context.",
            '"""',
            "",
            "Module docstring should reflect the actual content and purpose of the module.",
        ]
        return "\n".join(context_parts)

    def find_python_files(self) -> list[Path]:
        """Find all Python files in the target directory and subdirectories.

        The method recursively walks through the target directory, filtering out
        common non-source directories like .git, __pycache__, build, etc., and
        collects all Python files with .py extension that don't start with a dot.

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

    def analyze_module(self, file_path: Path) -> Optional[ModuleInfo]:
        """Analyze a Python module and extract its structure.

        Parses the given Python file using AST to extract module-level information
        including docstring, imports, classes, functions, and constants. Private
        functions (starting with underscore) are excluded from the analysis.

        :param file_path: Path to the Python module file to analyze.
        :return: ModuleInfo object containing extracted structure information, or None if analysis fails.
        """
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                content = f.read()

            tree = ast.parse(content)

            # Extract module docstring
            module_docstring = None
            if (
                tree.body
                and isinstance(tree.body[0], ast.Expr)
                and isinstance(tree.body[0].value, ast.Constant)
                and isinstance(tree.body[0].value.value, str)
            ):
                module_docstring = tree.body[0].value.value

            # Extract module components
            imports = []
            classes = []
            functions = []
            constants = []

            for node in tree.body:
                if isinstance(node, ast.Import):
                    for alias in node.names:
                        imports.append(f"import {alias.name}")
                elif isinstance(node, ast.ImportFrom):
                    module_name = node.module or ""
                    names = [alias.name for alias in node.names]
                    imports.append(f"from {module_name} import {', '.join(names)}")
                elif isinstance(node, ast.ClassDef):
                    classes.append(node.name)
                elif isinstance(node, ast.FunctionDef):
                    # Skip private functions for documentation purposes
                    if not node.name.startswith("_"):
                        functions.append(node.name)
                elif isinstance(node, ast.Assign):
                    # Look for module-level constants (ALL_CAPS variables)
                    for target in node.targets:
                        if isinstance(target, ast.Name) and target.id.isupper():
                            constants.append(target.id)

            return ModuleInfo(
                file_path=file_path,
                current_docstring=module_docstring,
                imports=imports[:10],  # Limit to first 10 imports for context
                classes=classes,
                functions=functions,
                constants=constants,
            )

        except Exception as e:
            LOGGER.error(f"Error analyzing module {file_path}: {e}")
            return None

    def generate_module_docstring_with_cody(self, module_info: ModuleInfo) -> Optional[str]:
        """Generate or improve a module docstring using Cody API.

        Analyzes the provided module information and constructs a detailed prompt
        for the Cody API to generate an appropriate SPSDK-style module docstring.
        The method handles both cases where a module has an existing docstring
        that needs improvement and where no docstring exists.

        :param module_info: Complete information about the module including file path,
                           classes, functions, constants, imports, and current docstring
        :raises Exception: When Cody API communication fails or returns invalid response
        :return: Generated docstring content or None if current docstring is adequate
                 or if generation fails
        """
        # Prepare the prompt for Cody
        prompt_parts = [
            self.spsdk_context,
            "",
            f"File: {module_info.file_path}",
            f"Module name: {module_info.file_path.stem}",
            "",
            "Please analyze the following Python module and provide a proper SPSDK-style module docstring.",
            "",
            "Module structure analysis:",
        ]

        if module_info.classes:
            prompt_parts.extend(
                [
                    f"Classes found: {', '.join(module_info.classes)}",
                ]
            )

        if module_info.functions:
            prompt_parts.extend(
                [
                    f"Public functions found: {', '.join(module_info.functions)}",
                ]
            )

        if module_info.constants:
            prompt_parts.extend(
                [
                    f"Constants found: {', '.join(module_info.constants)}",
                ]
            )

        if module_info.imports:
            prompt_parts.extend(
                [
                    "",
                    "Key imports:",
                    *[f"  {imp}" for imp in module_info.imports[:5]],  # Show first 5 imports
                ]
            )

        prompt_parts.extend(
            [
                "",
                "",
            ]
        )

        if module_info.current_docstring:
            prompt_parts.extend(
                [
                    "Current module docstring:",
                    f'"""{module_info.current_docstring}"""',
                    "",
                    "Please improve this module docstring to match SPSDK standards, or indicate if it's already good.",
                    "If docs string already contains lists with classes, functions, imports, etc, remove them.",
                    "If the current docstring is already good, return 'DOCSTRING_OK'",
                ]
            )
        else:
            prompt_parts.append(
                "This module has no docstring. Please create one following SPSDK standards."
            )
        prompt_parts.extend(
            [
                "",
                "Requirements:",
                "- Follow the SPSDK module docstring format shown in the context",
                "- Start with a clear, concise one-line summary of the module's purpose",
                "- Add a blank line after the summary line if there's additional content",
                "- Include a more detailed description if the module is complex",
                "- List main classes and functions if they are significant",
                "- Keep it relevant to the actual module content",
                "- Include empty lines for proper formatting (PEP 257 compliance)",
                "- Only return the docstring content (without the triple quotes)",
                "- If the current docstring is already good, return 'DOCSTRING_OK', otherwise clean doc string text ",
                "    (no text more like thinking parts etc), because the response will ",
                "    be handled automatically by script ",
                "- Focus on what the module does, not implementation details",
                "- MAXIMAL line length from including indent spaces is 100 characters",
            ]
        )
        prompt = "\n".join(prompt_parts)

        LOGGER.info(f"Requesting module docstring for: {module_info.file_path.name}")

        try:
            response = send_prompt_to_cody(prompt)
            if response and response.strip():
                # Clean up the response
                cleaned_response = response.strip()

                # Check if Cody says the docstring is already OK
                if "DOCSTRING_OK" in cleaned_response:
                    LOGGER.info(
                        f"Module docstring for {module_info.file_path.name} is already good"
                    )
                    return None

                # Remove any markdown code blocks if present
                cleaned_response = re.sub(r"^[a-zA-Z]*\n", "", cleaned_response, flags=re.MULTILINE)
                cleaned_response = re.sub(r"\n$", "", cleaned_response)

                # Remove any triple quotes that might be included
                cleaned_response = cleaned_response.replace('"""', "")

                # Ensure proper SPSDK formatting
                cleaned_response = self._ensure_spsdk_formatting(cleaned_response)

                return cleaned_response.strip()

            LOGGER.error(f"No response from Cody for module: {module_info.file_path.name}")
            return None

        except Exception as e:
            LOGGER.error(
                f"Error getting module docstring from Cody for {module_info.file_path.name}: {e}"
            )
            return None

    def _ensure_spsdk_formatting(self, docstring: str) -> str:
        """Ensure the docstring follows SPSDK formatting with proper empty lines.

        This method formats docstrings to comply with SPSDK standards by adding appropriate
        blank lines after the title and ensuring proper spacing around list sections that
        contain keywords like 'main', 'classes', 'functions', 'constants', or 'features'.

        :param docstring: The input docstring to be formatted.
        :return: Formatted docstring with proper SPSDK spacing and structure.
        """
        lines = docstring.split("\n")
        if not lines:
            return docstring

        formatted_lines = []
        title = lines[0].strip()
        formatted_lines.append(title)

        # If there are more lines after the title, ensure blank line separation
        remaining_lines = [line for line in lines[1:] if line.strip() or line == ""]

        if remaining_lines:
            # Add blank line after summary if not already present
            if remaining_lines and remaining_lines[0].strip():
                formatted_lines.append("")

            # Process remaining lines, ensuring proper spacing
            prev_was_empty = True  # We just added an empty line
            in_list_section = False

            for line in remaining_lines:
                stripped = line.strip()

                # Skip empty lines at the beginning after we've added our blank line
                if not formatted_lines[-1] and not stripped:
                    continue

                # Detect list sections (Main classes:, Main functions:, etc.)
                if stripped.endswith(":") and any(
                    keyword in stripped.lower()
                    for keyword in ["main", "classes", "functions", "constants", "features"]
                ):
                    if not prev_was_empty and formatted_lines and formatted_lines[-1].strip():
                        formatted_lines.append("")  # Add empty line before section
                    in_list_section = True
                elif stripped.startswith("-") and in_list_section:
                    # This is a list item, keep it as is
                    pass
                elif stripped and in_list_section and not stripped.startswith("-"):
                    # End of list section
                    in_list_section = False

                # Add the line
                formatted_lines.append(line)
                prev_was_empty = stripped == ""

        return "\n".join(formatted_lines)

    def update_module_docstring(self, module_info: ModuleInfo, new_docstring: str) -> bool:
        """Update the module docstring in the file.

        This method reads the Python file, locates the appropriate position for the module
        docstring (after headers like shebang, encoding, and copyright), removes any existing
        module docstring, and inserts the new docstring at the correct location.

        :param module_info: Information about the module including file path and current docstring.
        :param new_docstring: The new docstring content to be inserted into the module.
        :return: True if the docstring was successfully updated, False otherwise.
        """
        try:
            with open(module_info.file_path, "r", encoding="utf-8") as f:
                lines = f.readlines()

            # Find where to insert/replace the module docstring
            # Module docstring should be at the top, after shebang/encoding/copyright
            insert_line = 0

            # Skip shebang, encoding, and copyright/license headers
            for i, line in enumerate(lines):
                stripped = line.strip()
                if (
                    stripped.startswith("#!")
                    or stripped.startswith("# -*- coding:")
                    or stripped.startswith("# Copyright")
                    or stripped.startswith("# SPDX-License-Identifier")
                    or (
                        stripped.startswith("#")
                        and any(
                            word in stripped.lower() for word in ["copyright", "license", "author"]
                        )
                    )
                    or stripped == "#"
                ):
                    continue
                else:
                    insert_line = i
                    break

            # Skip any empty lines after headers
            while insert_line < len(lines) and lines[insert_line].strip() == "":
                insert_line += 1

            # Format the new docstring (no indentation for module docstring)
            docstring_lines = []
            docstring_lines.append(f'"""{new_docstring.splitlines()[0]}\n')

            # Add remaining lines of docstring
            for line in new_docstring.splitlines()[1:]:
                if line.strip():
                    docstring_lines.append(f"{line}\n")
                else:
                    docstring_lines.append("\n")

            docstring_lines.append('"""\n')
            docstring_lines.append("\n")  # Add empty line after module docstring

            # Remove existing module docstring if present
            if module_info.current_docstring:
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

                # Remove the old docstring lines (and following empty line if present)
                if remove_end > remove_start:
                    # Also remove one following empty line if it exists
                    if remove_end < len(lines) and lines[remove_end].strip() == "":
                        remove_end += 1
                    del lines[remove_start:remove_end]
                    insert_line = remove_start

            # Insert the new docstring
            for i, docstring_line in enumerate(docstring_lines):
                lines.insert(insert_line + i, docstring_line)

            if not self.dry_run:
                with open(module_info.file_path, "w", encoding="utf-8") as f:
                    f.writelines(lines)
                LOGGER.info(f"✅ Updated module docstring in {module_info.file_path}")
            else:
                LOGGER.info(
                    f"🔍 [DRY RUN] Would update module docstring in {module_info.file_path}"
                )
                LOGGER.debug(f"Would insert docstring at line {insert_line + 1}")

            return True

        except Exception as e:
            LOGGER.error(f"Error updating module docstring in {module_info.file_path}: {e}")
            return False

    def process_file(self, file_path: Path) -> None:
        """Process a single Python file and update its module docstring.

        Analyzes the given Python file, generates a new docstring using AI assistance,
        and updates the module's docstring if improvements are needed. The method
        handles the complete workflow from analysis to file modification.

        :param file_path: Path to the Python file to be processed.
        :raises SPSDKError: When module analysis fails or file operations encounter errors.
        """
        LOGGER.info(f"Processing module: {file_path}")

        module_info = self.analyze_module(file_path)
        if not module_info:
            LOGGER.error(f"Failed to analyze module: {file_path}")
            return

        # Generate new docstring
        new_docstring = self.generate_module_docstring_with_cody(module_info)

        if new_docstring:
            LOGGER.info(f"Generated new docstring for module: {file_path.name}")
            success = self.update_module_docstring(module_info, new_docstring)
            if success:
                LOGGER.info(f"✅ Successfully updated module docstring for {file_path.name}")
            else:
                LOGGER.error(f"❌ Failed to update module docstring for {file_path.name}")
        else:
            LOGGER.info(f"⏭️  No changes needed for module: {file_path.name}")

    def run(self) -> None:
        """Run the module docstring updater on all Python files.

        Processes all Python files in the target directory by updating their module-level
        docstrings. The method validates the target directory existence, finds all Python
        files, and processes each file individually. Errors during file processing are
        logged but do not stop the overall process.
        """
        if not self.target_directory.exists():
            LOGGER.error(f"Target directory does not exist: {self.target_directory}")
            return

        python_files = self.find_python_files()

        if not python_files:
            LOGGER.warning("No Python files found to process")
            return

        LOGGER.info(f"Starting module docstring update process for {len(python_files)} files")

        for file_path in python_files:
            try:
                self.process_file(file_path)
            except Exception as e:
                LOGGER.error(f"Error processing file {file_path}: {e}")
                continue

        LOGGER.info("✅ Module docstring update process completed")


def main() -> None:
    """Main entry point for the docstring updater tool.

    Parses command line arguments, validates the target path (directory or file), and runs
    the module docstring updater. Handles keyboard interrupts and unexpected
    errors gracefully with appropriate exit codes.

    :raises SystemExit: When path validation fails or unexpected errors occur.
    """
    parser = argparse.ArgumentParser(
        description="Update Python module docstrings using Cody API",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
python docstring_updater_modules.py /path/to/spsdk/source
python docstring_updater_modules.py ./spsdk --dry-run
python docstring_updater_modules.py ../project/src --verbose
python docstring_updater_modules.py single_file.py --dry-run
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
        updater = ModuleDocstringUpdater(parent_dir, dry_run=args.dry_run)

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
        updater = ModuleDocstringUpdater(args.path, dry_run=args.dry_run)

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
