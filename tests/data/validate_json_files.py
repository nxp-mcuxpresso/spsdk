#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
#!/usr/bin/env python3
## Copyright 2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause
"""JSON Schema Validator for SPSDK test data files.

This module provides validation functionality for JSON files in the SPSDK repository
against their respective schemas. It validates fuses configuration files, TrustZone
configuration files, and processor register files to ensure data integrity.
"""

import glob
import json
import os
import sys
from typing import Any, Optional, Union

import jsonschema
from jsonschema import validate

# Import the referencing library
try:
    import referencing
except ImportError:
    print("Warning: 'referencing' library not found. Installing it is recommended.")
    print("Run: pip install referencing")
    # We'll handle this case in the code


class JsonSchemaValidator:
    """JSON Schema Validator for SPSDK configuration files.

    This class provides comprehensive validation of JSON files against predefined schemas
    including fuses, processor registers, and TrustZone configurations. It automatically
    discovers JSON files in the project structure and validates them against appropriate
    schemas to ensure configuration integrity across the SPSDK ecosystem.
    """

    def __init__(self, root_dir: str = ".", schemas_dir: Optional[str] = None) -> None:
        """Initialize the validator with the root directory to search and schemas directory.

        Args:
            root_dir: Root directory to search for JSON files
            schemas_dir: Directory containing JSON schemas. If None, defaults to "tools/json_schemas" under root_dir
        """
        self.root_dir = root_dir

        # Set schemas directory - either provided or default location
        if schemas_dir is None:
            self.schemas_dir = os.path.join(root_dir, "tools", "json_schemas")
        else:
            self.schemas_dir = schemas_dir

        self.fuses_schema_path = os.path.join(self.schemas_dir, "fuses_schema.json")
        self.register_schema_path = os.path.join(
            self.schemas_dir, "processors_registers_schema.json"
        )
        self.trustzone_schema_path = os.path.join(self.schemas_dir, "trustzone_schema.json")

        # Load schemas
        try:
            with open(self.fuses_schema_path, "r", encoding="utf-8") as f:
                self.fuses_schema = json.load(f)
            with open(self.register_schema_path, "r", encoding="utf-8") as f:
                self.register_schema = json.load(f)
            with open(self.trustzone_schema_path, "r", encoding="utf-8") as f:
                self.trustzone_schema = json.load(f)
        except FileNotFoundError as e:
            print(f"Error: Schema file not found: {e}")
            sys.exit(1)
        except json.JSONDecodeError as e:
            print(f"Error: Invalid JSON in schema file: {e}")
            sys.exit(1)

        # Create a registry for schema references
        self.registry = self._create_schema_registry()

    def _create_schema_registry(self) -> Union[dict[str, Any], "referencing.Registry"]:
        """Create a registry for schema references using the referencing library.

        Loads all JSON schema files from the schemas directory and creates either a
        referencing.Registry object (if the referencing library is available) or a
        simple dictionary store for schema validation purposes.

        :return: Registry that can handle localschema references, either as a
                 referencing.Registry object or a dictionary mapping schema URIs to schema data.
        """
        # Create a schema store for all schema files
        schema_store: dict[str, Any] = {}

        # Load all schema files from the schemas directory
        for schema_file in glob.glob(os.path.join(self.schemas_dir, "*.json")):
            schema_name = os.path.basename(schema_file)
            try:
                with open(schema_file, "r", encoding="utf-8") as f:
                    schema_data = json.load(f)
                    # Store the schema with its localschema URI
                    schema_store[f"localschema:{schema_name}"] = schema_data
            except (json.JSONDecodeError, IOError) as e:
                print(f"Warning: Could not load schema file {schema_file}: {e}")

        # Check if we have the referencing library
        if "referencing" in sys.modules:
            # Create a retrieval function that handles the localschema URIs
            def retrieve(uri: str) -> "referencing.Resource":
                """Retrieve a schema resource from the schema store.

                This method looks up a schema by its URI in the local schema store and returns
                it as a referencing Resource object for JSON schema validation.

                :param uri: The URI identifier of the schema to retrieve.
                :raises referencing.exceptions.Unretrievable: When the requested URI is not found in the schema store.
                :return: A referencing Resource object containing the schema contents.
                """
                if uri in schema_store:
                    return referencing.Resource.from_contents(schema_store[uri])
                raise referencing.exceptions.Unretrievable(uri)

            # Create and return the registry
            return referencing.Registry(retrieve=retrieve)  # type: ignore

        # If referencing is not available, return the schema store
        # The validate_json_file method will handle this case
        return schema_store

    def find_json_files(
        self, search_dir: Optional[str] = None
    ) -> tuple[list[str], list[str], list[str]]:
        """Find all JSON files in the repository or specified directory.

        Searches recursively through the specified directory (or root directory if none provided)
        to categorize JSON files into fuses files, trustzone files, and other JSON files.
        Schema files are excluded from the results.

        :param search_dir: Directory to search for JSON files. If None, uses the root_dir.
        :return: Tuple containing three lists: (fuses_files, trustzone_files, other_files)
            with paths to respective JSON files.
        """
        fuses_files: list[str] = []
        trustzone_files: list[str] = []
        other_files: list[str] = []

        # Use the provided search directory or fall back to root_dir
        search_path = search_dir if search_dir is not None else self.root_dir

        for root, _, _ in os.walk(search_path):
            # Find fuses_*.json files
            for file_path in glob.glob(os.path.join(root, "fuses*.json")):
                fuses_files.append(file_path)

            # # Find tz_*.json files
            # for file_path in glob.glob(os.path.join(root, "tz*.json")):
            #     trustzone_files.append(file_path)

            # Find other *.json files (excluding the schema files themselves)
            for file_path in glob.glob(os.path.join(root, "*.json")):
                # Skip schema files, fuses files, and trustzone files
                if (
                    not file_path.startswith(self.schemas_dir)
                    and not os.path.basename(file_path).startswith("fuses")
                    and not os.path.basename(file_path).startswith("tz")
                ):
                    other_files.append(file_path)

        return fuses_files, trustzone_files, other_files

    def validate_json_file(
        self, file_path: str, schema: dict[str, Any]
    ) -> tuple[bool, Optional[str]]:
        """Validate a JSON file against a schema.

        The method supports both modern referencing library and legacy RefResolver
        for JSON schema validation with proper error handling and fallback mechanisms.

        :param file_path: Path to the JSON file to validate.
        :param schema: JSON schema dictionary to validate against.
        :raises json.JSONDecodeError: Invalid JSON format in the file.
        :raises jsonschema.exceptions.ValidationError: Schema validation failed.
        :return: Tuple containing validation result (True if valid, False otherwise) and error message (None if valid).
        """
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                json_data = json.load(f)

            # Check if we're using the referencing library
            if "referencing" in sys.modules:
                # Use the referencing library for validation
                from jsonschema import validators

                # Get the appropriate validator class
                validator_class = validators.validator_for(schema)
                # Create a validator with the registry
                validator = validator_class(schema, registry=self.registry)
                validator.validate(json_data)
            else:
                # Fall back to the older approach with a warning
                print(
                    "Warning: Using deprecated validation method. Install 'referencing' for better compatibility."
                )
                # Create a temporary RefResolver with our schema store
                resolver = jsonschema.RefResolver("", schema, store=self.registry)
                validate(instance=json_data, schema=schema, resolver=resolver)

            return True, None
        except json.JSONDecodeError as e:
            return False, f"Invalid JSON format: {e}"
        except jsonschema.exceptions.ValidationError as e:
            return False, f"Schema validation error: {e}"
        except Exception as e:
            return False, f"Unexpected error: {str(e)}"

    def validate_all(
        self, search_dir: Optional[str] = None
    ) -> dict[str, dict[str, Union[bool, Optional[str]]]]:
        """Validate all JSON files against their respective schemas.

        Searches for JSON files in the specified directory and validates them against
        appropriate schemas based on file naming patterns. Fuses files are validated
        against fuses schema, TrustZone files against TrustZone schema, and other
        JSON files against register schema.

        :param search_dir: Directory to search for JSON files. If None, uses the root_dir.
        :return: Dictionary with file paths as keys and validation results as values.
                 Each result contains 'valid' (bool) and 'error' (str or None) keys.
        """
        results: dict[str, dict[str, Union[bool, Optional[str]]]] = {}
        fuses_files, trustzone_files, other_files = self.find_json_files(search_dir)

        print(f"Found {len(fuses_files)} fuses*.json files")
        print(f"Found {len(trustzone_files)} tz*.json files")
        print(f"Found {len(other_files)} other *.json files")

        # Validate fuses_*.json files
        for file_path in fuses_files:
            is_valid, error = self.validate_json_file(file_path, self.fuses_schema)
            results[file_path] = {"valid": is_valid, "error": error}

        # Validate tz*.json files
        for file_path in trustzone_files:
            is_valid, error = self.validate_json_file(file_path, self.trustzone_schema)
            results[file_path] = {"valid": is_valid, "error": error}

        # Validate other *.json files
        for file_path in other_files:
            is_valid, error = self.validate_json_file(file_path, self.register_schema)
            results[file_path] = {"valid": is_valid, "error": error}

        return results


def main() -> None:
    """Main function to run the validator directly."""
    root_dir = "." if len(sys.argv) <= 1 else sys.argv[1]
    schemas_dir = None if len(sys.argv) <= 2 else sys.argv[2]
    validator = JsonSchemaValidator(root_dir, schemas_dir)

    results = validator.validate_all()

    # Print results
    all_valid = True
    fail = 0
    for file_path, result in results.items():
        if not result["valid"]:
            all_valid = False
            fail += 1
            print(f"❌ {file_path}: {result['error']}")

    if all_valid:
        print("✅ All JSON files are valid!")
        sys.exit(0)
    else:
        print(f"❌ Some JSON files({fail}) failed validation.")
        sys.exit(1)


if __name__ == "__main__":
    main()
