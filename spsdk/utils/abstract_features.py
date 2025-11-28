#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2019-2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""SPSDK abstract base classes for configuration, verification, and feature management.

This module provides foundational abstract classes that define common interfaces
and behaviors across SPSDK components. It includes base classes for configuration
handling, verification processes, and feature implementations with optional
communication capabilities.
"""

from abc import ABC, abstractmethod
from datetime import datetime
from typing import Any, Optional

from typing_extensions import Self

from spsdk import version as spsdk_version
from spsdk.utils.abstract import BaseClass, RawBaseClass
from spsdk.utils.config import Config
from spsdk.utils.database import get_schema_file
from spsdk.utils.family import FamilyRevision, get_families, update_validation_schema_family
from spsdk.utils.schema_validator import CommentedConfig
from spsdk.utils.verifier import Verifier, VerifierResult

########################################################################################################################
# Abstract Class for Feature Classes
########################################################################################################################


class ConfigBaseClass(ABC):
    """Base class for SPSDK components with configuration support.

    This abstract class provides a foundation for SPSDK features that require
    configuration management, validation, and family-specific support. It defines
    the interface for configuration validation schemas, template generation, and
    family compatibility checking across NXP MCU portfolio.

    :cvar FEATURE: Primary feature identifier for family support lookup.
    :cvar SUB_FEATURE: Optional sub-feature identifier for specialized variants.
    """

    FEATURE = "Not defined"
    SUB_FEATURE: Optional[str] = None

    family: FamilyRevision

    @classmethod
    def get_supported_families(cls, include_predecessors: bool = False) -> list[FamilyRevision]:
        """Get supported families for the feature.

        Retrieves a list of family revisions that are supported by this feature class,
        optionally including predecessor families.

        :param include_predecessors: Whether to include predecessor families in the result.
        :return: List of supported family revisions for this feature.
        """
        return get_families(
            feature=cls.FEATURE,
            sub_feature=cls.SUB_FEATURE,
            include_predecessors=include_predecessors,
        )

    @classmethod
    @abstractmethod
    def get_validation_schemas(cls, family: FamilyRevision) -> list[dict[str, Any]]:
        """Create the list of validation schemas for the specified family.

        This method generates validation schemas that can be used to validate
        configuration data or other inputs specific to the given MCU/MPU/MPU family.

        :param family: The target MCU/MPU/MPU family and revision information.
        :return: List of validation schema dictionaries.
        """

    @classmethod
    def get_validation_schemas_from_cfg(cls, config: Config) -> list[dict[str, Any]]:
        """Get validation schemas based on configuration.

        This method extracts validation schemas by first checking the configuration against
        basic validation schemas, then retrieving family-specific schemas based on the
        family revision loaded from the configuration. Classes with non-standard behavior
        should override this implementation.

        :param config: Valid configuration object containing family and revision information
        :return: List of validation schema dictionaries for the specified configuration
        """
        config.check(cls.get_validation_schemas_basic())
        return cls.get_validation_schemas(FamilyRevision.load_from_config(config))

    def _get_validation_schemas(self) -> list[dict[str, Any]]:
        """Get the list of validation schemas for the current family.

        This method retrieves validation schemas by calling the static method with the
        instance's family attribute.

        :return: List of validation schemas for the configured family.
        """
        return self.get_validation_schemas(self.family)

    @classmethod
    def get_config_template(cls, family: FamilyRevision) -> str:
        """Get feature configuration template.

        The method generates a configuration template for the specified family by first
        retrieving the validation schemas and then creating the template based on those schemas.

        :param family: Family for which the template should be generated.
        :return: Template file string representation.
        """
        schemas = cls.get_validation_schemas(family)
        return cls._get_config_template(family, schemas)

    @classmethod
    def _get_config_template(cls, family: FamilyRevision, schemas: list[dict[str, Any]]) -> str:
        """Get feature configuration template.

        Generates a configuration template string for the specified family using the provided
        JSON validation schemas. The template includes a main title and optional notes.

        :param family: Family for which the template should be generated.
        :param schemas: List of JSON validation schemas used to generate the template.
        :return: Template file string representation.
        """
        main_title = schemas[0].get(
            "main_title", f"{cls.FEATURE} Configuration template for {family}."
        )
        note = schemas[0].get("note")

        return CommentedConfig(main_title, schemas, note=note).get_template()

    @classmethod
    def get_validation_schemas_basic(cls) -> list[dict[str, Any]]:
        """Get list of validation schemas for family key.

        The method retrieves the general family schema and updates it with supported families
        for the current class, returning a list containing the configured family schema.

        :return: List of validation schemas with updated family configurations.
        """
        family_schema = get_schema_file("general")["family"]
        update_validation_schema_family(
            sch=family_schema["properties"], devices=cls.get_supported_families()
        )
        return [family_schema]

    @classmethod
    def pre_check_config(cls, config: Config) -> None:
        """Check the input configuration against validation schemas.

        The method retrieves validation schemas from the configuration and performs
        validation checks to ensure the configuration is valid and complete.

        :param config: Feature configuration to be validated.
        :raises SPSDKError: In case of invalid configuration.
        """
        schemas = cls.get_validation_schemas_from_cfg(config)
        config.check(schemas)

    @abstractmethod
    def get_config(self, data_path: str = "./") -> Config:
        """Create configuration of the Feature.

        :param data_path: Path to store the data files of configuration.
        :return: Configuration dictionary.
        """

    def get_config_yaml(self, data_path: str = "./", **kwargs: Any) -> str:
        """Create configuration YAML for the Feature.

        The method generates a YAML configuration with validation schemas, timestamps,
        and SPSDK version information for the specific feature and family.

        :param data_path: Path to store the data files of configuration.
        :param kwargs: Any non-standard named parameters for getting correct configuration.
        :return: Configuration YAML string with metadata and validation schemas.
        """
        schemas = self._get_validation_schemas()
        main_title = schemas[0].get(
            "main_title", f"{self.FEATURE} Configuration for {self.family}."
        )
        note = schemas[0].get("note")
        return CommentedConfig(
            main_title=(
                f"{main_title}.\n"
                f"Created: {datetime.now().strftime('%d/%m/%Y %H:%M:%S')}.\n"
                f"NXP SPSDK version: {spsdk_version}"
            ),
            schemas=schemas,
            note=note,
        ).get_config(self.get_config(data_path=data_path, **kwargs))

    @classmethod
    @abstractmethod
    def load_from_config(cls, config: Config) -> Self:
        """Load feature object from configuration.

        :param config: Configuration dictionary.
        :return: Initialized feature object.
        """


class VerifyBaseClass:
    """Base class for objects that support verification functionality.

    This abstract base class provides a standard interface for implementing
    verification capabilities across SPSDK components. Subclasses should
    override the verify method to provide specific verification logic.

    :cvar FEATURE: Feature name identifier used in verification reporting.
    """

    FEATURE: str

    def verify(self) -> Verifier:
        """Get verification result for the feature.

        Creates a verifier object that contains the verification status of the current feature
        implementation. By default, returns a warning indicating the feature is not implemented.

        :return: Verifier object containing feature verification results.
        """
        ret = Verifier(f"Feature '{self.FEATURE}' verification")
        ret.add_record(
            name="Implementation", result=VerifierResult.WARNING, value="Not implemented"
        )
        return ret


class FeatureBaseClass(BaseClass, VerifyBaseClass, ConfigBaseClass):
    """Base class for SPSDK features with configuration and verification capabilities.

    This class serves as the foundation for all SPSDK feature implementations,
    combining base functionality, verification capabilities, and configuration
    management. It provides a unified interface for feature classes that need
    to handle configuration data, perform validation, and maintain consistent
    behavior across the SPSDK ecosystem.
    """


class FeatureBaseClassComm(RawBaseClass, VerifyBaseClass, ConfigBaseClass):
    """Base class for communication features without export/parse methods.

    This class combines raw data handling, verification capabilities, and configuration
    management for communication-related features in SPSDK. It provides a foundation
    for implementing communication protocols that require data validation and
    configuration but do not need serialization capabilities.
    """
