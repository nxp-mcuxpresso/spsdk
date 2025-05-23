#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2019-2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""Module for base abstract classes."""

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
    """Base class for for classes with configuration."""

    FEATURE = "Not defined"
    SUB_FEATURE: Optional[str] = None

    family: FamilyRevision

    @classmethod
    def get_supported_families(cls, include_predecessors: bool = False) -> list[FamilyRevision]:
        """Get supported families for the feature."""
        return get_families(
            feature=cls.FEATURE,
            sub_feature=cls.SUB_FEATURE,
            include_predecessors=include_predecessors,
        )

    @classmethod
    @abstractmethod
    def get_validation_schemas(cls, family: FamilyRevision) -> list[dict[str, Any]]:
        """Create the list of validation schemas.

        :param family: The CPU/MPU
        :return: List of validation schemas.
        """

    @classmethod
    def get_validation_schemas_from_cfg(cls, config: Config) -> list[dict[str, Any]]:
        """Get validation schema based on configuration.

        If the class doesn't behave generally, just override this implementation.

        :param config: Valid configuration
        :return: Validation schemas
        """
        config.check(cls.get_validation_schemas_basic())
        return cls.get_validation_schemas(FamilyRevision.load_from_config(config))

    def _get_validation_schemas(self) -> list[dict[str, Any]]:
        """Create the list of validation schemas.

        :return: List of validation schemas.
        """
        return self.get_validation_schemas(self.family)

    @classmethod
    def get_config_template(cls, family: FamilyRevision) -> str:
        """Get feature configuration template.

        :param family: Family for which the template should be generated.
        :return: Template file string representation.
        """
        schemas = cls.get_validation_schemas(family)
        return cls._get_config_template(family, schemas)

    @classmethod
    def _get_config_template(cls, family: FamilyRevision, schemas: list[dict[str, Any]]) -> str:
        """Get feature configuration template.

        :param family: Family for which the template should be generated.
        :param schemas: List of JSON validation schemas.
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

        :return: Validation list of schemas.
        """
        family_schema = get_schema_file("general")["family"]
        update_validation_schema_family(
            sch=family_schema["properties"], devices=cls.get_supported_families()
        )
        return [family_schema]

    @classmethod
    def pre_check_config(cls, config: Config) -> None:
        """Check the input configuration.

        :param config: Feature configuration.
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
        """Create configuration of the Feature.

        :param data_path: Path to store the data files of configuration.
        :param kwargs: Any non standard named parameters for getting correct configuration.
        :return: Configuration dictionary.
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
    """Base class that adds verifying of object."""

    FEATURE: str

    def verify(self) -> Verifier:
        """Verifier object data."""
        ret = Verifier(f"Feature '{self.FEATURE}' verification")
        ret.add_record(
            name="Implementation", result=VerifierResult.WARNING, value="Not implemented"
        )
        return ret


class FeatureBaseClass(BaseClass, VerifyBaseClass, ConfigBaseClass):
    """Base class for features."""


class FeatureBaseClassComm(RawBaseClass, VerifyBaseClass, ConfigBaseClass):
    """Base class for features for communication features without export/parse methods."""
