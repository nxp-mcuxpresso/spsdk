#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2021-2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""Module for general utilities used by TP applications."""
import itertools
import os
from typing import Any, Callable, Optional, Union

import click
import colorama
import prettytable
from typing_extensions import Literal

from spsdk.apps.utils.common_cli_options import FC, spsdk_config_option
from spsdk.exceptions import SPSDKError
from spsdk.tp.exceptions import SPSDKTpError
from spsdk.tp.tp_intf import TpDevInterface, TpIntfDescription
from spsdk.tp.tphost import TrustProvisioningHost
from spsdk.tp.utils import (
    get_supported_devices,
    get_tp_device_class,
    get_tp_device_types,
    get_tp_target_class,
    get_tp_target_types,
    scan_tp_devices,
    scan_tp_targets,
    single_tp_device_adapter,
    single_tp_target_adapter,
)
from spsdk.utils.database import DatabaseManager, get_db, get_schema_file
from spsdk.utils.misc import find_file, load_binary, load_configuration
from spsdk.utils.schema_validator import check_config, update_validation_schema_family


class TPBaseConfig:
    """Base class for TP app configs."""

    SCHEMA_MEMBERS: list[str] = []

    def __init__(self, config_data: dict, config_dir: Optional[str] = None) -> None:
        """Initialize the basic configuration.

        :param config_data: Initial configuration data
        :param config_dir: Path to configuration file
        """
        self.config_data = config_data
        self.config_dir = config_dir

    def _validate(self, schema_members: Optional[list[str]] = None) -> None:
        """Validate configuration data using appropriate validation schema.

        :param schema_members: Explicit schema members to check (default: self.SCHEMA_MEMBERS)
        """
        schema_cfg = get_schema_file(DatabaseManager.TP)
        schema_members_int = schema_members or self.SCHEMA_MEMBERS
        # Get this app type scheme pieces
        sch_list = []
        for sch_name in schema_members_int:
            if (
                "properties" in schema_cfg[sch_name]
                and "family" in schema_cfg[sch_name]["properties"]
            ):
                update_validation_schema_family(
                    schema_cfg[sch_name]["properties"], devices=get_supported_devices()
                )
            sch_list.append(schema_cfg[sch_name])

        # First check common settings
        check_config(
            config=self.config_data,
            schemas=sch_list,
            search_paths=[self.config_dir] if self.config_dir else None,
        )

        # Add device schemas
        if "device" in self.SCHEMA_MEMBERS:
            sch_list.extend(
                get_tp_device_class(self.config_data["tp_device"]).get_validation_schemas()
            )
        # Optionally add also target schemas
        if "target" in self.SCHEMA_MEMBERS:
            sch_list.extend(
                get_tp_target_class(self.config_data["tp_target"]).get_validation_schemas()
            )

        check_config(
            config=self.config_data,
            schemas=sch_list,
            search_paths=[self.config_dir] if self.config_dir else None,
        )

    @staticmethod
    def _get_config_data(config_file_path: Optional[str] = None) -> dict[str, Any]:
        """Setup initial configuration data."""
        if config_file_path:
            return load_configuration(config_file_path)
        return {"timeout": 60}

    @property
    def tp_device(self) -> str:
        """Trust Provisioning device."""
        return self.config_data["tp_device"]

    @property
    def tp_device_parameter(self) -> dict[str, Any]:
        """Trust Provisioning device parameters."""
        return self.config_data["tp_device_parameter"]

    @property
    def timeout(self) -> int:
        """Timeout."""
        return self.config_data.get("timeout", 60)

    @property
    def family(self) -> str:
        """Target chip family."""
        return self.config_data["family"]


class TPHostConfig(TPBaseConfig):
    """Configuration class for TPHost app."""

    SCHEMA_MEMBERS = [
        "family",
        "provisioning_firmware",
        "oem_firmware",
        "tp_timeout",
        "audit_log",
        "device",
        "target",
    ]

    def __init__(
        self,
        tp_device: Optional[str] = None,
        tp_device_parameter: Optional[list[str]] = None,
        tp_target: Optional[str] = None,
        tp_target_parameter: Optional[list[str]] = None,
        family: Optional[str] = None,
        firmware: Optional[str] = None,
        prov_firmware: Optional[str] = None,
        audit_log: Optional[str] = None,
        audit_log_key: Optional[str] = None,
        timeout: Optional[int] = None,
        config: Optional[str] = None,
    ) -> None:
        """Initialize the TPHost configuration."""
        config_data = self._get_config_data(config)
        config_dir = os.path.dirname(config) if config else None

        super().__init__(config_data=config_data, config_dir=config_dir)

        if timeout is not None:
            self.config_data["timeout"] = timeout
        if tp_device:
            self.config_data["tp_device"] = tp_device
        if tp_target:
            self.config_data["tp_target"] = tp_target
        if family:
            self.config_data["family"] = family
        if firmware:
            self.config_data["firmware"] = firmware
        if prov_firmware:
            self.config_data["prov_firmware"] = prov_firmware
        if audit_log:
            self.config_data["audit_log"] = audit_log
        if audit_log_key:
            self.config_data["audit_log_key"] = audit_log_key

        self.config_data["tp_device_parameter"] = sanitize_param_struct(
            "tp_device_parameter", tp_device_parameter, self.config_data, self.config_dir
        )
        self.config_data["tp_target_parameter"] = sanitize_param_struct(
            "tp_target_parameter", tp_target_parameter, self.config_data, self.config_dir
        )

        self._validate()

        if "audit_log" not in self.config_data:
            return

        try:
            self.config_data["audit_log"] = find_file(
                self.config_data["audit_log"],
                search_paths=[self.config_dir] if self.config_dir else None,
            )
        except SPSDKError:
            # file doesn't exist yet
            # if config file is defined make the audit_log path relative to it
            if self.config_dir and "audit_log" in self.SCHEMA_MEMBERS:
                self.config_data["audit_log"] = os.path.join(
                    self.config_dir, self.config_data["audit_log"]
                )

    @property
    def tp_target(self) -> str:
        """Trust Provisioning target."""
        return self.config_data["tp_target"]

    @property
    def tp_target_parameter(self) -> dict[str, Any]:
        """Trust Provisioning target parameters."""
        return self.config_data["tp_target_parameter"]

    @property
    def audit_log(self) -> str:
        """Path to audit log."""
        return self.config_data["audit_log"]

    @property
    def audit_log_key(self) -> str:
        """Path to audit log key."""
        # up until this point 'audit_log_key' was optional
        if "audit_log_key" not in self.config_data:
            raise SPSDKTpError("audit-log-key is not specified")
        return find_file(
            self.config_data["audit_log_key"],
            search_paths=[self.config_dir] if self.config_dir else None,
        )

    @property
    def firmware_data(self) -> Optional[bytes]:
        """OEM firmware content."""
        if not self.config_data.get("firmware"):
            return None
        file_path = find_file(
            self.config_data["firmware"],
            search_paths=[self.config_dir] if self.config_dir else None,
        )
        return load_binary(file_path)

    @property
    def prov_firmware_data(self) -> Optional[bytes]:
        """Provisioning Firmware content."""
        if not self.config_data.get("prov_firmware"):
            return None
        file_path = find_file(
            self.config_data["prov_firmware"],
            search_paths=[self.config_dir] if self.config_dir else None,
        )
        return load_binary(file_path)


class TPConfigConfig(TPBaseConfig):
    """Configuration class for TPConfig app."""

    SCHEMA_MEMBERS = [
        "family",
        "tp_timeout",
        "device",
        "production_quota",
        "oem_log_prk",
        "nxp_prod_cert",
        "nxp_global_attest_cert",
        "oem_id",
    ]

    def __init__(
        self,
        config_file_path: str,
        tp_device: Optional[str] = None,
        tp_device_parameter: Optional[list[str]] = None,
        timeout: Optional[int] = None,
    ) -> None:
        """Initialize the TPConfig configuration."""
        config_dir = os.path.dirname(config_file_path)
        config_data = self._get_config_data(config_file_path)

        super().__init__(config_data=config_data, config_dir=config_dir)

        if timeout is not None:
            self.config_data["timeout"] = timeout
        if tp_device:
            self.config_data["tp_device"] = tp_device
        self.config_data["tp_device_parameter"] = sanitize_param_struct(
            "tp_device_parameter", tp_device_parameter, self.config_data, self.config_dir
        )

        # first we need to validate family, after that we check family-specific settings
        self._validate()
        db = get_db(self.family, revision="latest")
        if db.get_bool(DatabaseManager.TP, "use_prov_data"):
            extra_checks = ["provisioning_data"]
        else:
            extra_checks = ["cmpa", "cfpa", "sb_kek", "user_kek"]
        self._validate(extra_checks)


def multiple_tp_dict(multi: Optional[list[str]]) -> dict[str, str]:
    """Convert even Multiple option to dict in order.

    :param multi: Input List with multiple options.
    :return: Result dictionary
    :raises SPSDKTpError: Problem parsing the input
    """
    try:
        if multi is None:
            return {}
        return dict(item.split("=") for item in multi if isinstance(item, str))
    except Exception as e:
        raise SPSDKTpError(f"Unable to process input {multi}") from e


def sanitize_param_struct(
    param_name: str, cli_params: Optional[list[str]], config_params: dict, config_dir: Optional[str]
) -> dict:
    """Sanitize TP Target/Device parameter settings.

    :param param_name: Name of the parameter group
    :param cli_params: Parameters passed from CLI
    :param config_params: Parameters read from config file
    :param config_dir: Path to config file (for extended search)
    :return: Sanitized parameter config structure
    """
    sanitized_config = config_params.get(param_name, {}) or {}
    sanitized_config.update(multiple_tp_dict(cli_params))
    if "config_file" in sanitized_config:
        config_file_path = sanitized_config["config_file"]
        config_file_path = find_file(
            config_file_path, search_paths=[config_dir] if config_dir else None
        )
        sanitized_config["config_file"] = config_file_path
    return sanitized_config


def print_device_table(intfs: list[TpIntfDescription]) -> str:
    """Prints the List of Interfaces to nice colored table."""
    if len(intfs) == 0:
        return (
            colorama.Fore.RED
            + "Nothing to print - empty interface list!"
            + colorama.Style.RESET_ALL
        )

    # exhaust the chain iterator
    header = list(
        # get all the header elements from interfaces
        # serialize them in to chain: list[list[str]] -> iterator[str]
        itertools.chain.from_iterable(i.as_dict().keys() for i in intfs),
    )
    # remove duplicates whilst preserving the order
    header = list(dict.fromkeys(header))

    table = prettytable.PrettyTable(_sanitize_table_header(header))
    table.align = "l"
    table.header = True
    table.border = True
    table.hrules = prettytable.HRuleStyle.HEADER
    table.vrules = prettytable.VRuleStyle.NONE
    for i, intf in enumerate(intfs):
        fields = [
            colorama.Fore.YELLOW + str(i),
            colorama.Fore.MAGENTA + intf.name,
            colorama.Fore.GREEN + intf.description,
        ]

        for field in header[2:]:
            fields.append(colorama.Fore.CYAN + str(intf.as_dict().get(field, "")))
        table.add_row(fields)

    return table.get_string() + colorama.Style.RESET_ALL


def _sanitize_table_header(header: list[str]) -> list[str]:
    """Sanitize header for use as Table header.

    Capitalize header items.
    Replace "_" with a " " in header items.
    Insert "#" at the first place.
    """
    if "name" not in header or "description" not in header:
        raise SPSDKTpError("Missing mandatory header fields in interface description.")
    header = [item.capitalize() for item in header]
    header = [item.replace("_", " ") for item in header]
    header.insert(0, "#")
    return header


def process_tp_inputs(
    tp_type: str,
    tp_parameters: Union[list[str], dict],
    scan_func: Callable[[Optional[str], Optional[dict]], list[TpIntfDescription]],
    header: Literal["device", "target"],
    print_func: Callable[[str], None],
) -> TpIntfDescription:
    """Process input from config file and/or command line and return corresponding interface.

    In case no interface (device/target) is found, function throws an error.
    In case there are more interfaces found, print out a list of interfaces and exit.

    :param tp_type: Type of tp adapter (scard, blhost, ...)
    :param tp_parameters: Parameters specifying TP Interface
    :param scan_func: Function for scanning TP Interfaces
    :param header: String determining potential error message header (device/target)
    :param print_func: Function for displaying potential error message
    :raises SPSDKTpError: No TP Interface (device/target) found
    :return: Designated Interface Description
    """
    if tp_type not in get_tp_device_types() + get_tp_target_types():
        raise SPSDKTpError(f"Unknown {header} type: {tp_type}")
    header_map = {"device": "TP Device", "target": "TP Target"}
    styled_header = header_map[header]
    params = tp_parameters if isinstance(tp_parameters, dict) else multiple_tp_dict(tp_parameters)
    interfaces = scan_func(tp_type, params)
    if not interfaces:
        raise SPSDKTpError(
            f"No {styled_header} found. Search criteria: type={tp_type}; params={params}"
        )
    if len(interfaces) > 1:
        print_func(
            f"{len(interfaces)} {styled_header}s found "
            f"with search criteria type={tp_type}; params={params}"
        )
        print_func(print_device_table(interfaces))
        print_func(f"You need to provide search criteria that fit only one {styled_header}.")
        raise SPSDKTpError()
    return interfaces[0]


###############################################################
# Common options/commands used in both tphost and tpconfig applications


def tp_device_options(options: FC) -> FC:
    """Provides: tp_device: str, tp_device_parameter: List[str]."""
    options = click.option(
        "-dp",
        "--tp-device-parameter",
        type=str,
        multiple=True,
        help="""
The Trusted Device parameters, may be used multiple times to setup TP device interface.
To see available parameters for given TP device, run `tphost/tpconfig device-help`.
Example: -dp id=123456
""",
    )(options)
    options = click.option(
        "-d",
        "--tp-device",
        type=click.Choice(get_tp_device_types(), case_sensitive=False),
        help="The Trusted Device to be used for provisioning target.",
        default=get_tp_device_types()[0] if single_tp_device_adapter() else None,
    )(options)
    return options


def tp_target_options(options: FC) -> FC:
    """Provides: tp_target: str, tp_target_parameter: List[str]."""
    options = click.option(
        "-tp",
        "--tp-target-parameter",
        type=str,
        multiple=True,
        help="""
The Trusted Target parameter, may be used multiple times to setup TP target interface.
To see available parameters for given TP device, run `tphost/tpconfig target-help`.
Example: -tp blhost_baudrate=115200
""",
    )(options)
    options = click.option(
        "-t",
        "--tp-target",
        type=click.Choice(get_tp_target_types(), case_sensitive=False),
        help="The Trusted Target Interface to be used for provisioning process.",
        default=get_tp_target_types()[0] if single_tp_target_adapter() else None,
    )(options)
    return options


@click.command(name="device-help")
@click.option(
    "-d",
    "--tp-device",
    help="Device name to print help, if not used, all devices help will be printed.",
)
def device_help(tp_device: Optional[str] = None) -> None:
    """Command prints help for all devices or optionally only for specified."""
    dev_list = [tp_device] if tp_device else get_tp_device_types()

    for i, dev in enumerate(dev_list):
        click.echo(colorama.Fore.YELLOW + f"#{i}: {dev.upper()} device:")
        click.echo(colorama.Fore.WHITE + get_tp_device_class(dev).get_help() + "\n")
    click.echo(colorama.Style.RESET_ALL)


@click.command(name="target-help")
@click.option(
    "-t",
    "--tp-target",
    help="Target name to print help, if not used, all targets help will be printed.",
)
def target_help(tp_target: Optional[str] = None) -> None:
    """Command prints help for all targets or optionally only for specified."""
    target_list = [tp_target] if tp_target else get_tp_target_types()

    for i, target in enumerate(target_list):
        click.echo(colorama.Fore.YELLOW + f"#{i}: {target.upper()} target:")
        click.echo(colorama.Fore.WHITE + get_tp_target_class(target).get_help() + "\n")
    click.echo(colorama.Style.RESET_ALL)


@click.command(name="list-tptargets", no_args_is_help=not single_tp_target_adapter())
@tp_target_options
def list_tptargets(tp_target: str, tp_target_parameter: list[str]) -> None:
    """Command prints all supported and connected TP targets."""
    tp_targets = scan_tp_targets(tp_target, multiple_tp_dict(tp_target_parameter))
    click.echo(print_device_table(tp_targets))


@click.command(name="list-tpdevices", no_args_is_help=not single_tp_device_adapter())
@tp_device_options
def list_tpdevices(tp_device: str, tp_device_parameter: list[str]) -> None:
    """Command prints all supported and connected TP devices."""
    tp_devices = scan_tp_devices(tp_device, multiple_tp_dict(tp_device_parameter))
    click.echo(print_device_table(tp_devices))


@click.command(name="get-counters", no_args_is_help=False)
@tp_device_options
@click.option(
    "-t",
    "--timeout",
    type=click.IntRange(0, 600, clamp=True),
    help="The target provisioning timeout in seconds.",
)
@spsdk_config_option(
    help="Path to configuration file (parameters on CLI take precedence).",
)
def get_counters(
    tp_device: str,
    tp_device_parameter: list[str],
    timeout: int,
    config: str,
) -> None:
    """Get Provisioning counters from TP device."""
    TPHostConfig.SCHEMA_MEMBERS = ["device"]
    tp_config = TPHostConfig(
        tp_device=tp_device,
        tp_device_parameter=tp_device_parameter,
        config=config,
        timeout=timeout,
    )
    device = tp_config.tp_device
    params = tp_config.tp_device_parameter

    tp_interface = process_tp_inputs(
        tp_type=device,
        tp_parameters=params,
        header="device",
        scan_func=scan_tp_devices,
        print_func=click.echo,
    )
    tp_dev = tp_interface.create_interface()
    assert isinstance(tp_dev, TpDevInterface)

    tp_worker = TrustProvisioningHost(
        tpdev=tp_dev,
        tptarget=None,  # type: ignore  # target is not used, we set it to None on purpose
        info_print=click.echo,
    )
    tp_worker.get_counters()
