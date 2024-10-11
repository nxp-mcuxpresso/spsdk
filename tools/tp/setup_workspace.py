#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2021-2024 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""Script to setup workspace for Trust Provisioning models."""

import os
import shutil
import sys
from typing import Sequence, cast

import ruamel.yaml
from InquirerPy import inquirer
from InquirerPy.utils import get_style
from InquirerPy.validator import NumberValidator, ValidationError
from prompt_toolkit.validation import Document

from spsdk.tp.adapters import TpDevSmartCard
from spsdk.tp.utils import get_tp_devices
from spsdk.utils.database import DatabaseManager, get_common_data_file_path, get_db, get_families
from spsdk.utils.nxpdevscan import UartDeviceDescription, search_nxp_uart_devices

# import logging
# logging.basicConfig(level=logging.INFO)
# logger = logging.getLogger(__name__)

VERBOSITY = {"normal": "", "verbose": "--verbose", "debug": "--debug"}
THIS_DIR = os.path.dirname(os.path.abspath(__file__))
SAMPLE_DATA_DIR_NAME = "sample_config_data"
SAMPLE_DATA_DIR = os.path.join(THIS_DIR, SAMPLE_DATA_DIR_NAME)


class HexNumberValidator(NumberValidator):
    """Help class to validate hexadecimal number."""

    def validate(self, document: Document) -> None:
        """Validate hexadecimal number.

        :param document: Document with hex number in text
        :raises ValidationError: No valid hexadecimal number
        """
        try:
            int(document.text, 0)
        except ValueError as e:
            raise ValidationError(
                message=self._message,  # pylint: disable=no-member
                cursor_position=document.cursor_position,
            ) from e


def setup_tp_device_model(tp_device_id: str, use_prov_data: bool, family: str) -> str:
    """Setup Trust Provisioning device models.

    :param tp_device_id: TODO
    :param use_prov_data: TODO
    :param family: TODO
    :return: TODO
    """
    model_top_dir = "tp_device_models"
    model_sub_dir = f"tp_device_{tp_device_id}"
    model_dir = f"{model_top_dir}/{model_sub_dir}"
    shutil.copytree(f"{THIS_DIR}/blank_device", model_dir)

    yaml = ruamel.yaml.YAML()
    with open(f"{model_dir}/config.yaml") as f:
        data = yaml.load(f)
    data["id"] = tp_device_id
    data["use_prov_data"] = use_prov_data
    data["data"]["family"] = family
    with open(f"{model_dir}/config.yaml", "w") as f:
        yaml.dump(data, f)

    models_file = f"{model_top_dir}/models.yaml"
    with open(models_file, "w") as f:
        yaml.dump([f"{model_sub_dir}/config.yaml"], f)
    return models_file


def setup_tp_target_model(tp_target_id: str, use_prov_data: bool, family: str) -> str:
    """Setup Trust Provisioning target models.

    :param tp_target_id: TODO
    :param use_prov_data: TODO
    :param family: TODO
    :return: TODO
    """
    model_top_dir = "tp_target_models"
    model_sub_dir = f"tp_target_{tp_target_id.split('/')[-1]}"
    model_dir = f"{model_top_dir}/{model_sub_dir}"
    shutil.copytree(f"{THIS_DIR}/blank_target", model_dir)

    yaml = ruamel.yaml.YAML()
    with open(f"{model_dir}/config.yaml") as f:
        data = yaml.load(f)
    data["id"] = tp_target_id
    data["use_prov_data"] = use_prov_data
    data["family"] = family
    data["name"] = family
    with open(f"{model_dir}/config.yaml", "w") as f:
        yaml.dump(data, f)

    models_file = f"{model_top_dir}/models.yaml"
    with open(models_file, "w") as f:
        yaml.dump([f"{model_sub_dir}/config.yaml"], f)
    return models_file


def setup_tp_config_file(
    default_tpconfig_data: bool,
    tp_device: str,
    tp_device_parameter: dict,
    family: str,
    use_prov_data: bool,
) -> None:
    """Setup Trust Provisioning configuration file.

    :param default_tpconfig_data: TODO
    :param tp_device: TODO
    :param tp_device_parameter: TODO
    :param family: TODO
    :param use_prov_data: TODO
    """
    template_name = (
        "tpconfig_cfg_data_template.yaml" if use_prov_data else "tpconfig_cfg_template.yaml"
    )
    shutil.copy(get_common_data_file_path(os.path.join("tp", template_name)), "tp_config.yaml")
    yaml = ruamel.yaml.YAML()
    with open("tp_config.yaml") as f:
        data: dict = yaml.load(f)

    data["family"] = family
    data["tp_device"] = tp_device
    data["tp_device_parameter"] = tp_device_parameter

    if default_tpconfig_data:
        if not os.path.isdir(SAMPLE_DATA_DIR_NAME):
            shutil.copytree(SAMPLE_DATA_DIR, "sample_config_data")
        sample_file = "tp_config_data_prov.yaml" if use_prov_data else "tp_config_data.yaml"
        with open(f"{SAMPLE_DATA_DIR}/{sample_file}") as f:
            default_data = yaml.load(f)
        data.update(default_data)
    with open("tp_config.yaml", "w") as f:
        yaml.dump(data, f)


def setup_tp_host_file(
    default_tphost_data: bool,
    tp_device: str,
    tp_device_parameter: dict,
    tp_target: str,
    tp_target_parameter: dict,
    family: str,
) -> None:
    """Setup Trust Provisioning host file.

    :param default_tphost_data: TODO
    :param tp_device: TODO
    :param tp_device_parameter: TODO
    :param tp_target: TODO
    :param tp_target_parameter: TODO
    :param family: TODO
    """
    shutil.copy(
        get_common_data_file_path(os.path.join("tp", "tphost_cfg_template.yaml")), "tp_host.yaml"
    )
    yaml = ruamel.yaml.YAML()
    with open("tp_host.yaml") as f:
        data: dict = yaml.load(f)

    data["family"] = family
    data["tp_device"] = tp_device
    data["tp_device_parameter"] = tp_device_parameter
    data["tp_target"] = tp_target
    data["tp_target_parameter"] = tp_target_parameter

    if default_tphost_data:
        if not os.path.isdir(SAMPLE_DATA_DIR_NAME):
            shutil.copytree(SAMPLE_DATA_DIR, "sample_config_data")
        with open(f"{SAMPLE_DATA_DIR}/tp_host_data.yaml") as f:
            default_data = yaml.load(f)
        data.update(default_data)

    with open("tp_host.yaml", "w") as f:
        yaml.dump(data, f)


def get_cards() -> list[str]:
    """Get all viable cards.

    :raises RuntimeError: No viable Smart Cards found
    :return: List of cards
    """
    tp_devices = cast(Sequence[TpDevSmartCard], get_tp_devices())
    if not tp_devices:
        raise RuntimeError("No viable Smart Cards found")
    result = [
        f"{device.descriptor.serial_number} @ {device.card_connection.getReader()}"  # type: ignore
        for device in tp_devices
    ]
    return result


def get_card_id(info: str) -> str:
    """Get TP card ID from its information string.

    :param info: Card information string
    :return: ID of card
    """
    return info.split("@")[0].strip()


def get_uart_targets() -> list[str]:
    """Get all UART targets.

    :raises RuntimeError: No viable UART MBoot devices found
    :return: List of UART targets
    """
    tp_targets = cast(Sequence[UartDeviceDescription], search_nxp_uart_devices())
    if not tp_targets:
        raise RuntimeError("No viable UART MBoot devices found")
    result = [target.name for target in tp_targets]
    return result


def setup_runner_files(verbosity: str) -> None:
    """Setup runner files.

    :param verbosity: Verbosity level
    """
    verbosity = VERBOSITY[verbosity]

    def render_command(command: str, use_f_string: bool = False) -> str:
        result = [
            f'command = {"f" if use_f_string else ""}"{command}"',
            'print(f"Running: {command}")',
            "subprocess.check_call(command.split())\n",
        ]
        return "\n".join(result)

    # TODO: if you figure out the blank lines in Jinja, please change this mess :D
    with open("run_tp_config.py", "w") as f:
        command = f"tpconfig {verbosity} load --config tp_config.yaml"

        f.write("import os\nimport subprocess\n\nimport yaml\n\n")
        f.write("os.chdir(os.path.dirname(__file__))\n\n")
        f.write('with open("tp_host.yaml") as f:\n')
        f.write("    data = yaml.safe_load(f)\n")
        f.write('tp_log_file = data["audit_log"]\n')
        f.write("try:\n    os.remove(tp_log_file)\n")
        f.write("except FileNotFoundError:\n    pass\n\n")
        f.write(render_command(command=command))

    with open("run_tp_host.py", "w") as f:
        command = f"tphost {verbosity} load --config tp_host.yaml"
        f.write("import os\nimport subprocess\n\n")
        f.write("os.chdir(os.path.dirname(__file__))\n\n")
        f.write(render_command(command=command))

    with open("run_tp_verify.py", "w") as f:
        command = f"tphost {verbosity}" + " verify -l {tp_log_file} -k {tp_key_file}"
        f.write("import os\nimport subprocess\n\nimport yaml\n\n")
        f.write("os.chdir(os.path.dirname(__file__))\n\n")
        f.write('with open("tp_host.yaml") as f:\n')
        f.write("    data = yaml.safe_load(f)\n")
        f.write('tp_log_file = data["audit_log"]\n')
        f.write('tp_key_file = data["audit_log_key"]\n\n')
        f.write(render_command(command=command, use_f_string=True))


def main() -> None:
    """Setup Trust provisioning workspace."""
    dest_path = inquirer.filepath(
        message="Destination for new workspace:",
        only_directories=True,
    ).execute()
    if os.path.isdir(dest_path):
        delete_confirm = inquirer.confirm(
            message=(
                "Destination already exists!!! "
                "Do you want to continue? (existing folder will be deleted)"
            ),
            default=False,
            style=get_style({"question": "#ff0000"}),
        ).execute()
        if not delete_confirm:
            sys.exit()
    family = inquirer.rawlist(
        message="Select family",
        choices=get_families(DatabaseManager.TP),
        default="lpc55s3x",
    ).execute()
    tp_device_type = inquirer.rawlist(
        message="Which type of TPDevice to use:",
        choices=["scard", "swmodel"],
        default="scard",
    ).execute()
    if tp_device_type == "scard":
        scan_for_scard = inquirer.confirm(
            message="Scan for connected cards now?",
            default=True,
            transformer=lambda x: "scanning for cards with TP Applet" if x else "scan cancelled",
            long_instruction="If you skip scanning, make sure to update 'id' manually",
        ).execute()
        if scan_for_scard:
            tp_device_id = inquirer.rawlist(
                message="Select Smart Card",
                choices=get_cards(),
                transformer=lambda x: f"id={get_card_id(x)}",
            ).execute()
            tp_device_id = get_card_id(tp_device_id)
        else:
            tp_device_id = "smart_card_id_placeholder"
    if tp_device_type == "swmodel":
        tp_device_id = inquirer.text(
            message="Provide ID for the device model:",
            default="1234",
        ).execute()

    tp_target_type = inquirer.select(
        message="Which type of TPTarget to use:",
        choices=["blhost_uart", "swmodel"],
        default="blhost_uart",
    ).execute()

    if tp_target_type == "blhost_uart":
        scan_for_uart = inquirer.confirm(
            message="Scan for connected MBoot devices via UART?",
            default=True,
            transformer=lambda x: "scanning for MBoot UART devices" if x else "scan cancelled",
            long_instruction="If you skip scanning, make sure to update 'blhost_com' manually",
        ).execute()
        if scan_for_uart:
            port = inquirer.rawlist(
                message="Select MBoot UART device",
                choices=get_uart_targets(),
            ).execute()
        else:
            port = "blhost_com_port_placeholder"
        baud_rate = inquirer.rawlist(
            message="Select UART baud rate",
            choices=["256_000", "115_200", "57_600", "19_200", "9_600"],
            default="115_200",
        ).execute()
        uart_timeout = inquirer.text(
            message="Provide UART timeout in ms",
            default="5_000",
            validate=HexNumberValidator(),
        ).execute()
    if tp_target_type == "swmodel":
        tp_target_id = inquirer.text(
            message="Provide ID for the target model:",
            default="comX",
        ).execute()

    default_tpconfig_data = inquirer.confirm(
        message="Setup TPConfig config file with default data",
        default=True,
    ).execute()

    default_tphost_data = inquirer.confirm(
        message="Setup TPHost config file with default data",
        default=True,
    ).execute()

    setup_runners = inquirer.confirm(
        message="Setup helper runner scripts?",
        default=True,
    ).execute()
    if setup_runners:
        verbosity = inquirer.select(
            message="Select helper output verbosity",
            choices=list(VERBOSITY.keys()),
            default=list(VERBOSITY.keys())[1],
        ).execute()

    final_check = inquirer.confirm(
        message="Proceed with workspace creation using info above?",
        default=True,
    ).execute()
    if not final_check:
        sys.exit()

    if os.path.isdir(dest_path):
        shutil.rmtree(dest_path, ignore_errors=False)
    os.makedirs(dest_path, exist_ok=False)
    os.chdir(dest_path)

    use_prov_data = get_db(family, "latest").get_bool(DatabaseManager.TP, "use_prov_data")

    tp_device_params = {"id": tp_device_id}
    if tp_device_type == "swmodel":
        model_file = setup_tp_device_model(
            tp_device_id=tp_device_id, use_prov_data=use_prov_data, family=family
        )
        tp_device_params.update({"config_file": model_file})

    tp_target_params = {}
    if tp_target_type == "swmodel":
        model_file = setup_tp_target_model(
            tp_target_id=tp_target_id, use_prov_data=use_prov_data, family=family
        )
        tp_target_params = {
            "config_file": model_file,
            "id": tp_target_id,
        }
    if tp_target_type == "blhost_uart":
        tp_target_type = "blhost"
        tp_target_params = {
            "blhost_timeout": uart_timeout,
            "blhost_port": port,
            "blhost_baudrate": baud_rate,
        }

    setup_tp_config_file(
        default_tpconfig_data=default_tpconfig_data,
        tp_device=tp_device_type,
        tp_device_parameter=tp_device_params,
        family=family,
        use_prov_data=use_prov_data,
    )

    setup_tp_host_file(
        default_tphost_data=default_tphost_data,
        tp_device=tp_device_type,
        tp_device_parameter=tp_device_params,
        tp_target=tp_target_type,
        tp_target_parameter=tp_target_params,
        family=family,
    )

    if setup_runners:
        setup_runner_files(verbosity=verbosity)

    print(f"\nMake sure to review tp_config.yaml and tp_host.yaml in '{dest_path}'")


if __name__ == "__main__":
    main()
