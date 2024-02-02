# NXP Secure Provisioning SDK

**Secure Provisioning SDK (SPSDK)** enables connection and communication with target devices for purposes of secure provisioning and programming. Delivered as python library with command-line applications for direct utilization.

<img src="docs/_static/images/spsdk-architecture.png" alt="drawing" width="600"/>

## Links

* [GitHub](https://github.com/NXPmicro/spsdk)
* [PyPi](https://pypi.org/project/spsdk/)
* [Documentation](https://spsdk.readthedocs.io)
* [Project page](https://www.nxp.com/design/software/development-software/secure-provisioning-sdk-spsdk:SPSDK)

## Supported Devices

Following NXP devices are supported:

- LPC55 [S6x](https://www.nxp.com/products/processors-and-microcontrollers/arm-microcontrollers/general-purpose-mcus/lpc5500-cortex-m33/high-efficiency-arm-cortex-m33-based-microcontroller-family:LPC55S6x) / [S3x](https://www.nxp.com/products/processors-and-microcontrollers/arm-microcontrollers/general-purpose-mcus/lpc5500-arm-cortex-m33/lpc553x-s3x-advanced-analog-armcortex-m33-based-mcu-family:LPC553x) / [S2x](https://www.nxp.com/products/processors-and-microcontrollers/arm-microcontrollers/general-purpose-mcus/lpc5500-cortex-m33/lpc552x-s2x-mainstream-arm-cortex-m33-based-microcontroller-family:LPC552x-S2x) / [S1x](https://www.nxp.com/products/processors-and-microcontrollers/arm-microcontrollers/general-purpose-mcus/lpc5500-cortex-m33/lpc551x-s1x-baseline-arm-cortex-m33-based-microcontroller-family:LPC551X-S1X) / [S0x](https://www.nxp.com/products/processors-and-microcontrollers/arm-microcontrollers/general-purpose-mcus/lpc5500-cortex-m33/lpc550x-s0x-baseline-arm-cortex-m33-based-microcontroller-family:LPC550x)
- i.MX RT [600](https://www.nxp.com/products/processors-and-microcontrollers/arm-microcontrollers/i-mx-rt-crossover-mcus/i-mx-rt600-crossover-mcu-with-arm-cortex-m33-and-dsp-cores:i.MX-RT600) / [500](https://www.nxp.com/products/processors-and-microcontrollers/arm-microcontrollers/i-mx-rt-crossover-mcus/i-mx-rt500-crossover-mcu-with-arm-cortex-m33-core:i.MX-RT500)
- i.MX RT [1064](https://www.nxp.com/products/processors-and-microcontrollers/arm-microcontrollers/i-mx-rt-crossover-mcus/i-mx-rt1064-crossover-mcu-with-arm-cortex-m7-core:i.MX-RT1064) / [1060](https://www.nxp.com/products/processors-and-microcontrollers/arm-microcontrollers/i-mx-rt-crossover-mcus/i-mx-rt1060-crossover-mcu-with-arm-cortex-m7-core:i.MX-RT1060) / [1050](https://www.nxp.com/products/processors-and-microcontrollers/arm-microcontrollers/i-mx-rt-crossover-mcus/i-mx-rt1050-crossover-mcu-with-arm-cortex-m7-core:i.MX-RT1050) / [1024](https://www.nxp.com/products/processors-and-microcontrollers/arm-microcontrollers/i-mx-rt-crossover-mcus/i-mx-rt1024-crossover-mcu-with-arm-cortex-m7-core-operating-up-to-500-mhz-with-4-mb-flash:i.MX-RT1024) / [1020](https://www.nxp.com/products/processors-and-microcontrollers/arm-microcontrollers/i-mx-rt-crossover-mcus/i-mx-rt1020-crossover-mcu-with-arm-cortex-m7-core:i.MX-RT1020) / [1010](https://www.nxp.com/products/processors-and-microcontrollers/arm-microcontrollers/i-mx-rt-crossover-mcus/i-mx-rt1010-crossover-mcu-with-arm-cortex-m7-core:i.MX-RT1010) / [1015](https://www.nxp.com/products/processors-and-microcontrollers/arm-microcontrollers/i-mx-rt-crossover-mcus/i-mx-rt1015-crossover-mcu-with-arm-cortex-m7-core-operating-up-to-500-mhz:i.MX-RT1015)
- i.MX RT [1180](https://www.nxp.com/products/processors-and-microcontrollers/arm-microcontrollers/i-mx-rt-crossover-mcus/i-mx-rt1180-crossover-mcu-dual-core-arm-cortex-m7-and-cortex-m33-with-tsn-switch:i.MX-RT1180) / [1170](https://www.nxp.com/products/processors-and-microcontrollers/arm-microcontrollers/i-mx-rt-crossover-mcus/i-mx-rt1170-crossover-mcu-family-first-ghz-mcu-with-arm-cortex-m7-and-cortex-m4-cores:i.MX-RT1170) / [1160](https://www.nxp.com/design/development-boards/i-mx-evaluation-and-development-boards/i-mx-rt1160-evaluation-kit:MIMXRT1160-EVK)
- [KW45](https://www.nxp.com/products/wireless/bluetooth-low-energy/32-bit-bluetooth-5-3-long-range-mcus-with-can-fd-and-lin-bus-options-arm-cortex-m33-core:KW45)
- [K32W1](https://www.nxp.com/products/wireless/multiprotocol-mcus/tri-core-secure-and-ultra-low-power-mcu-for-matter-over-thread-and-bluetooth-le-5-3:K32W148)
- [MCXN9xx](https://www.nxp.com/products/processors-and-microcontrollers/arm-microcontrollers/general-purpose-mcus/mcx-arm-cortex-m/mcx-n-series/mcx-n94x-and-n54x-mcus-with-dual-core-arm-cortex-m33-edgelock-secure-subsystem-and-neural-processing-unit:MCX-N94X-N54X)
- [RW610](https://www.nxp.com/products/wireless/wi-fi-plus-bluetooth-plus-802-15-4/wireless-mcu-with-integrated-tri-radiobr1x1-wi-fi-6-plus-bluetooth-low-energy-5-3-802-15-4:RW612)
- [NHS52Sxx](https://www.nxp.com/products/wireless-connectivity/bluetooth-low-energy/nhs52sx4-ultra-low-power-bluetooth-low-energy-solution-with-arm-cortex-m33-trustzone-for-medical-iot:NHS52Sx4)
- [MCXA1xx] (https://www.nxp.com/products/processors-and-microcontrollers/arm-microcontrollers/general-purpose-mcus/mcx-arm-cortex-m:MCX-MCUS)
- [MCXN23x] (https://www.nxp.com/products/processors-and-microcontrollers/arm-microcontrollers/general-purpose-mcus/mcx-arm-cortex-m:MCX-MCUS)

## Supported environments

Windows 10 and 11, 64bit
Ubuntu 22.04.1 LTS
Mac OS Sonoma 14

## Usage

- See [installation](https://spsdk.readthedocs.io/en/latest/usage/installation.html) guide
- See [examples](examples) directory
- See [application](spsdk/apps) directory

---

## Dependencies

The core dependencies are included in [requirements.txt](requirements.txt).

The dependencies for the development and testing are included in [requirements-develop.txt](requirements-develop.txt).
