/*
 * Copyright (c) 2015, Freescale Semiconductor, Inc.
 * Copyright 2016-2019 NXP
 * All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "board.h"
#include "fsl_debug_console.h"
#include "fsl_gpio.h"

#include "pin_mux.h"
#include "clock_config.h"
/*******************************************************************************
 * Definitions
 ******************************************************************************/
#define APP_BOARD_TEST_LED_PORT 0U
#define APP_BOARD_TEST_LED_PIN 14U
#define APP_SW_PORT 0U
#define APP_SW_PIN 10U

/*******************************************************************************
 * Prototypes
 ******************************************************************************/

/*******************************************************************************
 * Variables
 ******************************************************************************/
volatile uint32_t g_systickCounter;

/*******************************************************************************
 * Code
 ******************************************************************************/
void SysTick_Handler(void)
{
    if (g_systickCounter != 0U)
    {
        g_systickCounter--;
    }
}

void SysTick_DelayTicks(uint32_t n)
{
    g_systickCounter = n;
    while (g_systickCounter != 0U)
    {
    }
}

void write_shadows() {
    *((uint32_t*)0x87654320) = 0xBEBADED0;
    *((uint32_t*)0x87654321) = 0xBEBADED1;
    *((uint32_t*)0x87654322) = 0xBEBADED2;
    *((uint32_t*)0x87654323) = 0xBEBADED3;
    *((uint32_t*)0x87654324) = 0xBEBADED4;
    *((uint32_t*)0x87654325) = 0xBEBADED5;
    *((uint32_t*)0x87654326) = 0xBEBADED6;
    *((uint32_t*)0x87654327) = 0xBEBADED7;
    *((uint32_t*)0x87654328) = 0xBEBADED8;
    *((uint32_t*)0x87654329) = 0xBEBADED9;
    *((uint32_t*)0x8765432A) = 0xBEBADEDA;
    *((uint32_t*)0x8765432B) = 0xBEBADEDB;
}
  

/*!
 * @brief Main function
 */
int main(void)
{
    /* Define the init structure for the output LED pin*/
    gpio_pin_config_t led_config = {
        kGPIO_DigitalOutput,
        0,
    };

    BOARD_InitPins();

    write_shadows();
    
    /* Init output LED GPIO. */
    GPIO_PortInit(GPIO, APP_BOARD_TEST_LED_PORT);
    GPIO_PortInit(GPIO, APP_SW_PORT);
    GPIO_PinInit(GPIO, APP_BOARD_TEST_LED_PORT, APP_BOARD_TEST_LED_PIN, &led_config);
    GPIO_PinWrite(GPIO, APP_BOARD_TEST_LED_PORT, APP_BOARD_TEST_LED_PIN, 1);

    /* Port masking */
    GPIO_PortMaskedSet(GPIO, APP_BOARD_TEST_LED_PORT, 0x0000FFFF);
    GPIO_PortMaskedWrite(GPIO, APP_BOARD_TEST_LED_PORT, 0xFFFFFFFF);
    GPIO_PortRead(GPIO, APP_BOARD_TEST_LED_PORT);
    GPIO_PortMaskedRead(GPIO, APP_BOARD_TEST_LED_PORT);

    /* Set systick reload value to generate 1ms interrupt */
    SysTick_Config(SystemCoreClock / 1000U);

    /* Blink LED several times to confirm the application is running */  
    int blink_count = 16;
    while (--blink_count)
    {
        GPIO_PortToggle(GPIO, APP_BOARD_TEST_LED_PORT, 1u << APP_BOARD_TEST_LED_PIN);
        /* Delay */
        SysTick_DelayTicks(10000U);
    }

    /* RESET back to boot-loader */  
    SCB->AIRCR =
        (SCB->AIRCR & ~SCB_AIRCR_VECTKEY_Msk) | (0x05FAUL << SCB_AIRCR_VECTKEY_Pos) | SCB_AIRCR_SYSRESETREQ_Msk;
}
