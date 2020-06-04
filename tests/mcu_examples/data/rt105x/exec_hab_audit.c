/*
 * Copyright 2020 NXP
 * All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * The application is linked in RAM at 0x20018000
 */

#include "board.h"

#include "pin_mux.h"
#include "system_MIMXRT1052.h"
#include "clock_config.h"
/*******************************************************************************
 * Definitions
 ******************************************************************************/
#define EXAMPLE_LED_GPIO BOARD_USER_LED_GPIO
#define EXAMPLE_LED_GPIO_PIN BOARD_USER_LED_PIN


/**********************************************************************************************/
/*  HAB  **************************************************************************************/
/**********************************************************************************************/

uint8_t logs[1024] = {0xA5, 0x5A, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF};

enum hab_config {
	HAB_CFG_RETURN = 0x33,	/* < Field Return IC */
	HAB_CFG_OPEN = 0xf0,	/* < Non-secure IC */
	HAB_CFG_CLOSED = 0xcc	/* < Secure IC */
};

/* State definitions */
enum hab_state {
	HAB_STATE_INITIAL = 0x33,	/* Initialising state (transitory) */
	HAB_STATE_CHECK = 0x55,		/* Check state (non-secure) */
	HAB_STATE_NONSECURE = 0x66,	/* Non-secure state */
	HAB_STATE_TRUSTED = 0x99,	/* Trusted state */
	HAB_STATE_SECURE = 0xaa,	/* Secure state */
	HAB_STATE_FAIL_SOFT = 0xcc, /* Soft fail state */
	HAB_STATE_FAIL_HARD = 0xff, /* Hard fail state (terminal) */
	HAB_STATE_NONE = 0xf0,		/* No security state machine */
	HAB_STATE_MAX
};

enum hab_status {
	HAB_STS_ANY = 0x00,
	HAB_FAILURE = 0x33,
	HAB_WARNING = 0x69,
	HAB_SUCCESS = 0xf0
};

#define HAB_RVT_BASE				0x200300

#define HAB_RVT_ENTRY				(*(uint32_t *)(HAB_RVT_BASE + 0x04))
#define HAB_RVT_EXIT				(*(uint32_t *)(HAB_RVT_BASE + 0x08))
#define HAB_RVT_AUTHENTICATE_IMAGE	(*(uint32_t *)(HAB_RVT_BASE + 0x2C))
#define HAB_RVT_REPORT_EVENT		(*(uint32_t *)(HAB_RVT_BASE + 0x20))
#define HAB_RVT_REPORT_STATUS		(*(uint32_t *)(HAB_RVT_BASE + 0x24))


/*******************************************************************************
 * Prototypes
 ******************************************************************************/
typedef enum hab_status hab_loader_callback_f_t(void**, size_t*, const void*);
typedef enum hab_status hab_rvt_entry_t(void);
typedef enum hab_status hab_rvt_exit_t(void);
typedef enum hab_status hab_rvt_report_event_t(enum hab_status, uint32_t, uint8_t* , size_t*);
typedef enum hab_status hab_rvt_report_status_t(enum hab_config *, enum hab_state *);
typedef uint32_t hab_rvt_authenticate_image_t(uint8_t, int, void **, size_t *, hab_loader_callback_f_t);



/*******************************************************************************
 * Code
 ******************************************************************************/

/*
 * The following function authenticate the application and reads the HAB log.
 * Resulting status LOG is stored into `logs` static variable
 * The function
 */
uint32_t exec_hab_audit(uint32_t authenticate) {
    /* The following code can be used to turn ON the LED, to ensure, the function was properly executed */
	//BOARD_InitPins();
    //GPIO_PinWrite(EXAMPLE_LED_GPIO, EXAMPLE_LED_GPIO_PIN, 0);

    memset(logs, 0x00, sizeof(logs));

	//check that external FLASH is readable
 	uint32_t pc = (*(uint32_t *)(0x60001004));
 	if ((pc < 0x60000000UL) || (pc >= 0x60010000UL)) {
 		//FLASH not accessible or PC outside expected range
 		memset(logs, 0xFF, 4);
 		return 0;
 	}

    hab_rvt_entry_t *hab_rvt_entry = ((hab_rvt_entry_t *)HAB_RVT_ENTRY);
	hab_rvt_exit_t *hab_rvt_exit = ((hab_rvt_entry_t *)HAB_RVT_EXIT);
    hab_rvt_authenticate_image_t *hab_rvt_authenticate_image = ((hab_rvt_authenticate_image_t *)HAB_RVT_AUTHENTICATE_IMAGE);
	hab_rvt_report_status_t *hab_rvt_report_status = ((hab_rvt_report_status_t *)HAB_RVT_REPORT_STATUS);
	hab_rvt_report_event_t *hab_rvt_report_event = ((hab_rvt_report_event_t *)HAB_RVT_REPORT_EVENT);

    if (authenticate) {
    	(int)hab_rvt_entry();

    	/*Image authentication. Parameters:
    	[in] cid Caller ID, used to identify which SW issued this call.
    	[in] ivt_offset Address of target region
    	[in,out] start Initial (possibly partial) image load address on entry. Final image load address on exit.
    	[in,out] bytes Initial (possibly partial) image size on entry. Final image size on exit.
    	[in] loader Callback function to load the full image to its final load address. Set to NULL if not required.*/
    	uint32_t start = 0x60000000UL;
    	size_t len = 0x20000U;
    	hab_rvt_authenticate_image(0x0, 0x1000, (void **)&start, (size_t *)&len, NULL);

    	(int)hab_rvt_exit();
    }

	enum hab_config config = 0xFF;
	enum hab_state state = 0xFF;

	/* Check HAB status */
	logs[0] = hab_rvt_report_status(&config, &state);
	logs[1] = config;
    logs[2] = state;
	if (logs[0] != HAB_SUCCESS) {
		uint8_t * d_logs = logs + 4;
		uint32_t index = 0; /* Loop index */
		uint8_t event_data[128]; /* Event data buffer */
		size_t bytes = sizeof(event_data); /* Event size in bytes */
		/* Read HAB events */
		while (hab_rvt_report_event(HAB_STS_ANY, index, event_data, &bytes) == HAB_SUCCESS) {
			memcpy(d_logs, event_data, bytes);
			d_logs += bytes;
			index++;
		}
	}

    return 0;
}



/*!
 * @brief Main function
 */
int main(void)
{
	exec_hab_audit(1);

	//loop forever
    while (1) ;
}
