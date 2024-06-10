/**
* \file   led.h
* \author Trung Tin Nguyen (1120436), and Dung Anh Huynh Pham (764527) (wrote based on Prof. Jakob's "hello_world_small.c" program)
* \date   04.01.2024
*
* \brief LED configuration
*
*
*
* \note <notes>
* \todo <todos>
* \warning <warnings, e.g. dependencies, order of execution etc.>
*
*  Changelog:\n
*  - <version; data of change; author>
*            - <description of the change>
*
* \copyright Copyright ©2023
* Department of electrical engineering and information technology, Hochschule Darmstadt - University of applied sciences (h_da). All Rights Reserved.
* Permission to use, copy, modify, and distribute this software and its documentation for educational, and research purposes in the context of non-commercial
* (unless permitted by h_da) and official h_da projects, is hereby granted for enrolled students of h_da, provided that the above copyright notice,
* this paragraph and the following paragraph appear in all copies, modifications, and distributions.
*
* Contact Prof.Dr. C. Jakob, christian.jakob@h-da.de, Birkenweg 8 64295 Darmstadt - GERMANY for commercial requests.
*
* \warning This software is a PROTOTYPE version and is not designed or intended for use in production, especially not for safety-critical applications!
* The user represents and warrants that it will NOT use or redistribute the Software for such purposes.
* This prototype is for research purposes only. This software is provided "AS IS," without a warranty of any kind.
**/

#ifndef MYCODE_LED_H_
#define MYCODE_LED_H_


#include "system.h"


typedef unsigned int alt_u32;

#define __I volatile const 	// read-only permission
#define __IO volatile 		// read/write permission ...
#define __O volatile 		// write only permission ;-) doesn't work in C...

//PIO_OUTPUT unit structure
typedef struct {
	__IO alt_u32 DATA_REG;
	__IO alt_u32 DIRECTION_REG;
	__IO alt_u32 INTERRUPTMASK_REG;
	__IO alt_u32 EDGECAPTURE_REG;
	 __O alt_u32 OUTSET_REG;
	 __O alt_u32 OUTCLEAR_REG;
} PIO_TYPE;

//Base address of the PIO output unit SYS_PIO_OUT_BASE in "system.h"
//append that address into this pointer expression
//MSB is set to one to bypass the data cache
#define LEDS (*((PIO_TYPE *) 0x80011020 ))


#endif /* MYCODE_LED_H_ */
