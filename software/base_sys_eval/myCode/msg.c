/**
* \file   msg.c
* \author Trung Tin Nguyen (1120436), and Dung Anh Huynh Pham (764527)
* \date   14.12.2023
*
* \brief contain APIs to convert string into uint32_t array containing HEX values of each ASCII character.
*
* This file contains APIs that can represent the input string as an array of uint32_t values
*  storing the HEX values of each ASCII character.
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
*/

/*****************************************************************************/
/* Include files                                                             */
/*****************************************************************************/
#include "sys/alt_stdio.h"
#include <stdlib.h>	//for the usage of malloc
#include <string.h> //for the usage of strlen()

#include "msg.h"


/*****************************************************************************/
/* Function implementation - global ('extern') and local ('static')          */
/*****************************************************************************/

/**
 * \brief Initialization of the Message Object.
 *
 *	The function represents a string as a uint32_t* by storing the ASCII values of the characters in an
 * array of uint32_t variables.
 *
 * \param MSG_message_t* message : IN - the Message Object that contains an uin32_t array representation of the input string
 * \param const char* string : IN - the input string
 * \param uint32_t stringLength : IN - the input string length
 */
void MSG_init(MSG_message_t* message, const char* string, uint32_t stringLength)
{
	message->m_stringLength = stringLength;

	//allocate memory for the string
	// '+1' here to make place for null-termination
	message->m_string = (char *)malloc((message->m_stringLength +1 ) * sizeof(char));
	if(message->m_string == NULL)
	{
		//TODO: add error handling
		alt_printf("Memory allocation failed\n");
	}

	//initialize values of message->string by copying the input string into it
	strcpy(message->m_string, string);

	//an uint32_t variable can hold 4 ASCII characters, null-termination is not considered
	//=> number of elements in the array is: (stringLegth + 3) / 4
	message->m_numOfElementsInUint32Array = (uint32_t)((message->m_stringLength + 3) / 4);

	//allocate memory to store each character of the string
	message->m_uint32Array = (uint32_t*)malloc(message->m_numOfElementsInUint32Array * sizeof(uint32_t));
	if(message->m_uint32Array == NULL)
	{
		//TODO: add error handling
		alt_printf("Memory allocation failed\n");
	}

	//assigning the characters to the elements of the uint32_t array. in Big Endian
	for(uint32_t i = 0; i < message->m_stringLength; i++)
	{
		//Initialize to 0 at the start of each group of 4 characters (4 * 8bit = 32 bit)
		//<=> start of an uint32_t element
		if(i % 4 == 0)
		{
			//index of new element starts at 0, 4, 8, etc.
			message->m_uint32Array[i / 4] = 0;
		}

		message->m_uint32Array[i/4] = (message->m_uint32Array[i/4] << 8) | message->m_string[i];
	}

	//check if there are leading zeros and then perform a left shift
	uint32_t lastElementIndex = message->m_numOfElementsInUint32Array - 1;

	if ((message->m_uint32Array[lastElementIndex] & 0xFFFFFF00) == 0)
	{
		// Perform left shift if true
		message->m_uint32Array[lastElementIndex] = message->m_uint32Array[lastElementIndex] << 24;
	}
	else if ((message->m_uint32Array[lastElementIndex] & 0xFFFF0000) == 0)
	{
		// Perform left shift if true
		message->m_uint32Array[lastElementIndex] = message->m_uint32Array[lastElementIndex] << 16;
	}
	else if ((message->m_uint32Array[lastElementIndex] & 0xFF000000) == 0)
	{
		// Perform left shift if true
		message->m_uint32Array[lastElementIndex] = message->m_uint32Array[lastElementIndex] << 8;
	}
}

/**
 * \brief function to print out the 32-bit representation of the string.
 *
 * \param MSG_message_t* message : IN - the Message Object that contains an uin32_t array representation of the input string
 */
void MSG_printUint32Representation(MSG_message_t* message)
{
	alt_printf("The string \"%s\" represented as an array of uint32_t elements: \n", message->m_string);

	for(uint64_t i = 0; i < message->m_numOfElementsInUint32Array; i++)
	{
		//this API is quite strange.. I cannot print the index, if I do, things will mess up!
		alt_printf("- word[] = 0x%x \n", message->m_uint32Array[i]);
	}
	alt_putchar('\n');
}

/**
 * \brief free the memory allocated for the member of the objects in the argument list.
 *
 * \param MSG_message_t* message : IN - the Message Object that contains an uin32_t array representation of the input string
 */
void MSG_freeMemory(MSG_message_t* message)
{
	if(message->m_string != NULL)
	{
		free(message->m_string);
		message->m_string = NULL;
	}

	if(message->m_uint32Array != NULL)
	{
		free(message->m_uint32Array);
		message->m_uint32Array = NULL;
	}
}
