/**
* \file   msg.h
* \author Trung Tin Nguyen (1120436), and Dung Anh Huynh Pham (764527)
* \date   14.12.2023
*
* \brief contain APIs to convert string into uint32_t array containing HEX values of each ASCII character.
*
* This file contains APIs that can represent the input string as an array of uint32_t values
*  storing the HEX values of each ASCII character.
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

#ifndef MSG_H_
#define MSG_H_

#include "global.h"

/*****************************************************************************/
/* Global pre-processor symbols/macros and type declarations                 */
/*****************************************************************************/

//####################### Structures

/**
* \brief Message Object contains the string and its uint32_t array representation
*/
struct sMSG_message{
	uint64_t 	m_stringLength;		/**< in characters. Max is 2.305843009e+18 characters */
	char*		m_string;			/**< string is an array of char */
	uint64_t 	m_numOfElementsInUint32Array; /**< in words/elements */
	uint32_t*	m_uint32Array;		/**< uint32_t array representation of the string */
};
typedef struct sMSG_message MSG_message_t;


/*****************************************************************************/
/* API functions                                                             */
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
void MSG_init(MSG_message_t* message, const char* string, uint32_t stringLength);

/**
 * \brief function to print out the 32-bit representation of the string.
 *
 * \param MSG_message_t* message : IN - the Message Object that contains an uin32_t array representation of the input string
 */
void MSG_printUint32Representation(MSG_message_t* message);

/**
 * \brief free the memory allocated for the member of the objects in the argument list.
 *
 * \param MSG_message_t* message : IN - the Message Object that contains an uin32_t array representation of the input string
 */
void MSG_freeMemory(MSG_message_t* message);

#endif /* MSG_H_ */
