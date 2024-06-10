/**
* \file   global.h
* \author Trung Tin Nguyen (1120436), and Dung Anh Huynh Pham (764527) (written based on Prof. Fromm's "global.h" file in PSoC projects)
* \date   14.12.2023
*
* \brief typedefs for common datatypes
*
* detailed description what the file does
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
* Contact Prof.Dr. C. Jakob, christian.jakob@h-da.de, Birkenweg 8 64295 Darmstadt - GERMANY for commercial requests.
*
* \warning This software is a PROTOTYPE version and is not designed or intended for use in production, especially not for safety-critical applications!
* The user represents and warrants that it will NOT use or redistribute the Software for such purposes.
* This prototype is for research purposes only. This software is provided "AS IS," without a warranty of any kind.
**/

#ifndef GLOBAL_H_
#define GLOBAL_H_


/*****************************************************************************/
/* Type definitions ('typedef')                                        		 */
/*****************************************************************************/

typedef signed 		char    	sint8_t;            /**< \brief         -128 .. +127            */
typedef unsigned 	char  		uint8_t;            /**< \brief            0 .. 255             */
typedef signed 		short   	sint16_t;           /**< \brief       -32768 .. +32767          */
typedef unsigned 	short 		uint16_t;           /**< \brief            0 .. 65535           */
typedef signed 		long    	sint32_t;           /**< \brief  -2147483648 .. +2147483647     */
typedef unsigned 	long  		uint32_t;           /**< \brief            0 .. 4294967295      */
typedef 			float   	float32_t;	        /**< \brief  single precision floating point number (4 byte) */
typedef 			double  	float64_t;	        /**< \brief  double precision floating point number (8 byte) */
typedef signed 		long long   sint64_t;           /**< \brief -9223372036854775808 .. +9223372036854775807     */
typedef unsigned 	long long 	uint64_t;           /**< \brief                    0 .. 18446744073709551615     */
typedef unsigned	char  		boolean_t; 	        /**< \brief  for use with TRUE/FALSE        */
typedef 			char    	char_t;		        /**< \brief	Character Datatype*/

#define TRUE        		((boolean_t) 1==1)      /**< \brief	Value is true (boolean_t type) */

#define FALSE       		((boolean_t) 1==0)      /**< \brief	Value is true (boolean_t type) */


#endif /* GLOBAL_H_ */
