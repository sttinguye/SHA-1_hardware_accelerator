/**
* \file   sha1.h
* \author Trung Tin Nguyen (1120436), and Dung Anh Huynh Pham (764527)
* \date   14.12.2023
*
* \brief sha-1 algorithm implemented in C
*
* This file contains API of the SHA-1 algorithm
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

#ifndef SHA1_H_
#define SHA1_H_

#include "global.h"
#include "msg.h"

/*****************************************************************************/
/* Global pre-processor symbols/macros and type declarations                 */
/*****************************************************************************/

//####################### Defines/Macros

/**
 * \brief Macros for the SHA-1 algorithm implementation
 *
 * Check Prof. Jakob's lecture slides on SHA-1
 *  for more details about these constants
 */

/**
 * \brief The defined number of bits per SHA-1 block.
 */
#define SHA1_BLOCK_SIZE					512		/**< in bits  */

/**
 * \brief Each 512-bit block contains 16 words of size 32bit.
 * 		  1 word = 32 bits.
 */
#define SHA1_TOTAL_WORDS_PER_BLOCK    	16		/**< in words */

/**
 * \brief max number of ASCII characters that can fit in a 512-bit block.
 *
 * - Each 512-bit block consists of 16 32-bit words.
 * - Theoretically, max number of bits of a message in a single 512-bit block is 447 bit.
 * - However the real limit is 440 bit because each ASCII character has 8 bits.
 * => If the input string contains more than 55 ASCII characters, we need more 512-bit block(s).
 */
#define SHA1_MAX_ASCII_CHARS_PER_BLOCK	55		/**< in characters*/

/**
 * \brief	Each 512-bit block will expand its 16 words into 80 words
 * 			for the Compression Function
 */
#define SHA1_NUM_OF_EXPANDED_WORDS_PER_BLOCK    80		/**< in words */

/**
 * \brief Each 512-bit block will be processed by a Compression Function that
 * 		  take 80 rounds to process the hash values.
 */
#define SHA1_NUM_OF_ROUNDS_PER_BLOCK    		80		/**< in rounds */

/**
 * \brief At start-up, the input buffer (5 x 32bit register) is initialized
 *        with some magic numbers (FIPS PUB 180-1)
 */
#define SHA1_INIT_HASH_A	0x67452301		/**< in hex */
#define SHA1_INIT_HASH_B	0xEFCDAB89		/**< in hex */
#define SHA1_INIT_HASH_C	0x98BADCFE		/**< in hex */
#define SHA1_INIT_HASH_D	0x10325476		/**< in hex */
#define SHA1_INIT_HASH_E	0xC3D2E1F0		/**< in hex */

/**
 * \brief The Compression Function contains 4 stage, each stage has 1 K constant.
 */
#define SHA1_K_STAGE_1		0x5A827999		/**< in hex */
#define SHA1_K_STAGE_2		0x6ED9EBA1		/**< in hex */
#define SHA1_K_STAGE_3		0x8F1BBCDC		/**< in hex */
#define SHA1_K_STAGE_4		0xCA62C1D6		/**< in hex */


//####################### Enumerations

/**
* \brief Enumerations for the indexes of the 5 hash values
*/
enum eSHA1_HashIndex{
  SHA1_HASH_A = 0,  	/**< index of Hash A */
  SHA1_HASH_B = 1, 		/**< index of Hash B */
  SHA1_HASH_C = 2, 		/**< index of Hash C */
  SHA1_HASH_D = 3, 		/**< index of Hash D */
  SHA1_HASH_E = 4, 		/**< index of Hash E */

  SHA1_NUM_OF_HASH_WORDS_PER_BLOCK = 5     /**< number of hash values */
} ;
typedef enum eSHA1_HashIndex SHA1_hashIndex_t;


//####################### Structures

/**
* \brief Each 512-bit block contains 16 words of size of 32 bits, 5 input hashes, and 5 output hashes.
*/
struct sSHA1_512bit_block {
  uint32_t 	m_word[SHA1_TOTAL_WORDS_PER_BLOCK];					/**< an uin32_t array of 16 words */
  uint32_t 	m_inputHash[SHA1_NUM_OF_HASH_WORDS_PER_BLOCK];		/**< an uin32_t array of 5 input hashes */
  uint32_t 	m_outputHash[SHA1_NUM_OF_HASH_WORDS_PER_BLOCK];		/**< an uin32_t array of 5 output hashes */
};
typedef struct sSHA1_512bit_block SHA1_512bit_block_t;

/**
 * \brief Each SHA-1 packet contains one 512-bit block or more, depending on the input string length.
 */
struct sSHA1_Packet {
  uint64_t				m_numOf512bitBlocks;	/**< number of 512-bit blocks per of SHA-1 packet */
  SHA1_512bit_block_t*	m_512bit_block;    		/**< an array of 512-bit blocks */
};
typedef struct sSHA1_Packet SHA1_packet_t;


/*****************************************************************************/
/* API functions                                                             */
/*****************************************************************************/

/**
 * \brief Initialization of the SHA-1 Object + do the Pre-Processing step of SHA-1 algorithm.
 *
 *	The function that implements the SHA-1 pre-processing for input messages of arbitrary length
 *	is called in this SHA1_init() function.
 *
 * \param SHA1_packet_t* packet : IN - the SHA-1 Packet Object
 * \param MSG_message_t* message : IN - the Message Object that contains an uin32_t array representation of the input string
 */
void SHA1_init(SHA1_packet_t* packet, MSG_message_t* message);

/**
 * \brief Print out the pre-processed blocks of the SHA-1 packet on the Eclipse Console
 *
 * \param SHA1_packet_t* packet : IN - the SHA-1 Packet Object
 */
void SHA1_printPreProcessedPacket(SHA1_packet_t* packet);

/**
 * \brief This SHA-1 function operates on a single pre-processed 512-bit wide input message.
 *
 * This function is required in the Lab Assignment#1.
 * Check Prof. Jakob's lecture slides on the SHA-1 algorithm.
 *
 * \param uint32_t * hash_ptr : OUT - pointer to the processed hash
 * \param const uint32_t * message : IN - the pre-processed 512-bit wide input message
 * \param const uint32_t * prev_hash : IN - pointer to the initial hash
 */
void sha_1(uint32_t * hash_ptr, const uint32_t * message, const uint32_t * prev_hash);

/**
 * \brief This function takes the output hash of the current 512-bit block and assigns
 * 		  to the input hash of the next 512-bit block
 *
 * \param SHA1_packet_t* packet : IN - the SHA-1 Packet Object
 * \param uint64_t blockIndex : IN - current block index
 */
void SHA1_updateInputHashForNextBlock(SHA1_packet_t* packet, uint64_t blockIndex);

/**
 * \brief free the memory allocated for the member of the objects in the argument list.
 *
 * \param SHA1_packet_t* packet : IN - the SHA-1 Packet Object
 */
void SHA1_freeMemory(SHA1_packet_t* packet);

/**
 * \brief Print out the final hash result on the Eclipse Console
 *
 * \param SHA1_packet_t* packet : IN - the SHA-1 Packet Object
 * \param MSG_message_t* message : IN - the Message Object that contains an uin32_t array representation of the input string
 */
void SHA1_printFinalHash(SHA1_packet_t* packet, MSG_message_t* message);

#endif /* SHA1_H_ */
