/**
* \file   sha1.c
* \author Trung Tin Nguyen (1120436), and Dung Anh Huynh Pham (764527)
* \date   14.12.2023
*
* \brief sha-1 algorithm implemented in C
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
#include "sys/alt_stdio.h"	//to print out on Eclipse Console
#include <stdlib.h>	//for the usage of malloc
#include <assert.h> // for assert()

#include "sha1.h"
#include "sha1_config.h"


/*****************************************************************************/
/* Local variable definitions ('static')                                     */
/*****************************************************************************/

/**
* \brief array of 80 expanded words to be processed in the Compression Function
* 		 for each 512-bit block
*/
static uint32_t SHA1_expanded_word[SHA1_NUM_OF_EXPANDED_WORDS_PER_BLOCK] = {0};


/*****************************************************************************/
/* Local function prototypes ('static')                                      */
/*****************************************************************************/

/**
 * \brief This function initialize the 5 input hash values of each 512bit block.
 *
 * \param SHA1_packet_t* packet : IN - the SHA-1 Packet Object
 */
static void SHA1_initInputHash(SHA1_packet_t* packet);

/**
 * \brief This function initialize the 5 output hash words of each 512bit block to 0.
 * 		  They will be modified later.
 *
 * \param SHA1_packet_t* packet : IN - the SHA-1 Packet Object
 */
static void SHA1_initOutputHash(SHA1_packet_t* packet);

/**
 * \brief initialize the 16 words of each 512bit block to 0. They will be modified later.
 *
 * \param SHA1_packet_t* packet : IN - the SHA-1 Packet Object
 */
static void SHA1_initWords(SHA1_packet_t* packet);

/**
 * \brief This function perform SHA-1 Pre-Processing step for input messages of arbitrary length.
 *
 * Pre-processing consists of 3 steps:
 * + #Step 1: put ASCII characters into the bits allocated for the Message part of the 512-bit block
 * + #Step 2: add the Padding part to the 512-bit block
 * + #Step 3: append the 64-bit representation of the length of the original message to the 512-bit block.
 *
 * - In simple case, where the original message length is equal to or less than 55 characters,
 *   those mentioned 3 steps will be performed on a single 512-bit block.
 * - However, if the original message length is larger than 55 characters,
 *   things get more complicated:
 *    + Step 1 is performed in a way that it will fill all characters to the blocks.
 *      If block[0] is out of space, then it will continue to fill in block[1] and so on
 *      until all characters are appended into the blocks.
 *    + Step 2: add the Padding right after finishing appending the ASCII characters in whichever
 *      block that Step 1 stops at.
 *    + Step 3: append the 64-bit representation of the length of the original message
 *      to the final block.
 *
 * \param SHA1_packet_t* packet : IN - the SHA-1 Packet Object
 * \param MSG_message_t* message : IN - the Message Object that contains an uin32_t array representation of the input string
 */
static void SHA1_preProcessing(SHA1_packet_t* packet, MSG_message_t* message);

/**
 * \brief This function append the ASCII characters into the 512-bit blocks
 *
 * \param SHA1_packet_t* packet : IN - the SHA-1 Packet Object
 * \param MSG_message_t* message : IN - the Message Object that contains an uin32_t array representation of the input string
 * \param uint64_t blockIndex : IN - the block index of the current 512-bit block
 * \param uint8_t* wordIndex : IN - the word index of the words of the current 512-bit block
 * \param uint64_t* uint32ArrayIndex : IN - the index of the uint32_t array of the Message Object
 */
static void SHA1_putASCIIinto512bitBlock(SHA1_packet_t* packet,
										 MSG_message_t* message,
										 uint64_t blockIndex,
										 uint8_t* wordIndex,
										 uint64_t* uint32ArrayIndex);

/**
 * \brief This function appends the padding the 512-bit block.
 *
 * \param SHA1_packet_t* packet : IN - the SHA-1 Packet Object
 * \param MSG_message_t* message : IN - the Message Object that contains an uin32_t array representation of the input string
 * \param uint64_t blockIndex : IN - the block index of the current 512-bit block
 * \param uint8_t* wordIndex : IN - the word index of the words of the current 512-bit block
 */
static void SHA1_addPaddingInto512bitBlock(SHA1_packet_t* packet,
										   MSG_message_t* message,
										   uint64_t blockIndex,
										   uint8_t* wordIndex);

/**
 * \brief This function appends the 64-bit representation of the original message length
 *
 * How this algorithm works is that we just put the last 64-bit representation
 * of the original message length to the last 64-bit of the last 512-bit block
 *
 * \param SHA1_packet_t* packet : IN - the SHA-1 Packet Object
 * \param MSG_message_t* message : IN - the Message Object that contains an uin32_t array representation of the input string
 * \param uint64_t blockIndex : IN - the block index of the current 512-bit block
 * \param uint8_t* wordIndex : IN - the word index of the words of the current 512-bit block
 */
static void SHA1_append64bitRepresentationOfLength(SHA1_packet_t* packet,
												   MSG_message_t* message,
												   uint64_t blockIndex,
												   uint8_t* wordIndex);

/**
 * \brief This function expands the 16 words of the current 512-bit block in to 80 words.
 *
 * Check Prof. Jakob's lecture slides on SHA-1 algorithm.
 *
 * \param const uint32_t * message : IN - the pre-processed 512-bit wide input message
 */
static void SHA1_wordExpansion(const uint32_t * message);

/**
 * \brief This function performs ROTL on a uint32_t variable
 *
 * \param uint32_t uint32Value : IN - the uin32_t value that needs to be ROTL
 * \param uint8_t numOfShiftBits : IN - the number of bits to be shifted. Must be between 0 and 31.
 * \return the result after performing ROTL
 */
static uint32_t SHA1_simpleROTL32(uint32_t uint32Value, uint8_t numOfShiftBits);

/**
 * \brief This function computes output hash A since its implementation is quite long
 *
 * Check Prof. Jakob's lecture slides on the SHA-1 algorithm.
 *
 * \param uint8_t roundIndex : IN - index of the current round of the Compression Function
 * \param uint32_t inputHashA : IN - input hash A
 * \param uint32_t inputHashB : IN - input hash B
 * \param uint32_t inputHashC : IN - input hash C
 * \param uint32_t inputHashD : IN - input hash D
 * \param uint32_t inputHashE : IN - input hash E
 */
static uint32_t SHA1_computeOutputHashA(uint8_t roundIndex, uint32_t inputHashA, uint32_t inputHashB, uint32_t inputHashC, uint32_t inputHashD, uint32_t inputHashE);

/**
 * \brief This function checks if the current stage of the Compression Function is stage 1 or not,
 * 		  depending on the current round index
 *
 * \param uint8_t roundIndex : IN - current round index of the Compression Function
 * \return TRUE or FALSE
 */
static boolean_t SHA1_isStage01(uint8_t roundIndex);

/**
 * \brief This function checks if the current stage of the Compression Function is stage 2 or not,
 * 		  depending on the current round index
 *
 * \param uint8_t roundIndex : IN - current round index of the Compression Function
 * \return TRUE or FALSE
 */
static boolean_t SHA1_isStage02(uint8_t roundIndex);

/**
 * \brief This function checks if the current stage of the Compression Function is stage 3 or not,
 * 		  depending on the current round index
 *
 * \param uint8_t roundIndex : IN - current round index of the Compression Function
 * \return TRUE or FALSE
 */
static boolean_t SHA1_isStage03(uint8_t roundIndex);

/**
 * \brief This function checks if the current stage of the Compression Function is stage 4 or not,
 * 		  depending on the current round index
 *
 * \param uint8_t roundIndex : IN - current round index of the Compression Function
 * \return TRUE or FALSE
 */
static boolean_t SHA1_isStage04(uint8_t roundIndex);

/**
 * \brief This function is used for stage 1 of the Compression Function.
 *
 * Check Prof. Jakob's lecture slides on the SHA-1 algorithm.
 *
 * \param uint32_t x : IN - first parameter
 * \param uint32_t y : IN - second parameter
 * \param uint32_t z : IN - third parameter
 * \return result of the computation
 */
static uint32_t SHA1_kernelFunctionForStage01(uint32_t x, uint32_t y, uint32_t z);

/**
 * \brief This function is used for stage 2 of the Compression Function.
 *
 * Check Prof. Jakob's lecture slides on the SHA-1 algorithm.
 *
 * \param uint32_t x : IN - first parameter
 * \param uint32_t y : IN - second parameter
 * \param uint32_t z : IN - third parameter
 * \return result of the computation
 */
static uint32_t SHA1_kernelFunctionForStage02(uint32_t x, uint32_t y, uint32_t z);

/**
 * \brief This function is used for stage 3 of the Compression Function.
 *
 * Check Prof. Jakob's lecture slides on the SHA-1 algorithm.
 *
 * \param uint32_t x : IN - first parameter
 * \param uint32_t y : IN - second parameter
 * \param uint32_t z : IN - third parameter
 * \return result of the computation
 */
static uint32_t SHA1_kernelFunctionForStage03(uint32_t x, uint32_t y, uint32_t z);

/**
 * \brief This function is used for stage 4 of the Compression Function.
 *
 * Check Prof. Jakob's lecture slides on the SHA-1 algorithm.
 *
 * \param uint32_t x : IN - first parameter
 * \param uint32_t y : IN - second parameter
 * \param uint32_t z : IN - third parameter
 * \return result of the computation
 */
static uint32_t SHA1_kernelFunctionForStage04(uint32_t x, uint32_t y, uint32_t z);


/*****************************************************************************/
/* Function implementation - global ('extern') and local ('static')          */
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
void SHA1_init(SHA1_packet_t* packet, MSG_message_t* message)
{
	/**
	 * - Each 512-bit block consists of 16 32-bit words.
	 * - Theoretically, max number of bits of a message in a single 512-bit block is 447 bit.
	 * - However the real limit is 440 bit because each ASCII character has 8 bits.
	 * => If the input string contains more than 55 ASCII characters, we need more 512-bit block(s).
	 */
	//calculate how many blocks of 512bit do we need
	packet->m_numOf512bitBlocks = (message->m_stringLength + (SHA1_MAX_ASCII_CHARS_PER_BLOCK - 1)) / SHA1_MAX_ASCII_CHARS_PER_BLOCK;

	//allocate memory based on how many 512-bit blocks are needed.
	packet->m_512bit_block = (SHA1_512bit_block_t*)malloc(packet->m_numOf512bitBlocks * sizeof(SHA1_512bit_block_t));

	//initialize the input hash words of each 512bit block.
	SHA1_initInputHash(packet);

	//initialize the output hash words of each 512bit block to 0. They will be modified later.
	SHA1_initOutputHash(packet);

	//initialize the 16 words of each 512bit block to 0. They will be modified later.
	SHA1_initWords(packet);

	//Pre-Processing step
	SHA1_preProcessing(packet, message);
}

/**
 * \brief This function initialize the 5 input hash values of each 512bit block.
 *
 * \param SHA1_packet_t* packet : IN - the SHA-1 Packet Object
 */
static void SHA1_initInputHash(SHA1_packet_t* packet)
{
	for(uint64_t blockIndex = 0; blockIndex < packet->m_numOf512bitBlocks; blockIndex++)
	{
		if(blockIndex == 0) //if it is the first ever 512bit block, we apply magic numbers (FIPS PUB 180-1).
		{
			packet->m_512bit_block[blockIndex].m_inputHash[SHA1_HASH_A] = SHA1_INIT_HASH_A;
			packet->m_512bit_block[blockIndex].m_inputHash[SHA1_HASH_B] = SHA1_INIT_HASH_B;
			packet->m_512bit_block[blockIndex].m_inputHash[SHA1_HASH_C] = SHA1_INIT_HASH_C;
			packet->m_512bit_block[blockIndex].m_inputHash[SHA1_HASH_D] = SHA1_INIT_HASH_D;
			packet->m_512bit_block[blockIndex].m_inputHash[SHA1_HASH_E] = SHA1_INIT_HASH_E;
		}
		else //if it is the 2nd block and so on, just apply 0. They will be modified later.
		{
			packet->m_512bit_block[blockIndex].m_inputHash[SHA1_HASH_A] = 0;
			packet->m_512bit_block[blockIndex].m_inputHash[SHA1_HASH_B] = 0;
			packet->m_512bit_block[blockIndex].m_inputHash[SHA1_HASH_C] = 0;
			packet->m_512bit_block[blockIndex].m_inputHash[SHA1_HASH_D] = 0;
			packet->m_512bit_block[blockIndex].m_inputHash[SHA1_HASH_E] = 0;
		}
	}
}

/**
 * \brief This function initialize the 5 output hash words of each 512bit block to 0.
 * 		  They will be modified later.
 *
 * \param SHA1_packet_t* packet : IN - the SHA-1 Packet Object
 */
static void SHA1_initOutputHash(SHA1_packet_t* packet)
{
	for(uint64_t blockIndex = 0; blockIndex < packet->m_numOf512bitBlocks; blockIndex++)
	{
		//initialize the 5 output hash words of each 512bit block to 0. They will be modified later.
		packet->m_512bit_block[blockIndex].m_outputHash[SHA1_HASH_A] = 0;
		packet->m_512bit_block[blockIndex].m_outputHash[SHA1_HASH_B] = 0;
		packet->m_512bit_block[blockIndex].m_outputHash[SHA1_HASH_C] = 0;
		packet->m_512bit_block[blockIndex].m_outputHash[SHA1_HASH_D] = 0;
		packet->m_512bit_block[blockIndex].m_outputHash[SHA1_HASH_E] = 0;
	}
}

/**
 * \brief initialize the 16 words of each 512bit block to 0. They will be modified later.
 *
 * \param SHA1_packet_t* packet : IN - the SHA-1 Packet Object
 */
static void SHA1_initWords(SHA1_packet_t* packet)
{
	//initialize the 16 words of each 512bit block to 0. They will be modified later.
	for(uint64_t blockIndex = 0; blockIndex < packet->m_numOf512bitBlocks; blockIndex++)
	{
		for(uint8_t wordIndex = 0; wordIndex < SHA1_TOTAL_WORDS_PER_BLOCK; wordIndex++)
		{
			packet->m_512bit_block[blockIndex].m_word[wordIndex] = 0;
		}
	}
}

/**
 * \brief This function perform SHA-1 Pre-Processing step for input messages of arbitrary length.
 *
 * Pre-processing consists of 3 steps:
 * + #Step 1: put ASCII characters into the bits allocated for the Message part of the 512-bit block
 * + #Step 2: add the Padding part to the 512-bit block
 * + #Step 3: append the 64-bit representation of the length of the original message to the 512-bit block.
 *
 * - In simple case, where the original message length is equal to or less than 55 characters,
 *   those mentioned 3 steps will be performed on a single 512-bit block.
 * - However, if the original message length is larger than 55 characters,
 *   things get more complicated:
 *    + Step 1 is performed in a way that it will fill all characters to the blocks.
 *      If block[0] is out of space, then it will continue to fill in block[1] and so on
 *      until all characters are appended into the blocks.
 *    + Step 2: add the Padding right after finishing appending the ASCII characters in whichever
 *      block that Step 1 stops at.
 *    + Step 3: append the 64-bit representation of the length of the original message
 *      to the final block.
 *
 * \param SHA1_packet_t* packet : IN - the SHA-1 Packet Object
 * \param MSG_message_t* message : IN - the Message Object that contains an uin32_t array representation of the input string
 */
static void SHA1_preProcessing(SHA1_packet_t* packet, MSG_message_t* message)
{
	for(uint64_t blockIndex = 0; blockIndex < packet->m_numOf512bitBlocks; blockIndex++)
	{
		//### pre-process the original message into the 512-bit block.

		/* The "wordIndex", which indexes the 16 32-bit words of each 512-bit block,
		 * it will go from 0 to 15 within the 512-bit block. */
		uint8_t wordIndex = 0;

		/* - The "uint32ArrayIndex" is another story, it indexes the words/elements in the
		 *   uint32_t array of the "message" Object.
		 * - It does not care about the indexes of the 512-bit block and the current word within
		 *   the 512-bit block.
		 * - So it is a static variable. */
		static uint64_t uint32ArrayIndex = 0;

		//#Step 1: put ASCII characters into the bits allocated for the Message part of the 512-bit block
		SHA1_putASCIIinto512bitBlock(packet, message, blockIndex, &wordIndex, &uint32ArrayIndex);

		//#Step 2: add the Padding part to the 512-bit block.
		SHA1_addPaddingInto512bitBlock(packet, message, blockIndex, &wordIndex);

		//#Step 3: append the 64-bit representation of the length of the original message.
		SHA1_append64bitRepresentationOfLength(packet, message, blockIndex, &wordIndex);

	}//end of for(uint64_t blockIndex = 0; blockIndex < packet->m_numOf512bitBlocks; blockIndex++)
}

/**
 * \brief This function append the ASCII characters into the 512-bit blocks
 *
 * \param SHA1_packet_t* packet : IN - the SHA-1 Packet Object
 * \param MSG_message_t* message : IN - the Message Object that contains an uin32_t array representation of the input string
 * \param uint64_t blockIndex : IN - the block index of the current 512-bit block
 * \param uint8_t* wordIndex : IN - the word index of the words of the current 512-bit block
 * \param uint64_t* uint32ArrayIndex : IN - the index of the uint32_t array of the Message Object
 */
static void SHA1_putASCIIinto512bitBlock(SHA1_packet_t* packet,
										 MSG_message_t* message,
										 uint64_t blockIndex,
										 uint8_t* wordIndex,
										 uint64_t* uint32ArrayIndex)
{
	//when (*uint32ArrayIndex) has reached its limit, we don't append ASCII characters anymore
	if((*uint32ArrayIndex) >= message->m_numOfElementsInUint32Array)
	{
		//increment the (*wordIndex) to do the next step, which is append padding.
		(*wordIndex)++;

		return;
	}

	//Find the limit of the Uint32_t Array in each iteration (of 512-bit blocks).
	uint64_t uint32ArrayLimit = 0;

	// '+1' here because "message->m_numOfElementsInUint32Array" starts from '1', while "blockIndex" starts from '0'.
	if (message->m_numOfElementsInUint32Array <= ((blockIndex + 1) * SHA1_TOTAL_WORDS_PER_BLOCK))
	{
		uint32ArrayLimit = message->m_numOfElementsInUint32Array;
	}
	else
	{
		// '+1' here because "uint32ArrayLimit" starts from '1', while "blockIndex" starts from '0'.
		uint32ArrayLimit = ((blockIndex + 1) * SHA1_TOTAL_WORDS_PER_BLOCK);
	}

	//append the ASCII characters into the words of the current 512-bit block.
	for(; (*uint32ArrayIndex) < uint32ArrayLimit; (*uint32ArrayIndex)++)
	{
		packet->m_512bit_block[blockIndex].m_word[(*wordIndex)] = message->m_uint32Array[(*uint32ArrayIndex)];

		//increment the (*wordIndex) to do the next step, append padding.
		(*wordIndex)++;
	}
}

/**
 * \brief This function appends the padding the 512-bit block.
 *
 * \param SHA1_packet_t* packet : IN - the SHA-1 Packet Object
 * \param MSG_message_t* message : IN - the Message Object that contains an uin32_t array representation of the input string
 * \param uint64_t blockIndex : IN - the block index of the current 512-bit block
 * \param uint8_t* wordIndex : IN - the word index of the words of the current 512-bit block
 */
static void SHA1_addPaddingInto512bitBlock(SHA1_packet_t* packet,
										   MSG_message_t* message,
										   uint64_t blockIndex,
										   uint8_t* wordIndex)
{
	//this flag is used so that the padding can only be done ONCE.
	static boolean_t paddingFlag = FALSE;

	//if the 512-bit block is already padded then we move on
	if(TRUE == paddingFlag)
	{
		return;
	}

	//move back 1 index to check if we can append Padding to the empty slots
	uint32_t startIndex = ((*wordIndex) - 1);

	/**
	 * e.g.,           0x00000000
	 *  -> do Padding: 0x80000000
	 *  --------------------------
	 *  -> gives:	   0x80000000
	 */
	if ((packet->m_512bit_block[blockIndex].m_word[startIndex] & 0xFFFFFFFF) == 0)
	{
		packet->m_512bit_block[blockIndex].m_word[startIndex] = packet->m_512bit_block[blockIndex].m_word[startIndex] | 0x80000000;

		//set the flag to TRUE so that this Padding code will never be executed the 2nd time.
		paddingFlag = TRUE;
	}
	/**
	 * e.g.,           0x61000000
	 *  -> do Padding: 0x  800000
	 *  --------------------------
	 *  -> gives:	   0x61800000
	 */
	else if ((packet->m_512bit_block[blockIndex].m_word[startIndex] & 0x00FFFFFF) == 0)
	{
		packet->m_512bit_block[blockIndex].m_word[startIndex] = packet->m_512bit_block[blockIndex].m_word[startIndex] | 0x800000;

		//set the flag to TRUE so that this Padding code will never be executed the 2nd time.
		paddingFlag = TRUE;
	}
	/**
	 * e.g.,           0x61610000
	 *  -> do Padding: 0x    8000
	 *  --------------------------
	 *  -> gives:	   0x61618000
	 */
	else if ((packet->m_512bit_block[blockIndex].m_word[startIndex] & 0x0000FFFF) == 0)
	{
		packet->m_512bit_block[blockIndex].m_word[startIndex] = packet->m_512bit_block[blockIndex].m_word[startIndex] | 0x8000;

		//set the flag to TRUE so that this Padding code will never be executed the 2nd time.
		paddingFlag = TRUE;
	}
	/**
	 * e.g.,           0x61616100
	 *  -> do Padding: 0x      80
	 *  --------------------------
	 *  -> gives:	   0x61616180
	 */
	else if ((packet->m_512bit_block[blockIndex].m_word[startIndex] & 0x000000FF) == 0)
	{
		packet->m_512bit_block[blockIndex].m_word[startIndex] = packet->m_512bit_block[blockIndex].m_word[startIndex] | 0x80;

		//set the flag to TRUE so that this Padding code will never be executed the 2nd time.
		paddingFlag = TRUE;
	}
	/**
	 * e.g.,           0x61616161 ???
	 *  -> we don't do Padding immediately, we increment the start index to the next word,
	 *     which will have value    0x00000000
	 *  -> then do the padding with 0x80000000
	 *  -> So we will have:
	 *
	 *     startIndex   ->	word[0] = 0x61616161
	 *     startIndex++ ->	word[1] = 0x00000000
	 *     do Padding:                0x80000000
	 *     --------------------------------------
	 *     gives:			word[1] = 0x80000000
	 */
	else
	{
		//we don't do Padding immediately, we increment the start index to the next word
		startIndex++;

		/**
		 * #special case: start index has exceeded its limit,
		 *  which means the current 512-bit block has run out of words for us to
		 *  append the Padding.
		 *  => we end our function here, then in the next iteration, startIndex will start from 0
		 */
		if(startIndex == SHA1_TOTAL_WORDS_PER_BLOCK)
		{
			return;
		}

		//do the padding with 0x80000000 as mentioned above
		packet->m_512bit_block[blockIndex].m_word[startIndex] = packet->m_512bit_block[blockIndex].m_word[startIndex] | 0x80000000;

		//set the flag to TRUE so that this Padding code will never be executed the 2nd time.
		paddingFlag = TRUE;
	}
}

/**
 * \brief This function appends the 64-bit representation of the original message length
 *
 * How this algorithm works is that we just put the last 64-bit representation
 * of the original message length to the last 64-bit of the last 512-bit block
 *
 * \param SHA1_packet_t* packet : IN - the SHA-1 Packet Object
 * \param MSG_message_t* message : IN - the Message Object that contains an uin32_t array representation of the input string
 * \param uint64_t blockIndex : IN - the block index of the current 512-bit block
 * \param uint8_t* wordIndex : IN - the word index of the words of the current 512-bit block
 */
static void SHA1_append64bitRepresentationOfLength(SHA1_packet_t* packet,
												   MSG_message_t* message,
												   uint64_t blockIndex,
												   uint8_t* wordIndex)
{
	//find the index of the last 512-bit block
	uint64_t lastBlockIndex = packet->m_numOf512bitBlocks - 1;

	//if this block index is not the index of the last 512-bit block => we bypass this function
	if(blockIndex < lastBlockIndex)
	{
		return;
	}

	//calculate number of bits of the original messgage
	uint64_t messageLengthInBits = ( (message->m_stringLength) * 8 );

	//calculate the next-to-last word index and last word index of the last 512-bit block.
	uint8_t nextToLastWordIndex = SHA1_TOTAL_WORDS_PER_BLOCK - 2;
	uint8_t lastWordIndex 		= SHA1_TOTAL_WORDS_PER_BLOCK - 1;

	//assign the first 32 bits of "messageLengthInBits" to the next-to-last word index
	packet->m_512bit_block[lastBlockIndex].m_word[nextToLastWordIndex] = (uint32_t)(messageLengthInBits >> 32);

	//assign the second 32 bits of "messageLengthInBits" to last word index
	packet->m_512bit_block[lastBlockIndex].m_word[lastWordIndex] = (uint32_t)(messageLengthInBits);
}

/**
 * \brief free the memory allocated for the member of the objects in the argument list.
 *
 * \param SHA1_packet_t* packet : IN - the SHA-1 Packet Object
 */
void SHA1_freeMemory(SHA1_packet_t* packet)
{
	if (packet->m_512bit_block != NULL)
	{
		free(packet->m_512bit_block);
		packet->m_512bit_block = NULL;
	}
}

/**
 * \brief Print out the pre-processed blocks of the SHA-1 packet on the Eclipse Console
 *
 * \param SHA1_packet_t* packet : IN - the SHA-1 Packet Object
 */
void SHA1_printPreProcessedPacket(SHA1_packet_t* packet)
{
	alt_putstr("\n## Printing the pre-processed blocks of 512-bit wide input message of the SHA-1 packet ##\n");

	alt_printf("Number of pre-processed Blocks: %x (in hex)\n", packet->m_numOf512bitBlocks);

	alt_putstr("block indexes are in hex!\n");
	for(uint64_t blockIndex = 0; blockIndex < packet->m_numOf512bitBlocks; blockIndex++)
	{
		alt_printf("- Block[%x]:\n", blockIndex);
		for(uint8_t wordIndex = 0; wordIndex < SHA1_TOTAL_WORDS_PER_BLOCK; wordIndex++)
		{
			//this API is quite strange.. I cannot print the index, if I do, things will mess up!
			alt_printf("  + word[] = 0x%x \n", packet->m_512bit_block[blockIndex].m_word[wordIndex]);
		}
	}

	alt_putchar('\n');
}

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
void sha_1(uint32_t * hash_ptr, const uint32_t * message, const uint32_t * prev_hash)
{
	//Perform expansion of the 16 words in to 80 words to be processed in the Compression Function
	SHA1_wordExpansion(message);

	//Buffer for the prev_hash, this buffer will be modified in the 80 rounds.
	uint32_t inputHash[SHA1_NUM_OF_HASH_WORDS_PER_BLOCK] = {0};

	//Initially, the buffer is the prev_hash
	inputHash[SHA1_HASH_A] = prev_hash[SHA1_HASH_A];
	inputHash[SHA1_HASH_B] = prev_hash[SHA1_HASH_B];
	inputHash[SHA1_HASH_C] = prev_hash[SHA1_HASH_C];
	inputHash[SHA1_HASH_D] = prev_hash[SHA1_HASH_D];
	inputHash[SHA1_HASH_E] = prev_hash[SHA1_HASH_E];

#if SHA1_CONFIG_ENABLE_DEBUG

	static uint64_t blockIndex = 0;

	alt_putstr("Printing the Hash computations for the current 512-bit block ##\n");
	alt_putstr("block indexes are in hex!\n");
	alt_printf("- Block[%x]:\n", blockIndex);

	//print the prev_hash
	alt_printf("\n prev_hash A = %x\n", prev_hash[SHA1_HASH_A]);
	alt_printf(" prev_hash B = %x\n", prev_hash[SHA1_HASH_B]);
	alt_printf(" prev_hash C = %x\n", prev_hash[SHA1_HASH_C]);
	alt_printf(" prev_hash D = %x\n", prev_hash[SHA1_HASH_D]);
	alt_printf(" prev_hash E = %x\n\n", prev_hash[SHA1_HASH_E]);

#endif

	//perform the 80 rounds of the Compression Function for the current 512-bit block
	for(uint8_t roundIndex = 0; roundIndex < SHA1_NUM_OF_ROUNDS_PER_BLOCK; roundIndex++)
	{
		//Perform the SHA-1 Kernel operations on the 5 hashes

		//Hash A computation
		hash_ptr[SHA1_HASH_A] = SHA1_computeOutputHashA(roundIndex,
														inputHash[SHA1_HASH_A],
														inputHash[SHA1_HASH_B],
														inputHash[SHA1_HASH_C],
														inputHash[SHA1_HASH_D],
														inputHash[SHA1_HASH_E]);

		//Hash B computation
		hash_ptr[SHA1_HASH_B] = inputHash[SHA1_HASH_A];

		//Hash C computation, check Prof. Jakob's slides for explanation of the number '30'
		hash_ptr[SHA1_HASH_C] = SHA1_simpleROTL32(inputHash[SHA1_HASH_B], 30);

		//Hash D computation
		hash_ptr[SHA1_HASH_D] = inputHash[SHA1_HASH_C];

		//Hash E computation
		hash_ptr[SHA1_HASH_E] = inputHash[SHA1_HASH_D];

		//save the result of the hash computation for the next round.
		inputHash[SHA1_HASH_A] = hash_ptr[SHA1_HASH_A];
		inputHash[SHA1_HASH_B] = hash_ptr[SHA1_HASH_B];
		inputHash[SHA1_HASH_C] = hash_ptr[SHA1_HASH_C];
		inputHash[SHA1_HASH_D] = hash_ptr[SHA1_HASH_D];
		inputHash[SHA1_HASH_E] = hash_ptr[SHA1_HASH_E];


#if SHA1_CONFIG_ENABLE_DEBUG

		alt_printf("  + round : A = %x, B = %x, C = %x, D = %x, E = %x\n",
					hash_ptr[SHA1_HASH_A],
					hash_ptr[SHA1_HASH_B],
					hash_ptr[SHA1_HASH_C],
					hash_ptr[SHA1_HASH_D],
					hash_ptr[SHA1_HASH_E]);

#endif

	}

#if SHA1_CONFIG_ENABLE_DEBUG

	alt_putstr("\nPrinting the Hash result of current 512-bit block ##\n");
	alt_putstr("block indexes are in hex!\n");
	alt_printf("- Block[%x]:\n", blockIndex);

	alt_printf("   + Hash A = %x + %x = %x\n ",
				hash_ptr[SHA1_HASH_A],
				prev_hash[SHA1_HASH_A],
				hash_ptr[SHA1_HASH_A] + prev_hash[SHA1_HASH_A]);

	alt_printf("  + Hash B = %x + %x = %x\n ",
				hash_ptr[SHA1_HASH_B],
				prev_hash[SHA1_HASH_B],
				hash_ptr[SHA1_HASH_B] + prev_hash[SHA1_HASH_B]);

	alt_printf("  + Hash C = %x + %x = %x\n ",
				hash_ptr[SHA1_HASH_C],
				prev_hash[SHA1_HASH_C],
				hash_ptr[SHA1_HASH_C] + prev_hash[SHA1_HASH_C]);

	alt_printf("  + Hash D = %x + %x = %x\n ",
				hash_ptr[SHA1_HASH_D],
				prev_hash[SHA1_HASH_D],
				hash_ptr[SHA1_HASH_D] + prev_hash[SHA1_HASH_D]);

	alt_printf("  + Hash E = %x + %x = %x\n ",
				hash_ptr[SHA1_HASH_E],
				prev_hash[SHA1_HASH_E],
				hash_ptr[SHA1_HASH_E] + prev_hash[SHA1_HASH_E]);

	blockIndex++;

	alt_putchar('\n');

#endif

	//compute final hash values for current 512-bit block
	hash_ptr[SHA1_HASH_A] += prev_hash[SHA1_HASH_A];
	hash_ptr[SHA1_HASH_B] += prev_hash[SHA1_HASH_B];
	hash_ptr[SHA1_HASH_C] += prev_hash[SHA1_HASH_C];
	hash_ptr[SHA1_HASH_D] += prev_hash[SHA1_HASH_D];
	hash_ptr[SHA1_HASH_E] += prev_hash[SHA1_HASH_E];
}

/**
 * \brief This function expands the 16 words of the current 512-bit block in to 80 words.
 *
 * Check Prof. Jakob's lecture slides on SHA-1 algorithm.
 *
 * \param const uint32_t * message : IN - the pre-processed 512-bit wide input message
 */
static void SHA1_wordExpansion(const uint32_t * message)
{
	uint16_t expandedWordIndex = 0;

	//The 512 bit wide input message is mapped on the first 16 words
	for(; expandedWordIndex < SHA1_TOTAL_WORDS_PER_BLOCK; expandedWordIndex++)
	{
		SHA1_expanded_word[expandedWordIndex] = message[expandedWordIndex];
	}

	//from 16 to 79 is another story
	for(; expandedWordIndex < SHA1_NUM_OF_EXPANDED_WORDS_PER_BLOCK; expandedWordIndex++)
	{
		//save the indexes from earlier operation
		uint32_t wordIndexMinus3  = SHA1_expanded_word[expandedWordIndex - 3];
		uint32_t wordIndexMinus8  = SHA1_expanded_word[expandedWordIndex - 8];
		uint32_t wordIndexMinus14 = SHA1_expanded_word[expandedWordIndex - 14];
		uint32_t wordIndexMinus16 = SHA1_expanded_word[expandedWordIndex - 16];

		//XOR result of the 4 earlier words
		uint32_t xorOperationResult = wordIndexMinus3 ^ wordIndexMinus8 ^ wordIndexMinus14 ^ wordIndexMinus16;

		//Perform ROTL by 1 bit on the XOR result
		SHA1_expanded_word[expandedWordIndex] = SHA1_simpleROTL32(xorOperationResult, 1);
	}

#if SHA1_CONFIG_ENABLE_DEBUG

	static uint64_t blockIndex = 0;

	alt_putstr("Printing the 80 expanded words ##\n");
	alt_putstr("block indexes are in hex!\n");
	alt_printf("- Block[%x]:\n", blockIndex);

	for(uint8_t i = 0; i < SHA1_NUM_OF_EXPANDED_WORDS_PER_BLOCK; i++)
	{
		//this API is quite strange.. I cannot print the index, if I do, things will mess up!
		alt_printf("  + expanded word[] = 0x%x \n", SHA1_expanded_word[i]);
	}

	blockIndex++;

	alt_putchar('\n');

#endif
}

/**
 * \brief This function performs ROTL on a uint32_t variable
 *
 * \param uint32_t uint32Value : IN - the uin32_t value that needs to be ROTL
 * \param uint8_t numOfShiftBits : IN - the number of bits to be shifted. Must be between 0 and 31.
 * \return the result after performing ROTL
 */
static uint32_t SHA1_simpleROTL32(uint32_t uint32Value, uint8_t numOfShiftBits)
{
	// Ensure shift is within [0, 31] range
	assert( (numOfShiftBits < 31) && "shift too much" );

	//in case shift by 0 bits.
	if(numOfShiftBits == 0) return uint32Value;

	return (uint32Value << numOfShiftBits) | (uint32Value >> (32 - numOfShiftBits));
}

/**
 * \brief This function computes output hash A since its implementation is quite long
 *
 * Check Prof. Jakob's lecture slides on the SHA-1 algorithm.
 *
 * \param uint8_t roundIndex : IN - index of the current round of the Compression Function
 * \param uint32_t inputHashA : IN - input hash A
 * \param uint32_t inputHashB : IN - input hash B
 * \param uint32_t inputHashC : IN - input hash C
 * \param uint32_t inputHashD : IN - input hash D
 * \param uint32_t inputHashE : IN - input hash E
 */
static uint32_t SHA1_computeOutputHashA(uint8_t roundIndex,
										uint32_t inputHashA,
										uint32_t inputHashB,
										uint32_t inputHashC,
										uint32_t inputHashD,
										uint32_t inputHashE)
{
	//result of the kernel function that is performed on hash B, hash C, and hash D
	uint32_t processInputHashBCD = 0;

	//constant K value depending on the current stage of the Compression Function
	uint32_t constantK = 0;

	//if the current round is in stage 1 of the Compression Function
	if( SHA1_isStage01(roundIndex) )
	{
		processInputHashBCD = SHA1_kernelFunctionForStage01(inputHashB, inputHashC, inputHashD);
		constantK = SHA1_K_STAGE_1;
	}
	//if the current round is in stage 2 of the Compression Function
	else if( SHA1_isStage02(roundIndex) )
	{
		processInputHashBCD = SHA1_kernelFunctionForStage02(inputHashB, inputHashC, inputHashD);
		constantK = SHA1_K_STAGE_2;
	}
	//if the current round is in stage 3 of the Compression Function
	else if( SHA1_isStage03(roundIndex) )
	{
		processInputHashBCD = SHA1_kernelFunctionForStage03(inputHashB, inputHashC, inputHashD);
		constantK = SHA1_K_STAGE_3;
	}
	//if the current round is in stage 4 of the Compression Function
	else if( SHA1_isStage04(roundIndex) )
	{
		processInputHashBCD = SHA1_kernelFunctionForStage04(inputHashB, inputHashC, inputHashD);
		constantK = SHA1_K_STAGE_4;
	}
	//un-defined round
	else
	{
		//TODO: error handling
	}

	//process input hash A by using ROTL by 5 bits, check Prof. Jakob's slides for explanation of the number '5'
	uint32_t processInputHashA = SHA1_simpleROTL32(inputHashA, 5);

	return processInputHashA + processInputHashBCD + inputHashE + SHA1_expanded_word[roundIndex] + constantK;
}

/**
 * \brief This function checks if the current stage of the Compression Function is stage 1 or not,
 * 		  depending on the current round index
 *
 * \param uint8_t roundIndex : IN - current round index of the Compression Function
 * \return TRUE or FALSE
 */
static boolean_t SHA1_isStage01(uint8_t roundIndex)
{
	return (roundIndex >= 0) && (roundIndex <= 19);
}

/**
 * \brief This function checks if the current stage of the Compression Function is stage 2 or not,
 * 		  depending on the current round index
 *
 * \param uint8_t roundIndex : IN - current round index of the Compression Function
 * \return TRUE or FALSE
 */
static boolean_t SHA1_isStage02(uint8_t roundIndex)
{
	return (roundIndex >= 20) && (roundIndex <= 39);
}

/**
 * \brief This function checks if the current stage of the Compression Function is stage 3 or not,
 * 		  depending on the current round index
 *
 * \param uint8_t roundIndex : IN - current round index of the Compression Function
 * \return TRUE or FALSE
 */
static boolean_t SHA1_isStage03(uint8_t roundIndex)
{
	return (roundIndex >= 40) && (roundIndex <= 59);
}

/**
 * \brief This function checks if the current stage of the Compression Function is stage 4 or not,
 * 		  depending on the current round index
 *
 * \param uint8_t roundIndex : IN - current round index of the Compression Function
 * \return TRUE or FALSE
 */
static boolean_t SHA1_isStage04(uint8_t roundIndex)
{
	return (roundIndex >= 60) && (roundIndex <= 79);
}

/**
 * \brief This function is used for stage 1 of the Compression Function.
 *
 * Check Prof. Jakob's lecture slides on the SHA-1 algorithm.
 *
 * \param uint32_t x : IN - first parameter
 * \param uint32_t y : IN - second parameter
 * \param uint32_t z : IN - third parameter
 * \return result of the computation
 */
static uint32_t SHA1_kernelFunctionForStage01(uint32_t x, uint32_t y, uint32_t z)
{
	return (x & y) ^ ((~x) & z);
}

/**
 * \brief This function is used for stage 2 of the Compression Function.
 *
 * Check Prof. Jakob's lecture slides on the SHA-1 algorithm.
 *
 * \param uint32_t x : IN - first parameter
 * \param uint32_t y : IN - second parameter
 * \param uint32_t z : IN - third parameter
 * \return result of the computation
 */
static uint32_t SHA1_kernelFunctionForStage02(uint32_t x, uint32_t y, uint32_t z)
{
	return x ^ y ^ z;
}

/**
 * \brief This function is used for stage 3 of the Compression Function.
 *
 * Check Prof. Jakob's lecture slides on the SHA-1 algorithm.
 *
 * \param uint32_t x : IN - first parameter
 * \param uint32_t y : IN - second parameter
 * \param uint32_t z : IN - third parameter
 * \return result of the computation
 */
static uint32_t SHA1_kernelFunctionForStage03(uint32_t x, uint32_t y, uint32_t z)
{
	return (x & y) ^ (x & z) ^ (y & z);
}

/**
 * \brief This function is used for stage 4 of the Compression Function.
 *
 * Check Prof. Jakob's lecture slides on the SHA-1 algorithm.
 *
 * \param uint32_t x : IN - first parameter
 * \param uint32_t y : IN - second parameter
 * \param uint32_t z : IN - third parameter
 * \return result of the computation
 */
static uint32_t SHA1_kernelFunctionForStage04(uint32_t x, uint32_t y, uint32_t z)
{
	return x ^ y ^ z;
}

/**
 * \brief Print out the final hash result on the Eclipse Console
 *
 * \param SHA1_packet_t* packet : IN - the SHA-1 Packet Object
 * \param MSG_message_t* message : IN - the Message Object that contains an uin32_t array representation of the input string
 */
void SHA1_printFinalHash(SHA1_packet_t* packet, MSG_message_t* message)
{
	//find the index of the last 512-bit block
	uint64_t lastBlockIndex = packet->m_numOf512bitBlocks - 1;

	alt_printf("\nThe final Hash values of the string \"%s\" is\n\n", message->m_string);
	alt_printf("	%x %x %x %x %x\n",
			packet->m_512bit_block[lastBlockIndex].m_outputHash[SHA1_HASH_A],
			packet->m_512bit_block[lastBlockIndex].m_outputHash[SHA1_HASH_B],
			packet->m_512bit_block[lastBlockIndex].m_outputHash[SHA1_HASH_C],
			packet->m_512bit_block[lastBlockIndex].m_outputHash[SHA1_HASH_D],
			packet->m_512bit_block[lastBlockIndex].m_outputHash[SHA1_HASH_E]);

	alt_putchar('\n');
}

/**
 * \brief This function takes the output hash of the current 512-bit block and assigns
 * 		  to the input hash of the next 512-bit block
 *
 * \param SHA1_packet_t* packet : IN - the SHA-1 Packet Object
 * \param uint64_t blockIndex : IN - current block index
 */
void SHA1_updateInputHashForNextBlock(SHA1_packet_t* packet, uint64_t blockIndex)
{
	uint64_t nextBlockIndex = blockIndex + 1;

	//if the current block index is the last block => we end our function
	if( nextBlockIndex >= packet->m_numOf512bitBlocks )
	{
		return;
	}

	packet->m_512bit_block[nextBlockIndex].m_inputHash[SHA1_HASH_A] = packet->m_512bit_block[blockIndex].m_outputHash[SHA1_HASH_A];
	packet->m_512bit_block[nextBlockIndex].m_inputHash[SHA1_HASH_B] = packet->m_512bit_block[blockIndex].m_outputHash[SHA1_HASH_B];
	packet->m_512bit_block[nextBlockIndex].m_inputHash[SHA1_HASH_C] = packet->m_512bit_block[blockIndex].m_outputHash[SHA1_HASH_C];
	packet->m_512bit_block[nextBlockIndex].m_inputHash[SHA1_HASH_D] = packet->m_512bit_block[blockIndex].m_outputHash[SHA1_HASH_D];
	packet->m_512bit_block[nextBlockIndex].m_inputHash[SHA1_HASH_E] = packet->m_512bit_block[blockIndex].m_outputHash[SHA1_HASH_E];
}
