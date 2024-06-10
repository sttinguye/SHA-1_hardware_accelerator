/*
 ============================================================================
 Name        : main.c
 Author      : Trung Tin Nguyen (1120436), and Dung Anh Huynh Pham (764527)
 Version     : v1.0
 Copyright   : fbeit, hda
 Description : FSoC Lab Assignment#1 - Implement SHA-1 algorithm in C
 ============================================================================
 */

#include "system.h"
#include "sys/alt_stdio.h"	//to print out on console
#include <string.h> 		//for the usage of strlen()

//user-defined files
#include "global.h" //typedefs for common datatypes
#include "sha1.h"   //SHA-1 implementation file
#include "msg.h"	//file containing API to convert input string into uint32_t array representation
#include "led.h"	//This file configure the LEDs

/**
 * \brief This function compares the output hash values and compare the correct one, then turn the LEDs accordingly
 *
 * \param SHA1_packet_t* packet : IN - the SHA-1 Packet Object
 */
void showResultOnLEDs(SHA1_packet_t* packet);

//the required input string
#define	INPUT_STRING "FSOC23/24 is fun!"

//the correct/expected SHA-1 hash values of the string "FSOC23/24 is fun!"
static uint32_t correctHashValues[SHA1_NUM_OF_HASH_WORDS_PER_BLOCK] =
	{0xa617f4b3, 0xa108b6dd, 0x82bb8c4a, 0x16ab0b35, 0x2a32a0b9};

int main(void)
{
	//Initially, we turn OFF all LEDs, 0xFF means all OFF
	LEDS.DATA_REG = 0xFF;

	alt_putstr("### FSOC_WS23/24_Lab01_1120436_764527 started. Works only with ASCII characters! ###\n\n");

	//Message Object process the input string into an array of uin32_t values.
	MSG_message_t message;

	//SHA-1 Packet Object process the array of uin32_t values of Object Message
	SHA1_packet_t packet;

	/**
	 * #Step 1: represent the input string as an array of uint32_t values storing
	 *          the HEX values of the ASCII characters.
	 */
	MSG_init(&message, INPUT_STRING, (uint32_t)strlen(INPUT_STRING));

	//print out uint32_t array representation of the input string.
	//un-comment if you want to see the uint32_t array representation of the input string.
//	MSG_printUint32Representation(&message);

	/**
	 * #Step 2: process the uint32_t array representation of the input string using SHA-1 algorithm.
	 */

	//initialize the sha1 packet object + do the Pre-Processing step of SHA-1 algorithm.
	SHA1_init(&packet, &message);

	//print out the pre-processed SHA1 packet.
	//un-comment if you want to see the 512-bit blocks of the SHA-1 Packet.
//	SHA1_printPreProcessedPacket(&packet);

	/**
	 * run the SHA-1 algorithm
	 *
	 * in file "sha1_config.h", you can turn the debug on or off to see the inner computations
	 */
	for(uint64_t i = 0; i < packet.m_numOf512bitBlocks; i++)
	{
		//operate on a single pre-processed 512-bit wide input message
		sha_1(packet.m_512bit_block[i].m_outputHash,
				packet.m_512bit_block[i].m_word,
				packet.m_512bit_block[i].m_inputHash);

		//takes the output hash of the current 512-bit block and assigns to the input hash of the next 512-bit block
		SHA1_updateInputHashForNextBlock(&packet, i);
	}

	//print out the final hash output.
	SHA1_printFinalHash(&packet, &message);

	//show the result on LEDs
	showResultOnLEDs(&packet);

	//release memory of the Objects at the end of program.
	SHA1_freeMemory(&packet);
	MSG_freeMemory(&message);

	return 0;
}

/**
 * \brief This function compares the output hash values and compare the correct one, then turn the LEDs accordingly
 *
 * \param SHA1_packet_t* packet : IN - the SHA-1 Packet Object
 */
void showResultOnLEDs(SHA1_packet_t* packet)
{
	//find the index of the last 512-bit block
	uint64_t lastBlockIndex = packet->m_numOf512bitBlocks - 1;

	if(packet->m_512bit_block[lastBlockIndex].m_outputHash[SHA1_HASH_A] != correctHashValues[SHA1_HASH_A])
	{
		//0xFF means all OFF
		LEDS.DATA_REG = 0xFF;
		return;
	}
	else if(packet->m_512bit_block[lastBlockIndex].m_outputHash[SHA1_HASH_B] != correctHashValues[SHA1_HASH_B])
	{
		//0xFF means all OFF
		LEDS.DATA_REG = 0xFF;
		return;
	}
	else if (packet->m_512bit_block[lastBlockIndex].m_outputHash[SHA1_HASH_C] != correctHashValues[SHA1_HASH_C])
	{
		//0xFF means all OFF
		LEDS.DATA_REG = 0xFF;
		return;
	}
	else if (packet->m_512bit_block[lastBlockIndex].m_outputHash[SHA1_HASH_D] != correctHashValues[SHA1_HASH_D])
	{
		//0xFF means all OFF
		LEDS.DATA_REG = 0xFF;
		return;
	}
	else if (packet->m_512bit_block[lastBlockIndex].m_outputHash[SHA1_HASH_E] != correctHashValues[SHA1_HASH_E])
	{
		//0xFF means all OFF
		LEDS.DATA_REG = 0xFF;
		return;
	}

    //0x00 means all ON
    LEDS.DATA_REG = 0x00;
}
