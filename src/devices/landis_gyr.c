/** @file
    ERT Standard Consumption Message (SCM) sensors.

    Copyright (C) 2020 Benjamin Larsson.

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.
*/

#include "decoder.h"

/**
ERT Standard Consumption Message (SCM) sensors.

Random information:

https://github.com/bemasher/rtlamr

https://en.wikipedia.org/wiki/Encoder_receiver_transmitter

https://patentimages.storage.googleapis.com/df/23/d3/f0c33d9b2543ff/WO2007030826A2.pdf

96-bit Itron® Standard Consumption Message protocol
https://www.smartmetereducationnetwork.com/uploads/how-to-tell-if-I-have-a-ami-dte-smart-advanced-meter/Itron%20Centron%20Meter%20Technical%20Guide1482163-201106090057150.pdf (page 28)

Data layout:

    SAAA AAAA  AAAA AAAA  AAAA A
    iiR PPTT TTEE CCCC CCCC CCCC  CCCC CCCC  CCCC IIII  IIII IIII  IIII IIII  IIII XXXX XXXX XXXX  XXXX

- S - Sync bit
- A - Preamble
- i - ERT ID Most Significant bits
- R - Reserved
- P - Physical tamper
- T - ERT Type (4 and 7 are mentioned in the pdf)
- E - Encoder Tamper
- C - Consumption data
- I - ERT ID Least Significant bits
- X - CRC (polynomial 0x6F63)

https://web.archive.org/web/20090828043201/http://www.openamr.org/wiki/ItronERTModel45

*/

static void landis_gyr_raw_msg(char *msg, uint8_t *b, uint8_t length) {
    int i;
    char c;
    char *p = msg;
    for (i = 0; i < length * 2; i++) {
        c = ((b[i >> 1]) >> (4 * (1 - (i & 1)))) & 0x0F;
        c = (c > 9) ? c + 55 : c + 48;
        *p++ = c;
    }
    *p = 0;
}

static void decode_10to8(bitbuffer_t *bytes, bitbuffer_t *bb, unsigned start) {
    // convert groups of 10 bits to one byte ?
    // remove start and stop bits
    uint8_t byte = 0;
    long offset = 1;
    bitbuffer_clear(bytes);
    uint8_t *data = bb->bb[0];
    unsigned bits = bb->bits_per_row[0] - start;
    //printf("bb length = %d bytes\n", bits / 10);
    for (unsigned ii=0; ii < bits / 10; ii++) {
        for (int jj=0; jj < 8; jj++) {
            // Start MSB first processing
            byte >>= 1;
            if (bitrow_get_bit(data, start + jj + offset))
                byte |= 0x80;
            if ((jj % 8) == 7) {
                bitbuffer_add_bit(bytes, byte >> 7 & 0x01);
                bitbuffer_add_bit(bytes, byte >> 6 & 0x01);
                bitbuffer_add_bit(bytes, byte >> 5 & 0x01);
                bitbuffer_add_bit(bytes, byte >> 4 & 0x01);
                bitbuffer_add_bit(bytes, byte >> 3 & 0x01);
                bitbuffer_add_bit(bytes, byte >> 2 & 0x01);
                bitbuffer_add_bit(bytes, byte >> 1 & 0x01);
                bitbuffer_add_bit(bytes, byte >> 0 & 0x01);
                byte = 0;
            }
        }
        offset += 10;
    }
}

static void new_bitbuffer(bitbuffer_t *bytes, bitbuffer_t *bb, unsigned start) {
    bitbuffer_clear(bytes);
    uint8_t *data = bb->bb[0];
    unsigned bits = bb->bits_per_row[0] - start;
    for (unsigned ii=0; ii < bits; ii++) {
        bitbuffer_add_bit(bytes, bitrow_get_bit(data, start + ii));
    }
}

static uint16_t landis_crc16 (uint16_t crc, uint8_t *data, size_t size) { 
// CoServ CRC = 0x45F8 
// Oncor CRC = 0x5FD6 
// EVERGY CRC = 0x486b
// Hard coded Poly 0x1021
    uint16_t i = 0;
    while (size--) {
        crc ^= data[i] << 8; 
        i++; 
        for (unsigned k = 0; k < 8; k++) 
            crc = crc & 0x8000 ? (crc << 1) ^ 0x1021 : crc << 1;
    }
    return crc; 
}

static int landis_gyr_decode(r_device *decoder, bitbuffer_t *bitbuffer)
{
//    uint8_t const preamble[] = {0xaa, 0xaa, 0xaa, 0xaa, 0xa0 , 0x07, 0xff /* , 0x??*/};
//    uint8_t const preamble[] = {0x55, 0x55, 0x55, 0x55, 0x55 , 0x55, 0x40, 0x0f, 0xff, 0x2a};
//    uint8_t const preamble[] = {0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0x80};
    uint8_t const preamble[] = {0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0x80};
    uint16_t preamble_bits = sizeof(preamble) * 8;
    
//    uint8_t *b;
    //uint8_t physical_tamper, ert_type, encoder_tamper;
    //uint32_t consumption_data, ert_id;
    data_t *data;
	char raw_msg[154] = {0}; // 42 hex chars plus 0
	//char raw_msg1[154] = {0}; // 42 hex chars plus 0
	//char raw_msg2[154] = {0}; // 42 hex chars plus 0
	//char raw_msg3[154] = {0}; // 42 hex chars plus 0

    // Search for preamble and sync-word
    unsigned start_pos = bitbuffer_search(bitbuffer, 0, 0, preamble, preamble_bits);

    // No preamble detected
    if (start_pos == bitbuffer->bits_per_row[0])
        return DECODE_ABORT_EARLY;

    if (bitbuffer->bits_per_row[0] > 1225)
        return DECODE_ABORT_LENGTH;

    if (bitbuffer->bits_per_row[0] < 130 )
        return DECODE_ABORT_LENGTH;

//    printf("Made it to header search!\n");
    //bitbuffer_debug(bitbuffer);

//    uint8_t const header_v4[] = {0x00, 0x5f, 0xf1}; // but only 30 bits
//    uint8_t const header_v5[] = {0x00, 0x7f, 0xf8}; // but only 31 bits

//    start_pos = bitbuffer_search(bitbuffer, 0, 0, header_v4, 24);
//    if (start_pos == bitbuffer->bits_per_row[0]) {
//        // No v1 to v4 header detected, try v5 header
//        start_pos = bitbuffer_search(bitbuffer, 0, 0, header_v5, 24);
//        if (start_pos == bitbuffer->bits_per_row[0])
//            // No v5 header detected
//            return DECODE_ABORT_EARLY;
//        else
//            start_pos += 31;
//    } else {
//        start_pos += 30;
//    }

//    uint8_t *bb = bitbuffer->bb[0];
//    bitbuffer_debug(bitbuffer);

    //printf("Number of rows = %d\n", bitbuffer->num_rows);
    //printf("buffer = %d bits\n", bitbuffer->bits_per_row[0]);
    // Remove preamble and sync word, keep whole payload
    //uint8_t b[155] = {0}; // I have seen a data string of over 750. But limit it here
    //bitbuffer_extract_bytes(bitbuffer, 0, start_pos + preamble_bits , b, bitbuffer->bits_per_row[0]);
    //uint8_t size = bitbuffer->bits_per_row[0] / 8 + 5;
    //printf("b length = %d bytes\n", (int)strlen((char *)b));
	//landis_gyr_raw_msg(raw_msg, b, size);
    // debug here
    //bitbuffer_debug(bitbuffer);
    bitbuffer_t bytes_from_preamble = {0};

    //start_pos += 81;
    //version 1-4 header is 30 bits and version 5 is 31 bits
    //if bits 61 to 81 are 0xff, 0x2a, the header is version 5
    //if bits 60 to 80 are 0xff, 0x2a, the header is version 4
    //start_pos += 80;
    // If shorten preamble above, new start position is 8 bits less!
    uint8_t const V4_HEADER_END = 72;
    bitbuffer_t bytes = {0};
    decode_10to8(&bytes, bitbuffer, start_pos + V4_HEADER_END - 20);
    uint8_t header_v4[2] = {0};
    bitbuffer_extract_bytes(&bytes, 0, 0, header_v4, 16);
    decode_10to8(&bytes, bitbuffer, start_pos + V4_HEADER_END - 19);
    uint8_t header_v5[2] = {0};
    bitbuffer_extract_bytes(&bytes, 0, 0, header_v5, 16);
    if (header_v4[0] == 0xff && header_v4[1] == 0x2a) {
        decode_10to8(&bytes, bitbuffer, start_pos + V4_HEADER_END);
    }
    else if (header_v5[0] == 0xff && header_v5[1] == 0x2a) {
        decode_10to8(&bytes, bitbuffer, start_pos + V4_HEADER_END +1);
    }
    uint8_t size = bytes.bits_per_row[0] / 8;
    // debug here
    //bitbuffer_debug(bytes);
    
    // first 8 bits is packet type
    uint8_t packet_type[1] = {0};
    bitbuffer_extract_bytes(&bytes, 0, 0, packet_type, 8);
   	char packet_type_txt[3] = {0};
	sprintf(packet_type_txt,"%02x", packet_type[0]);
    
    //if (packet_type[0] != 0xd5)
    //    return DECODE_ABORT_LENGTH;

    // crc'd data, so far packets are less than 75 bytes???
    uint8_t crc_data[144] = {0};
    //uint16_t crc_value = 0x0;
   	char crc_txt[5] = {0};
    uint16_t packet_length = 0x0;
    uint8_t b[2] = {0};
    uint8_t b1[1] = {0};
    
    switch (packet_type[0])
    {
        case 0xd5:
            // next 16 bits is packet length
            bitbuffer_extract_bytes(&bytes, 0, 8, b, 16);
            packet_length = (uint16_t)((b[0] << 8) | (b[1]));
            bitbuffer_extract_bytes(&bytes, 0, 24, crc_data, packet_length * 8 - 16);
            // next 16 bits is packet crc value
            bitbuffer_extract_bytes(&bytes, 0, 24 + packet_length * 8 - 16, b, 16);
            //crc_value = (uint16_t)((b[0] << 8) | (b[1]));
    	    sprintf(crc_txt,"%02x%02x", b[0], b[1]);
            break;

        case 0xd2:
            bitbuffer_extract_bytes(&bytes, 0, 8, b1, 8);
            packet_length = (uint16_t)(b1[0]);
            // no crc data ???
            bitbuffer_extract_bytes(&bytes, 0, 16, crc_data, packet_length * 8);
            packet_length += 2;
            //crc_value = 0x0;
            break;

        case 0x0:
            return DECODE_ABORT_LENGTH;
            break;

        default:
            new_bitbuffer(&bytes_from_preamble, bitbuffer, start_pos);
            bitbuffer_debug(&bytes_from_preamble);
            printf("packet_type = %s\n", packet_type_txt);
            bitbuffer_print(&bytes);
            printf("b length = %d bytes\n", size);
            if (size > 3) {
                // next 16 bits is packet length ?? possibly only 8 bits?
                bitbuffer_extract_bytes(&bytes, 0, 8, b1, 8);
                // try first 8 bits. == 0 then try all 16 bits for length
                if (b1[0] == 0x0) {
                    bitbuffer_extract_bytes(&bytes, 0, 16, b1, 8);
                    packet_length = (uint16_t)(b1[0]);
                    if (packet_length > 0) {
                        bitbuffer_extract_bytes(&bytes, 0, 24, crc_data, packet_length * 8 - 16);
                        // next 16 bits is packet crc value
                        bitbuffer_extract_bytes(&bytes, 0, 24 + packet_length * 8 - 16, b, 16);
                        //crc_value = (uint16_t)((b[0] << 8) | (b[1]));
     	                sprintf(crc_txt,"%02x%02x", b[0], b[1]);
                    }
                } else {
                    packet_length = (uint16_t)(b1[0]);
                    if (packet_length > 0) {
                        bitbuffer_extract_bytes(&bytes, 0, 16, crc_data, packet_length * 8 - 16);
                        // next 16 bits is packet crc value
                        bitbuffer_extract_bytes(&bytes, 0, 16 + packet_length * 8 - 16, b, 16);
                        //crc_value = (uint16_t)((b[0] << 8) | (b[1]));
     	                sprintf(crc_txt,"%02x%02x", b[0], b[1]);
                    }
                }
                break;
            }
    }
    // initial crc value
	char crc_calc_txt[5] = {0};
    uint16_t initial_crc_value = 0x486b;
    uint16_t crc_calc = 0x0;
    if (size > 0) {
        crc_calc = landis_crc16(initial_crc_value, crc_data, packet_length - 2);
    }
    sprintf(crc_calc_txt,"%04x", crc_calc);

	landis_gyr_raw_msg(raw_msg, crc_data, packet_length - 2);
/*
    uint8_t b1[155] = {0};
    bitbuffer_extract_bytes(bitbuffer, 0, start_pos + preamble_bits+10 , b1, bitbuffer->bits_per_row[0]-10);
	landis_gyr_raw_msg(raw_msg1, b1, size);

    uint8_t b2[155] = {0};
    bitbuffer_extract_bytes(bitbuffer, 0, start_pos + preamble_bits+2 , b2, bitbuffer->bits_per_row[0]-2);
	landis_gyr_raw_msg(raw_msg2, b2, size);

    uint8_t b3[155] = {0};
    bitbuffer_extract_bytes(bitbuffer, 0, start_pos + preamble_bits+3 , b3, bitbuffer->bits_per_row[0]-3);
	landis_gyr_raw_msg(raw_msg3, b3, size);
*/

    /* clang-format off */
    data = data_make(
            "model",           "",                 DATA_STRING, "LANDIS-GYR",
            "type",              "Type",         DATA_STRING, packet_type_txt,
            "crc",            "CRC",             DATA_STRING, crc_txt,
            "crc2",            "CRC2",             DATA_STRING, crc_calc_txt,
//            "ert_type",        "ERT Type",         DATA_INT, ert_type,
//            "encoder_tamper",  "Encoder Tamper",   DATA_INT, encoder_tamper,
//            "consumption_data","Consumption Data", DATA_INT, consumption_data,
            "mic",              "Integrity",        DATA_STRING, "CRC",
			"rawmsg",           "Datagram1",         DATA_STRING, raw_msg,
//			"rawmsg1",          "Datagram2",         DATA_STRING, raw_msg1,
//			"rawmsg2",          "Datagram3",         DATA_STRING, raw_msg2,
//			"rawmsg3",          "Datagram4",         DATA_STRING, raw_msg3,
            NULL);
    /* clang-format on */

    decoder_output_data(decoder, data);
    return 1;
}

static char *output_fields[] = {
        "model",
        "type",
        "crc",
        "crc2",
//        "ert_type",
//        "encoder_tamper",
//        "consumption_data",
        "mic",
		"rawmsg",
//		"rawmsg1",
//		"rawmsg2",
//		"rawmsg3",
        NULL,
};

r_device const landis_gyr = {
        .name        = "LANDIS_GYR Gridstream Protocol",
        .modulation  = FSK_PULSE_PCM,
        .short_width = 8,
        .long_width  = 8, // not used
        .gap_limit   = 0,
        .reset_limit = 800,
        .decode_fn   = &landis_gyr_decode,
        .disabled    = 0, // disabled and hidden, use 0 if there is a MIC, 1 otherwise
        .fields      = output_fields,
};
