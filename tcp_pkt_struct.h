//
// Created by ytpillai on 4/13/19.
//

#ifndef USERLAND_H
#define USERLAND_H

#include <netinet/ip.h>
#include <netinet/tcp.h>
#include "libs/uthash.h"
#include <stdint.h>
#include <string.h>
// Structs to read a manipulate a raw TCP packet
typedef uint32_t addr_t;
typedef uint16_t port_t;

#define METADATA_SIZE 100
#define RET_METADATA_SIZE 10000
#pragma pack(push, 1)

#pragma pack(pop)

#pragma pack(push, 1)
typedef struct {
    uint32_t padding; // All zeroes
    uint8_t  exp_opt; // Should be experimental option assigned by IANA
    uint8_t  exp_opt_len;
	uint16_t exp_opt_id;
//uint16_t exp_opt_exid; // ExID for experimental option
    // Metadata is here
} pkt_meta;
#pragma pack(pop)




typedef struct {
    uint32_t seq_no;
    char *buf;
    int buf_len;
    UT_hash_handle hh;
} file_info_hash;

#pragma pack(push, 1)
typedef struct {
    struct iphdr ipv4_header;
    struct tcphdr tcp_header;
} full_tcp_pkt_t;
#pragma pack(pop)


#endif //USERLAND_NFQUEUE_C_CLIENT_TCP_PACKET_STRUCT_H
