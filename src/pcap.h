#pragma once
#include <stdint.h>
// PCAP Global Header (to be written once at the start of capture)
typedef struct __attribute__((packed)) {
    uint32_t magic_number;   // 0xa1b2c3d4
    uint16_t version_major;  // 2
    uint16_t version_minor;  // 4
    int32_t  thiszone;       // GMT offset
    uint32_t sigfigs;        // accuracy of timestamps
    uint32_t snaplen;        // max length of captured packets
    uint32_t network;        // link-layer type: 105 = LINKTYPE_IEEE802_11
} pcap_hdr_t;

// PCAP Per-Packet Header
typedef struct __attribute__((packed)) {
    uint32_t ts_sec;         // timestamp seconds
    uint32_t ts_usec;        // timestamp microseconds
    uint32_t incl_len;       // number of octets of packet saved in file
    uint32_t orig_len;       // actual length of packet
} pcaprec_hdr_t;

// Optional: Radiotap header for ESP32 Wi-Fi metadata
typedef struct __attribute__((packed)) {
    uint8_t version;         // Always 0
    uint8_t pad;
    uint16_t len;            // Length of radiotap header
    uint32_t present;        // Bitmap of present fields (simplified)
} radiotap_hdr_t;

// Radiotap field bit masks (simplified)
#define RADIOTAP_TSFT        0x00000001
#define RADIOTAP_FLAGS       0x00000002
#define RADIOTAP_RATE        0x00000004
#define RADIOTAP_CHANNEL     0x00000008
#define RADIOTAP_DBM_ANTSIGNAL 0x00000020
