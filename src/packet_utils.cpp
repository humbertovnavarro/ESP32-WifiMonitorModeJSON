#include <stdio.h>
#include <inttypes.h>
#include "packet_utils.h"


void mac_to_str(const uint8_t* mac, char* out) {
    snprintf(out, 18, "%02X:%02X:%02X:%02X:%02X:%02X",
             mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

bool mgmt_frame_should_packet_filter(uint8_t* payload) {
    uint8_t subtype = (payload[0] & 0xF0) >> 4;
    switch (subtype) {
        case ASSOC_REQ: break;
        case ASSOC_RESP: return true;
        case REASSOC_REQ: break;
        case REASSOC_RESP: return true;
        case PROBE_REQ: break;
        case PROBE_RESP: return true;
        case BEACON: break;
        case ATIM: return true;
        case DISASSOC: break;
        case AUTH: break;
        case DEAUTH: break;
        case ACTION: return true;
    }
    return false;
}

const char* mgmt_frame_subtype_to_str(uint8_t subtype) {
    switch (subtype) {
        case 0:  return "ASSOC_REQ";
        case 1:  return "ASSOC_RESP";
        case 2:  return "REASSOC_REQ";
        case 3:  return "REASSOC_RESP";
        case 4:  return "PROBE_REQ";
        case 5:  return "PROBE_RESP";
        case 8:  return "BEACON";
        case 9:  return "ATIM";
        case 10: return "DISASSOC";
        case 11: return "AUTH";
        case 12: return "DEAUTH";
        case 13: return "ACTION";
        default: return "UNKNOWN";
    }
}
