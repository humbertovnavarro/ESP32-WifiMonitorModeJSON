#include <stdio.h>
#include <inttypes.h>

void mac_to_str(const uint8_t* mac, char* out);
bool mgmt_frame_should_packet_filter(uint8_t* payload);
const char* mgmt_frame_subtype_to_str(uint8_t subtype);
#define ASSOC_REQ     0
#define ASSOC_RESP    1
#define REASSOC_REQ   2
#define REASSOC_RESP  3
#define PROBE_REQ     4
#define PROBE_RESP    5
#define BEACON        8
#define ATIM          9
#define DISASSOC      10
#define AUTH          11
#define DEAUTH        12
#define ACTION        13
