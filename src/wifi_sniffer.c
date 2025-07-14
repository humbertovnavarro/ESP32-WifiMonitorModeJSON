#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include "esp_wifi.h"
#include "driver/uart.h"

wifi_promiscuous_filter_t wifi_sniffer_filter_config = {
    .filter_mask = WIFI_PROMIS_FILTER_MASK_ALL,
};

bool running = false;

const wifi_country_t wifi_country_config = {
    .cc = "US",
    .schan = 1,
    .nchan = 11,
    .policy = WIFI_COUNTRY_POLICY_AUTO
};

char* sniffer_frame_to_json(const wifi_promiscuous_pkt_t *ppkt) {
    static char json[512];  // Adjust size as needed
    const uint8_t* payload = ppkt->payload;
    uint16_t fc = payload[0] | (payload[1] << 8);
    uint8_t subtype = (fc >> 4) & 0xF;
    const char* subtype_str = "unknown";
    if ((fc & 0x0C) != 0x00) return NULL;  // Not a management frame
    switch (subtype) {
        case 0x08: subtype_str = "beacon"; return NULL; // Quick hack to filter. changeme.
        case 0x04: subtype_str = "probe_request"; break;
        case 0x05: subtype_str = "probe_response"; break;
        case 0x0B: subtype_str = "auth"; break;
        case 0x0C: subtype_str = "deauth"; break;
        default: return NULL;
    }
    char src[18], dst[18], bssid[18];
    snprintf(src, sizeof(src), "%02X:%02X:%02X:%02X:%02X:%02X",
             payload[10], payload[11], payload[12],
             payload[13], payload[14], payload[15]);
    snprintf(dst, sizeof(dst), "%02X:%02X:%02X:%02X:%02X:%02X",
             payload[4], payload[5], payload[6],
             payload[7], payload[8], payload[9]);
    snprintf(bssid, sizeof(bssid), "%02X:%02X:%02X:%02X:%02X:%02X",
             payload[16], payload[17], payload[18],
             payload[19], payload[20], payload[21]);
    char ssid[33] = "";
    uint8_t ssid_len = 0;
    if (payload[36] == 0x00 && payload[37] <= 32) {
        ssid_len = payload[37];
        const char* raw_ssid = (const char*)&payload[38];
        char* p = ssid;
        for (uint8_t i = 0; i < ssid_len && i < sizeof(ssid) - 1; i++) {
            char c = raw_ssid[i];
            if (c == '"' || c == '\\') {
                *p++ = '\\';
                *p++ = c;
            } else if ((unsigned char)c < 0x20) {
                p += sprintf(p, "\\u%04x", c);
            } else {
                *p++ = c;
            }
        }
        *p = '\0';
    }
    snprintf(json, sizeof(json),
             "{\"type\":\"%s\",\"source\":\"%s\",\"dest\":\"%s\",\"bssid\":\"%s\",\"rssi\":%d,\"channel\":%d",
             subtype_str, src, dst, bssid, ppkt->rx_ctrl.rssi, ppkt->rx_ctrl.channel);
    if (ssid_len > 0) {
        strncat(json, ",\"ssid\":\"", sizeof(json) - strlen(json) - 1);
        strncat(json, ssid, sizeof(json) - strlen(json) - 1);
        strncat(json, "\"", sizeof(json) - strlen(json) - 1);
    }
    strncat(json, "}", sizeof(json) - strlen(json) - 1);
    return json;
}


void sniffer_frame_cb(void* buf, wifi_promiscuous_pkt_type_t type) {
    char* out = sniffer_frame_to_json(buf);
    if(out != NULL) {
        printf(out);
        printf("\n");
    }    
}

void wifi_sniffer_start() {
    wifi_init_config_t default_wifi_client_config = WIFI_INIT_CONFIG_DEFAULT();
    ESP_ERROR_CHECK(esp_wifi_init(&default_wifi_client_config));
    ESP_ERROR_CHECK(esp_wifi_set_country(&wifi_country_config));
    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_NULL));
    ESP_ERROR_CHECK(esp_wifi_set_promiscuous(true));
    ESP_ERROR_CHECK(esp_wifi_set_promiscuous_filter(&wifi_sniffer_filter_config));
    ESP_ERROR_CHECK(esp_wifi_set_promiscuous_rx_cb(sniffer_frame_cb));
    ESP_ERROR_CHECK(esp_wifi_start());
}

void wifi_sniffer_set_filter(wifi_promiscuous_filter_t filter) {
    wifi_sniffer_filter_config = filter;
}
