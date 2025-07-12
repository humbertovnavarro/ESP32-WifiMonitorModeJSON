#include "esp_wifi.h"

const int CHANNEL = 11;

wifi_promiscuous_filter_t wifi_sniffer_filter_config = {
    .filter_mask = WIFI_PROMIS_FILTER_MASK_ALL,
};

const wifi_country_t wifi_country_config = {
    .cc = "US",
    .schan = 1,
    .nchan = 11,
    .policy = WIFI_COUNTRY_POLICY_AUTO
};

const char* frame_types[] = {
  "MANAGEMENT",
  "CONTROL",
  "DATA",
  "MISC"
};

void wifi_sniffer_frame_callback(void* buf, wifi_promiscuous_pkt_type_t type) {
    const wifi_promiscuous_pkt_t *ppkt = (wifi_promiscuous_pkt_t *)buf;
    const uint8_t* payload = ppkt->payload;
    uint16_t fc = payload[0] | (payload[1] << 8);
    uint8_t subtype = (fc >> 4) & 0xF;
    if ((fc & 0x0C) == 0x00) { // management frame
        const char* subtype_str = "unknown";
        switch (subtype) {
            case 0x08: subtype_str = "beacon"; break;
            case 0x04: subtype_str = "probe_request"; break;
            case 0x05: subtype_str = "probe_response"; break;
            case 0x00: subtype_str = "assoc_request"; break;
            case 0x01: subtype_str = "assoc_response"; break;
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
        const char* ssid = "";
        uint8_t ssid_len = 0;
        if (payload[36] == 0x00 && payload[37] <= 32) {
            ssid_len = payload[37];
            ssid = (const char*)&payload[38];
        }
        // Emit JSON
        printf("{\"type\":\"%s\",\"source\":\"%s\",\"dest\":\"%s\",\"bssid\":\"%s\",\"rssi\":%d,\"channel\":%d",
               subtype_str, src, dst, bssid, ppkt->rx_ctrl.rssi, ppkt->rx_ctrl.channel);
        if (ssid_len > 0) {
            printf(",\"ssid\":\"");
            for (uint8_t i = 0; i < ssid_len; i++) {
                char c = ssid[i];
                // JSON escape control characters or quotes
                if (c == '"' || c == '\\') printf("\\%c", c);
                else if ((unsigned char)c < 0x20) printf("\\u%04x", c);
                else putchar(c);
            }
            printf("\"");
        }
        printf("}\n");
    }
}

void wifi_sniffer_start() {
  wifi_init_config_t default_wifi_client_config = WIFI_INIT_CONFIG_DEFAULT();
  esp_wifi_init(&default_wifi_client_config);
  esp_wifi_set_country(&wifi_country_config);
  esp_wifi_set_mode(WIFI_MODE_NULL);
  esp_wifi_set_promiscuous(true);
  esp_wifi_set_promiscuous_filter(&wifi_sniffer_filter_config);
  esp_wifi_set_promiscuous_rx_cb(wifi_sniffer_frame_callback);
  esp_wifi_start();
  vTaskDelay(1000 / portTICK_PERIOD_MS);
  esp_wifi_set_channel(CHANNEL, WIFI_SECOND_CHAN_NONE);
}