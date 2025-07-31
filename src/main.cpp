#include "esp_wifi.h"
#include "nvs_flash.h"
#include "esp_http_client.h"
#include "driver/uart.h"
#include "esp_err.h"
#include "esp_timer.h"
#include "base64.hpp"
#define JSON_BUF_SIZE 2048
const int uart_buffer_size = (1024 * 16);
#define BAUD 115200
#define HOP_DELAY 250

QueueHandle_t uart_queue;

wifi_promiscuous_filter_t wifi_sniffer_filter_config = {
    .filter_mask = WIFI_PROMIS_FILTER_MASK_MGMT,
};

const wifi_country_t wifi_country_config = {
    .cc = "US",
    .schan = 1,
    .nchan = 11,
    .policy = WIFI_COUNTRY_POLICY_AUTO
};

void to_hex_str(const uint8_t* data, size_t len, char* out, size_t out_size) {
    const char* hex = "0123456789ABCDEF";
    size_t i, j = 0;
    for (i = 0; i < len && j + 2 < out_size; ++i) {
        out[j++] = hex[data[i] >> 4];
        out[j++] = hex[data[i] & 0x0F];
    }
    out[j] = '\0';
}

void mac_to_str(const uint8_t* mac, char* out) {
    snprintf(out, 18, "%02X:%02X:%02X:%02X:%02X:%02X",
             mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

void sniffer_frame_cb(void* buf, wifi_promiscuous_pkt_type_t type) {
    wifi_promiscuous_pkt_t* pkt = (wifi_promiscuous_pkt_t*)buf;
    const uint8_t* payload = pkt->payload;
    const char* subtype_str = "UNKNOWN";
    
    uint8_t subtype = (payload[0] & 0xF0) >> 4;

    switch (subtype) {
        case 0: subtype_str = "AssocReq"; break;
        case 1: subtype_str = "AssocResp"; return;
        case 2: subtype_str = "ReassocReq"; break;
        case 3: subtype_str = "ReassocResp"; return;
        case 4: subtype_str = "ProbeReq"; break;
        case 5: subtype_str = "ProbeResp"; return;
        case 8: subtype_str = "Beacon"; break;
        case 9: subtype_str = "ATIM"; return;
        case 10: subtype_str = "Disassoc"; break;
        case 11: subtype_str = "Auth"; break;
        case 12: subtype_str = "Deauth"; break;
        case 13: subtype_str = "Action"; return;
    }

    int len = pkt->rx_ctrl.sig_len;
    int64_t time_us = esp_timer_get_time();
    uint32_t ts_sec = time_us / 1000000;
    uint32_t ts_usec = time_us % 1000000;
    int rssi = pkt->rx_ctrl.rssi;
    int channel = pkt->rx_ctrl.channel;

    // Extract source MAC address
    char mac_str[18] = {0};
    if (len >= 16) {
        mac_to_str(payload + 10, mac_str);  // Address 2 (source)
    }

    // Parse SSID
    const char* ssid = "";
    char ssid_buf[33] = {0};
    if ((payload[0] & 0xF0) == 0x80 || (payload[0] & 0xF0) == 0x40) {
        int tag_offset = 36;
        while (tag_offset + 2 < len) {
            uint8_t tag_id = payload[tag_offset];
            uint8_t tag_len = payload[tag_offset + 1];
            if (tag_id == 0x00 && tag_offset + 2 + tag_len <= len) {
                int copy_len = tag_len > 32 ? 32 : tag_len;
                memcpy(ssid_buf, &payload[tag_offset + 2], copy_len);
                ssid_buf[copy_len] = '\0';
                ssid = ssid_buf;
                break;
            }
            tag_offset += 2 + tag_len;
        }
    }

    size_t encoded_len = encode_base64_length(len);
    unsigned char payload_b64[encoded_len + 1];
    encode_base64(payload, len, payload_b64);

    // Create JSON
    char json[JSON_BUF_SIZE];
    int json_len = snprintf(json, sizeof(json),
        "{"
        "\"ts_sec\":%lu,"
        "\"ts_usec\":%lu,"
        "\"rssi\":%d,"
        "\"channel\":%d,"
        "\"len\":%d,"
        "\"mac\":\"%s\","
        "\"ssid\":\"%s\","
        "\"subtype\":\"%s\","
        "\"payload\":\"%s\""
        "}\n",
        (unsigned long)ts_sec,
        (unsigned long)ts_usec,
        rssi,
        channel,
        len,
        mac_str,
        ssid,
        subtype_str,
        payload_b64
    );
    if (json_len > 0 && json_len < sizeof(json)) {
        uart_write_bytes(UART_NUM_0, json, json_len);
    }
}

void setup() {
  ESP_ERROR_CHECK(uart_driver_install(UART_NUM_0, uart_buffer_size, uart_buffer_size, 10, &uart_queue, 0));
  const uart_port_t uart_num = UART_NUM_0;
  uart_config_t uart_config = {
      .baud_rate = BAUD,
      .data_bits = UART_DATA_8_BITS,
      .parity = UART_PARITY_DISABLE,
      .stop_bits = UART_STOP_BITS_1,
      .flow_ctrl = UART_HW_FLOWCTRL_DISABLE,
  };
  #ifndef HELTEC_V3
    ESP_ERROR_CHECK(uart_set_pin(UART_NUM_0, 39, 37, UART_PIN_NO_CHANGE, UART_PIN_NO_CHANGE));
  #endif
  wifi_init_config_t default_wifi_client_config = WIFI_INIT_CONFIG_DEFAULT();
  ESP_ERROR_CHECK(esp_wifi_init(&default_wifi_client_config));
  ESP_ERROR_CHECK(esp_wifi_set_country(&wifi_country_config));
  ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_NULL));
  ESP_ERROR_CHECK(esp_wifi_set_promiscuous(true));
  ESP_ERROR_CHECK(esp_wifi_set_promiscuous_filter(&wifi_sniffer_filter_config));
  ESP_ERROR_CHECK(esp_wifi_set_promiscuous_rx_cb(sniffer_frame_cb));
  ESP_ERROR_CHECK(uart_param_config(uart_num, &uart_config));
  ESP_ERROR_CHECK(nvs_flash_init());
  ESP_ERROR_CHECK(esp_netif_init());
  ESP_ERROR_CHECK(esp_event_loop_create_default());
}

#define NUM_CHANNELS 3
int channels[] = {1, 6, 11};
#define HOP_DELAY 250

static int current_channel_index = 0;
static int last_channel = -1;

void loop(void) {
    while (1) {
        int channel = channels[current_channel_index];
        esp_wifi_set_channel(channel, WIFI_SECOND_CHAN_NONE);
        current_channel_index = (current_channel_index + 1) % NUM_CHANNELS;
        vTaskDelay(HOP_DELAY / portTICK_PERIOD_MS);
    }
}