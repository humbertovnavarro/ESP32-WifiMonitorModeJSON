#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "esp_wifi.h"
#include "config.h"
#include "driver/uart.h"
#include "packet_utils.h"
#include "Arduino.h"
#include "ArduinoJson.h"
#include "base64.hpp"

const int uart_buffer_size = UART_BUF_SIZE;

QueueHandle_t uart_queue;
TaskHandle_t hop_task_handle;

wifi_promiscuous_filter_t wifi_sniffer_filter_config = {
    .filter_mask = WIFI_PROMIS_FILTER_MASK_MGMT,
};

const wifi_country_t wifi_country_config = {
    .cc = COUNTRY,
    .schan = LOWER_CHANNEL_BOUND,
    .nchan = UPPER_CHANNEL_BOUND,
    .policy = WIFI_COUNTRY_POLICY_AUTO
};


void sniffer_frame_cb(void* buf, wifi_promiscuous_pkt_type_t type) {
    wifi_promiscuous_pkt_t* pkt = (wifi_promiscuous_pkt_t*)buf;
    uint8_t* payload = pkt->payload;
    int len = pkt->rx_ctrl.sig_len;

    if (mgmt_frame_should_packet_filter(payload)) {
        return;
    }

    // Timestamps
    int64_t time_us = esp_timer_get_time();
    uint32_t ts_sec = time_us / 1000000;
    uint32_t ts_usec = time_us % 1000000;

    // Signal info
    int rssi = pkt->rx_ctrl.rssi;
    int channel = pkt->rx_ctrl.channel;
    uint8_t subtype = (payload[0] & 0xF0) >> 4;

    // MAC addresses
// MAC addresses
    char mac1[18] = "", mac2[18] = "", mac3[18] = "";
    if (len >= 24) {
        mac_to_str(payload + 4,  mac1);  // Address 1
        mac_to_str(payload + 10, mac2);  // Address 2 (typically source MAC)
        mac_to_str(payload + 16, mac3);  // Address 3 (typically BSSID)
    }

    // Parse SSID (only for beacon/probe request)
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

    // Base64 encode payload
    size_t b64_len = encode_base64_length(len);
    unsigned char payload_b64[b64_len];
    size_t outlen;
    encode_base64(payload, len, payload_b64);
    // Build JSON
    JsonDocument doc;
    doc["ts_sec"] = ts_sec;
    doc["ts_usec"] = ts_usec;
    doc["rssi"] = rssi;
    doc["channel"] = channel;
    doc["len"] = len;
    doc["ssid"] = ssid;
    doc["ra"] = mac1;
    doc["ta"] = mac2;
    doc["dst"] = mac3;
    doc["type"] = mgmt_frame_subtype_to_str(subtype);
    doc["payload_b64"] = payload_b64;
    // Serialize JSON
    char output[1024];
    size_t written = serializeJson(doc, output, sizeof(output));
    output[written++] = '\n';  // newline for streaming readers
    // Send over UART
    uart_write_bytes(UART_NUM_0, output, written);
}

void hop_task(void *pvparams) {
    int current_channel_index = 0;
    int channels[] = HOP_CHANNELS;
    while (1) {
        int channel = channels[current_channel_index];
        esp_wifi_set_channel(channel, WIFI_SECOND_CHAN_NONE);
        current_channel_index = (current_channel_index + 1) % NUM_CHANNELS;
        vTaskDelay(HOP_DELAY / portTICK_PERIOD_MS);
    }
}

void setup(void) {
  ESP_ERROR_CHECK(uart_driver_install(UART_NUM_0, uart_buffer_size, uart_buffer_size, 10, &uart_queue, 0));
  const uart_port_t uart_num = UART_NUM_0;
  uart_config_t uart_config = {
      .baud_rate = BAUD,
      .data_bits = UART_DATA_8_BITS,
      .parity = UART_PARITY_DISABLE,
      .stop_bits = UART_STOP_BITS_1,
      .flow_ctrl = UART_HW_FLOWCTRL_DISABLE,
  };
  ESP_ERROR_CHECK(uart_set_pin(UART_NUM_0, UART_TX, UART_RX, UART_PIN_NO_CHANGE, UART_PIN_NO_CHANGE));
  wifi_init_config_t default_wifi_client_config = WIFI_INIT_CONFIG_DEFAULT();
  ESP_ERROR_CHECK(esp_wifi_init(&default_wifi_client_config));
  ESP_ERROR_CHECK(esp_wifi_set_country(&wifi_country_config));
  ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_NULL));
  ESP_ERROR_CHECK(esp_wifi_set_promiscuous(true));
  ESP_ERROR_CHECK(esp_wifi_set_promiscuous_filter(&wifi_sniffer_filter_config));
  ESP_ERROR_CHECK(esp_wifi_set_promiscuous_rx_cb(sniffer_frame_cb));
  ESP_ERROR_CHECK(uart_param_config(uart_num, &uart_config));
  ESP_ERROR_CHECK(esp_netif_init());
  ESP_ERROR_CHECK(esp_event_loop_create_default());
  xTaskCreate(hop_task, "hop_task", 1024, NULL, 0, &hop_task_handle);
}

void loop() {
    for(;;) {
        vTaskDelay(100);
    }
}