#include "Arduino.h"
#include "config.h"
#include "esp_wifi.h"
#include "base64.hpp"
#include "packet_utils.h"

QueueHandle_t packet_queue;
TaskHandle_t hop_task_handle;
TaskHandle_t uart_task_handle;

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
    wifi_promiscuous_pkt_t* pkt = (wifi_promiscuous_pkt_t*) buf;
    xQueueSendFromISR(packet_queue, pkt, 0);
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

void uart_task(void* pv) {
    wifi_promiscuous_pkt_t pkt;
    while (1) {
        if (xQueueReceive(packet_queue, &pkt, portMAX_DELAY)) {
            int len = pkt.rx_ctrl.sig_len;
            int channel = pkt.rx_ctrl.channel;
            int rssi = pkt.rx_ctrl.rssi;
            // Base64 encode payload
            size_t base64_len = encode_base64_length(len);
            char base64_out[base64_len + 1];
            encode_base64(pkt.payload, len, (unsigned char*)base64_out);
            base64_out[base64_len] = '\0';
            Serial.printf("{\"len\":%d,\"rssi\":%d,\"channel\":%d,\"pkt\":\"%s\"}\n",
                          len, rssi, channel, base64_out);
        }
        vTaskDelay(10);
    }
}

void setup(void) {
    Serial.begin(921600);
    packet_queue = xQueueCreate(100, sizeof(wifi_promiscuous_pkt_t));
    wifi_init_config_t default_wifi_client_config = WIFI_INIT_CONFIG_DEFAULT();
    ESP_ERROR_CHECK(esp_wifi_init(&default_wifi_client_config));
    ESP_ERROR_CHECK(esp_wifi_set_country(&wifi_country_config));
    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_NULL));
    ESP_ERROR_CHECK(esp_wifi_set_promiscuous(true));
    ESP_ERROR_CHECK(esp_wifi_set_promiscuous_filter(&wifi_sniffer_filter_config));
    ESP_ERROR_CHECK(esp_wifi_set_promiscuous_rx_cb(sniffer_frame_cb));
    ESP_ERROR_CHECK(esp_netif_init());
    ESP_ERROR_CHECK(esp_event_loop_create_default());
    xTaskCreate(hop_task, "hop_task", 1024, NULL, 0, &hop_task_handle);
    xTaskCreate(uart_task, "uart_task", 8192, nullptr, 1, &uart_task_handle);
}


void loop() {
    vTaskDelay(100);
}