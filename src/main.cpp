#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "esp_wifi.h"
#include "config.h"
#include "driver/uart.h"
#include "packet_utils.h"
#include "Arduino.h"
#include "ArduinoJson.h"
#include "base64.hpp"
#include "esp_heap_caps.h"
#include "stream_buffer.h"
#include "pcap.h"

static const char *TAG = "UART_PSRAM";
size_t psram_size = ESP.getPsramSize();
size_t free_heap = heap_caps_get_free_size(MALLOC_CAP_8BIT);
size_t uart_buffer_size = free_heap / 2 + psram_size;

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
    if (mgmt_frame_should_packet_filter(payload)) return;
    int64_t time_us = esp_timer_get_time();
    uint32_t ts_sec = time_us / 1000000;
    uint32_t ts_usec = time_us % 1000000;
    pcaprec_hdr_t phdr;
    phdr.ts_sec = ts_sec;
    phdr.ts_usec = ts_usec;
    phdr.incl_len = len;
    phdr.orig_len = len;
    uart_write_bytes(UART_NUM_0, (const char*)&phdr, sizeof(phdr));
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
    ESP_ERROR_CHECK(uart_driver_install(UART_NUM_0, uart_buffer_size, 0, 10, &uart_queue, 0));
    const uart_port_t uart_num = UART_NUM_0;
    uart_config_t uart_config = {
        .baud_rate = BAUD,
        .data_bits = UART_DATA_8_BITS,
        .parity = UART_PARITY_DISABLE,
        .stop_bits = UART_STOP_BITS_1,
        .flow_ctrl = UART_HW_FLOWCTRL_RTS,
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
    vTaskDelay(100);
}