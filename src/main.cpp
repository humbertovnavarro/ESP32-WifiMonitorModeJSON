#include "esp_wifi.h"
#include "nvs_flash.h"
#include "esp_http_client.h"
#include "driver/uart.h"
#include "esp_err.h"
#include "esp_timer.h"
#define HOP_DELAY 200

bool pcap_header_sent = false;
const int uart_buffer_size = (1024 * 2);
QueueHandle_t uart_queue;

struct pcap_hdr {
    uint32_t magic_number;   // 0xa1b2c3d4
    uint16_t version_major;  // 2
    uint16_t version_minor;  // 4
    int32_t  thiszone;       // GMT to local correction
    uint32_t sigfigs;        // accuracy of timestamps
    uint32_t snaplen;        // max length of captured packets
    uint32_t network;        // data link type (DLT_IEEE802_11 = 105)
};

struct pcaprec_hdr {
    uint32_t ts_sec;         // timestamp seconds
    uint32_t ts_usec;        // timestamp microseconds
    uint32_t incl_len;       // number of bytes of packet saved
    uint32_t orig_len;       // actual length of packet
};

wifi_promiscuous_filter_t wifi_sniffer_filter_config = {
    .filter_mask = WIFI_PROMIS_FILTER_MASK_ALL,
};
const wifi_country_t wifi_country_config = {
    .cc = "US",
    .schan = 1,
    .nchan = 11,
    .policy = WIFI_COUNTRY_POLICY_AUTO
};

uint8_t channels[] = {1, 6, 11};

void sniffer_frame_cb(void* buf, wifi_promiscuous_pkt_type_t type) {
    wifi_promiscuous_pkt_t* packet = (wifi_promiscuous_pkt_t*)buf;
    if (!pcap_header_sent) {
      pcap_hdr header = {
          .magic_number = 0xa1b2c3d4,
          .version_major = 2,
          .version_minor = 4,
          .thiszone = 0,
          .sigfigs = 0,
          .snaplen = 65535,
          .network = 105  // DLT_IEEE802_11
      };
      uart_write_bytes(UART_NUM_0, (const char*)&header, sizeof(header));
      pcap_header_sent = true;
    }
    wifi_promiscuous_pkt_t* pkt = (wifi_promiscuous_pkt_t*)buf;
    // Timestamp
    int64_t time_us = esp_timer_get_time();
    uint32_t ts_sec = time_us / 1000000;
    uint32_t ts_usec = time_us % 1000000;
    // Captured data
    uint32_t length = pkt->rx_ctrl.sig_len;
    uint32_t capped_len = (length > 65535) ? 65535 : length;
    struct pcaprec_hdr pkt_hdr = {
        .ts_sec = ts_sec,
        .ts_usec = ts_usec,
        .incl_len = capped_len,
        .orig_len = capped_len
    };
    // Send packet header
    uart_write_bytes(UART_NUM_0, (const char*)&pkt_hdr, sizeof(pkt_hdr));
    // Send actual packet data
    uart_write_bytes(UART_NUM_0, (const char*)pkt->payload, capped_len);
}

void setup() {
  ESP_ERROR_CHECK(uart_driver_install(UART_NUM_0, uart_buffer_size, uart_buffer_size, 10, &uart_queue, 0));
  const uart_port_t uart_num = UART_NUM_0;
  uart_config_t uart_config = {
      .baud_rate = 115200,
      .data_bits = UART_DATA_8_BITS,
      .parity = UART_PARITY_DISABLE,
      .stop_bits = UART_STOP_BITS_1,
      .flow_ctrl = UART_HW_FLOWCTRL_CTS_RTS,
      .rx_flow_ctrl_thresh = 122,
  };
  ESP_ERROR_CHECK(uart_set_pin(UART_NUM_0, 39, 37, UART_PIN_NO_CHANGE, UART_PIN_NO_CHANGE));
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

void loop(void) {
  for(int i = 0; i < 3; i++) {
    esp_wifi_set_channel(channels[i], WIFI_SECOND_CHAN_NONE);
    if(i == 2) {
      i = 0;
    }
    vTaskDelay(HOP_DELAY / portTICK_PERIOD_MS);
  }
}