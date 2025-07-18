#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include "esp_wifi.h"
#include "wifi_sniffer.h"
#include "esp_wifi_types.h"
#define STACK_SIZE 1024 * 4000

static wifi_promiscuous_filter_t wifi_sniffer_filter_config = {
  .filter_mask = WIFI_PROMIS_FILTER_MASK_ALL,
};

static wifi_country_t wifi_country_config = {
  .cc = "US",
  .schan = 1,
  .nchan = 11,
  .max_tx_power = 20,
  .policy = WIFI_COUNTRY_POLICY_AUTO
};

void wifi_sniffer_set_country_config(wifi_country_t config) {
  wifi_country_config = config;
}

void wifi_sniffer_set_filter(wifi_promiscuous_filter_t config) {
  wifi_sniffer_filter_config = config;
}

void wifi_sniffer_start(wifi_promiscuous_cb_t cb) {
  wifi_init_config_t default_wifi_client_config = WIFI_INIT_CONFIG_DEFAULT();
  ESP_ERROR_CHECK(esp_event_loop_create_default());
  ESP_ERROR_CHECK(esp_wifi_init(&default_wifi_client_config));
  ESP_ERROR_CHECK(esp_wifi_set_country(&wifi_country_config));
  ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_NULL));
  ESP_ERROR_CHECK(esp_wifi_set_promiscuous(true));
  ESP_ERROR_CHECK(esp_wifi_set_promiscuous_filter(&wifi_sniffer_filter_config));
  ESP_ERROR_CHECK(esp_wifi_set_promiscuous_rx_cb(cb));
}