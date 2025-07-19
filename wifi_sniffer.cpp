#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include "esp_wifi.h"
#include "wifi_sniffer.h"
#include "esp_wifi_types.h"
#define STACK_SIZE 1024 * 4000

static TaskHandle_t xChannelHopperHandle;
static SemaphoreHandle_t xWifiSnifferConfigSemaphore;

static bool running = false;
static int hop_delay = 200;
int *channels;
size_t num_channels;

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

void vChannelHopper(void* pvParameters) {
    size_t i = 0;
    while (running) {
        if (!xSemaphoreTake(xWifiSnifferConfigSemaphore, pdMS_TO_TICKS(10))) {
            continue;
        }

        if (!running || channels == NULL || num_channels == 0) {
            xSemaphoreGive(xWifiSnifferConfigSemaphore);
            vTaskDelay(pdMS_TO_TICKS(hop_delay));
            continue;
        }

        int current_channel = channels[i];
        esp_wifi_set_channel(current_channel, WIFI_SECOND_CHAN_NONE);

        i = (i + 1) % num_channels;

        xSemaphoreGive(xWifiSnifferConfigSemaphore);
        vTaskDelay(pdMS_TO_TICKS(hop_delay));
    }
}


void wifi_sniffer_set_hop_channels(int* set_channels, size_t count) {
    xSemaphoreTake(xWifiSnifferConfigSemaphore, 0);

    channels = (int*)realloc(channels, count * sizeof(int));
    if (channels) {
        memcpy(channels, set_channels, count * sizeof(int));
        num_channels = count;
    } else {
        num_channels = 0; // if realloc fails
    }
    xSemaphoreGive(xWifiSnifferConfigSemaphore);
}

void wifi_sniffer_set_hop_delay(int new_hop_delay) {
  xSemaphoreTake(xWifiSnifferConfigSemaphore, 0);
  hop_delay = new_hop_delay;
  xSemaphoreGive(xWifiSnifferConfigSemaphore);
}

void wifi_sniffer_stop() {
  running = false;
  vTaskDelete(xChannelHopperHandle);
  free(channels);
  esp_wifi_stop();
  esp_wifi_deinit();
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
  running = true;
  xWifiSnifferConfigSemaphore = xSemaphoreCreateMutex();
  xTaskCreate(vChannelHopper, "channel_hopper", 2048, NULL, 1, &xChannelHopperHandle);
}