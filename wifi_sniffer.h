#ifndef WIFI_SNIFFER_H
#define WIFI_SNIFFER_H

#include "esp_wifi.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include <vector>
#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Initializes the Wi-Fi stack in promiscuous mode and sets up packet capture to a callback function.
 *
 * @param cb The callback function to be called when a packet is captured.
 */
void wifi_sniffer_start(wifi_promiscuous_cb_t cb);

/**
 * @brief Sets the capture filter on monitor mode.
 *
 * @param config The filter configuration.
 */
void wifi_sniffer_set_filter(wifi_promiscuous_filter_t config);

/**
 * @brief Sets the country configuration and channel definitions on monitor mode.
 *
 * @param config The country configuration.
 */
void wifi_sniffer_set_country_config(wifi_country_t config);

#ifdef __cplusplus
}
#endif

#endif  // WIFI_SNIFFER_H
