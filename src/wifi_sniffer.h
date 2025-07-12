#ifndef WIFI_SNIFFER_H
#define WIFI_SNIFFER_H

#include "esp_wifi.h"

// Wi-Fi Channel to sniff on
#define CHANNEL 11

// Frame type strings for display
extern const char* frame_types[];

// Country configuration for Wi-Fi
extern const wifi_country_t wifi_country_config;

// Promiscuous mode filter configuration
extern wifi_promiscuous_filter_t wifi_sniffer_filter_config;

/**
 * @brief Callback function invoked on receiving a Wi-Fi frame in promiscuous mode.
 *
 * @param buf Pointer to the received packet buffer.
 * @param type Type of the received packet (management, control, data, etc.).
 */
void wifi_sniffer_frame_callback(void* buf, wifi_promiscuous_pkt_type_t type);

/**
 * @brief Initializes the Wi-Fi stack in promiscuous mode and sets up packet capture.
 */
void wifi_sniffer_start(void);

#endif // WIFI_SNIFFER_H
