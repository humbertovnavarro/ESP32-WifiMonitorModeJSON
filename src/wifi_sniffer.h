#include "esp_wifi.h"

/**
 * @brief Initializes the Wi-Fi stack in promiscuous mode and sets up packet capture.
 */
void wifi_sniffer_start(char* ssid, char* password);


void wifi_sniffer_set_filter(wifi_promiscuous_filter_t filter);