#ifndef WIFI_SNIFFER_H
#define WIFI_SNIFFER_H

#include <stddef.h>
#include "esp_wifi_types.h"
#include "esp_wifi.h"

#ifdef __cplusplus
extern "C" {
#endif

void wifi_sniffer_start(wifi_promiscuous_cb_t cb);
void wifi_sniffer_stop(void);
void wifi_sniffer_set_hop_channels(int* set_channels, size_t count);
void wifi_sniffer_set_hop_delay(int new_hop_delay);
void wifi_sniffer_set_country_config(wifi_country_t config);
void wifi_sniffer_set_filter(wifi_promiscuous_filter_t config);

#ifdef __cplusplus
}
#endif

#endif // WIFI_SNIFFER_H
