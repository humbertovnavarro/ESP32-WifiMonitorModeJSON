#include "esp_wifi.h"
#include "esp_wifi_types.h"
#include "wifi_sniffer.h"
#define HOP_DELAY 500

void wifi_sniffer_rx_cb(void* buf, wifi_promiscuous_pkt_type_t ppkt) {
    const wifi_promiscuous_pkt_t *pkt = (wifi_promiscuous_pkt_t *)buf;
    wifi_pkt_rx_ctrl_t rx_ctrl = pkt->rx_ctrl;
    Serial.println(rx_ctrl.channel);
    Serial.println(rx_ctrl.rssi);
    Serial.println();
}

void setup()
{
    Serial.begin(115200);
    pinMode(LED_BUILTIN, OUTPUT);
    Serial.println("Starting SNIFFUH");
    int my_channels[] = {1, 6, 11};
    wifi_sniffer_start(wifi_sniffer_rx_cb);
    wifi_sniffer_set_hop_channels(my_channels, sizeof(my_channels) / sizeof(my_channels[0]));
}

void loop()
{
    delay(1000);
    Serial.println("poke");
}