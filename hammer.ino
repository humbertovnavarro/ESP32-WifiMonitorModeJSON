#include "wifi_sniffer.h"
#include "esp_wifi.h"
#include "esp_wifi_types.h"
#include "nvs_flash.h"
#define HOP_DELAY 500
TaskHandle_t ChannelHopperHandle;
void setup()
{
    Serial.begin(115200);
    pinMode(LED_BUILTIN, OUTPUT);
    Serial.println("Starting SNIFFUH");
    wifi_sniffer_start(wifi_sniffer_rx_cb);
    xTaskCreate(channel_hopper, "channel_hopper", 2048, NULL, 1, &ChannelHopperHandle);
}

void wifi_sniffer_rx_cb(void* buf, wifi_promiscuous_pkt_type_t ppkt) {
    const wifi_promiscuous_pkt_t *pkt = (wifi_promiscuous_pkt_t *)buf;
    wifi_pkt_rx_ctrl_t rx_ctrl = pkt->rx_ctrl;
    Serial.println(rx_ctrl.channel);
    Serial.println(rx_ctrl.rssi);
    Serial.println();
}

void channel_hopper(void *pvParameters) {
    for(;;) {
        vTaskDelay(HOP_DELAY);
        esp_wifi_set_channel(1, WIFI_SECOND_CHAN_NONE);
        vTaskDelay(HOP_DELAY);
        esp_wifi_set_channel(6, WIFI_SECOND_CHAN_NONE);
        vTaskDelay(HOP_DELAY);
        esp_wifi_set_channel(11, WIFI_SECOND_CHAN_NONE);
    }
}

void loop()
{

}