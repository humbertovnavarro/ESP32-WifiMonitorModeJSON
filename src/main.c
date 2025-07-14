#include "esp_wifi.h"
#include "nvs_flash.h"
#include "wifi_sniffer.h"
#define HOP_DELAY 200
void app_main(void) {
  nvs_flash_init();
  esp_event_loop_create_default();
  uint8_t channels[] = {1, 6, 11};
  for(int i = 0; i < 3; i++) {
    esp_wifi_set_channel(channels[i], 0);
    if(i == 2) {
      i = 0;
    }
    vTaskDelay(HOP_DELAY / portTICK_PERIOD_MS);
  }
}

