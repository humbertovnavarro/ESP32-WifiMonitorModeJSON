#include "esp_wifi.h"
#include "nvs_flash.h"
#include "wifi_sniffer.h"
void app_main(void) {
  nvs_flash_init();
  esp_event_loop_create_default();
  wifi_sniffer_start();
  for(;;) {
    vTaskDelay(1000 / portTICK_PERIOD_MS);
  }
}

