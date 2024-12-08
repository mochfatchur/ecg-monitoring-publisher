# ECG Monitoring Publisher

## Deskripsi Proyek

## File Konfigurasi: `app_config.h`

Ubah File `app_config.template.h` menjadi `app_config.h`, file ini digunakan untuk mengatur konfigurasi proyek.

### Penjelasan Konfigurasi

1. **WiFi Configuration**:
   - `WIFI_SSID`: Nama jaringan WiFi yang akan digunakan ESP32 untuk terhubung ke internet.
   - `WIFI_PASSWORD`: Kata sandi untuk jaringan WiFi tersebut.

2. **MQTT Configuration**:
   - `MQTT_SERVER`: Alamat broker MQTT yang akan digunakan (contoh: `broker.hivemq.com`).
   - `MQTT_PORT`: Port komunikasi broker MQTT (default: `1883`).
   - `MQTT_PUBLISH_TOPIC`: Topik di mana data ECG akan dipublikasikan.