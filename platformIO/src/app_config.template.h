#ifndef APP_CONFIG_H
#define APP_CONFIG_H

#define DEVICE_ID "YOUR_DEVICE_ID"

#define WIFI_SSID "YOUR_WIFI_SSID"
#define WIFI_PASSWORD "YOUR_WIFI_PASSWORD"

// AD8232 pins
#define ECG_PIN 36 //  ESP32 analog input pin A0(VP) (GPIO36) for the AD8232 output
#define LO_PLUS 22 // Lead-off detection LO+
#define LO_MINUS 23 // Lead-off detection LO-

#define MQTT_SERVER "broker.hive.com"
#define MQTT_PORT 1883
#define MQTT_PUBLISH_TOPIC "ecg/" DEVICE_ID
#define MQTT_SUBSCRIBE_TOPIC "cmd/" DEVICE_ID

#define SERVER_BASE_URL "http://your-ip-server:3000"
#define API_URL(endpoint) (String(SERVER_BASE_URL) + endpoint)


#endif