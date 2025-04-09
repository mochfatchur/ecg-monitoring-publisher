#ifndef APP_CONFIG_H
#define APP_CONFIG_H

#define WIFI_SSID "YOUR_WIFI_SSID"
#define WIFI_PASSWORD "YOUR_WIFI_PASSWORD"

#define MQTT_SERVER "broker.hive.com"
#define MQTT_PORT 1883
#define MQTT_PUBLISH_TOPIC "YOUR_PUBLISH_TOPIC"

#define SERVER_BASE_URL "http://your-ip-server:3000"
#define API_URL(endpoint) (String(SERVER_BASE_URL) + endpoint)


#endif