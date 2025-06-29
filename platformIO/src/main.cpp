#include <Arduino.h>
#include <ArduinoJson.h>
#include <Crypto.h>
#include <CryptoLW.h>
#include <Ascon128.h>

#include <base64.h>
#include <Base64.hpp>

#include <WiFi.h>
#include "app_config.h"

#include <HTTPClient.h>
#include <PubSubClient.h>

// HKDF
#include <SHA256.h>
#include <HKDF.h>


// ECDH
#include "public_key.h"
#include "mbedtls/ecdh.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/entropy.h"

// timestamp
#include <time.h>


// setup NTP untuk timestamp
void setupTime() {
  configTime(7 * 3600, 0, "time.windows.com");  // UTC+7, 0 DST
  Serial.print("Menunggu sinkronisasi waktu");
  time_t now = time(nullptr);
  while (now < 100000) {  // Waktu awal biasanya 0
    delay(500);
    Serial.print(".");
    now = time(nullptr);
  }
  Serial.println("\nWaktu tersinkronisasi!");
}

// Ambil waktu epoch dalam milidetik
uint64_t getEpochMillis() {
  struct timeval tv;
  gettimeofday(&tv, NULL);
  return (uint64_t)tv.tv_sec * 1000 + tv.tv_usec / 1000;
}

// utils
void printHex(const uint8_t* data, size_t length) {
    for (size_t i = 0; i < length; i++) {
      if (data[i] < 0x10) Serial.print("0");
      Serial.print(data[i], HEX);
    }
    Serial.println();
}


// Fungsi untuk mengonversi string HEX menjadi byte array
void hexStringToBytes(const char *hexString, unsigned char *byteArray, size_t byteArrayLen) {
    for (size_t i = 0; i < byteArrayLen; i++) {
        sscanf(&hexString[i * 2], "%2hhx", &byteArray[i]);
    }
}

// Fungsi untuk menghasilkan uint8_t array untuk IV dan salt
void generateSecureRandom(uint8_t* output, size_t length) {
    for (size_t i = 0; i < length; i++) {
        output[i] = esp_random() & 0xFF; // Ambil byte acak
    }
}

// Fungsi untuk melakukan key exchange
// ECDH in booting mode
// For session
uint8_t session_key[16];

void postPubKeyExchange(JsonDocument& jsonDoc, uint8_t* server_pub, unsigned int* len) {
    if (WiFi.status() != WL_CONNECTED) {
      Serial.println("WiFi not connected.");
      return;
    }
  
    HTTPClient http;
    String url = API_URL("/key-exchange");
    Serial.println("Posting to: " + url);
    http.begin(url);
    http.addHeader("Content-Type", "application/json");
  
    String requestBody;
    serializeJson(jsonDoc, requestBody);
  
    Serial.println("Sending JSON:");
    Serial.println(requestBody);
  
    int httpCode = http.POST(requestBody);
  
    if (httpCode > 0) {
      Serial.printf("HTTP Response code: %d\n", httpCode);
      String response = http.getString();
      Serial.println("Response:");
      Serial.println(response);
  
      // Decode Base64 response ke server_pub
      *len = decode_base64((const unsigned char*)response.c_str(), server_pub);
      server_pub[*len] = '\0';  // Optional null terminator
    } else {
      Serial.printf("POST failed, error: %s\n", http.errorToString(httpCode).c_str());
      *len = 0;
    }
  
    http.end();
}


// HKDF function
void doHkdf(uint8_t shared_key[32], uint8_t* outputKey, size_t outputKeyLength, uint8_t* salt, size_t saltLength, uint8_t* info, size_t infoLength) {
    // Validasi input
    if (shared_key == nullptr || outputKey == nullptr || salt == nullptr || info == nullptr) {
        Serial.println("Error: Parameter null");
        return;
    }

    // Menggunakan HKDF dengan SHA-256
    hkdf<SHA256>(
        outputKey,           // Output buffer (pointer)
        outputKeyLength,     // Panjang output yang diinginkan
        shared_key,          // Input Key Material (32 byte)
        32,                  // Panjang shared_key (selalu 32 byte)
        salt,                // Salt
        saltLength,          // Panjang salt
        info,                // Info opsional
        infoLength           // Panjang info
    );

    // Cetak kunci hasil derivasi
    Serial.println("Derived Key:");
    for (size_t i = 0; i < outputKeyLength; i++) {
        Serial.printf("%02X ", outputKey[i]);
    }
    Serial.println();
}


void doKeyExchange() {
    // init
    mbedtls_ecdh_context ctx;
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_entropy_context entropy;
    uint8_t client_pub[65], server_pub[65];
    size_t olen = 0;
    uint8_t shared_secret[32];

    // Init
    mbedtls_ecdh_init(&ctx);
    mbedtls_ctr_drbg_init(&ctr_drbg);
    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, NULL, 0);

    // Load curve (use secp256r1)
    mbedtls_ecp_group_load(&ctx.grp, MBEDTLS_ECP_DP_SECP256R1);

    // Generate client keypair
    mbedtls_ecdh_gen_public(&ctx.grp, &ctx.d, &ctx.Q, mbedtls_ctr_drbg_random, &ctr_drbg);
    mbedtls_ecp_point_write_binary(&ctx.grp, &ctx.Q, MBEDTLS_ECP_PF_UNCOMPRESSED, &olen, client_pub, sizeof(client_pub));


    // Generate Salt
    const size_t saltLen = 16;
    uint8_t salt[saltLen];
    generateSecureRandom(salt, saltLen);
    String saltBase64 = base64::encode(salt, saltLen);

    // Encode to base64
    String pub_b64 = base64::encode(client_pub, olen);
    // Buat payload JSON menggunakan ArduinoJson
    StaticJsonDocument<256> payload;
    payload["pub_key"] = pub_b64;
    payload["device_id"] = DEVICE_ID;
    payload["salt"] = saltBase64;

    // Send to server
    unsigned int len = 0;
    postPubKeyExchange(payload, server_pub, &len);
    
    // Load server public key
    mbedtls_ecp_point_read_binary(&ctx.grp, &ctx.Qp, server_pub, len);

    // Derive shared secret
    mbedtls_ecdh_compute_shared(&ctx.grp, &ctx.z, &ctx.Qp, &ctx.d, mbedtls_ctr_drbg_random, &ctr_drbg);
    mbedtls_mpi_write_binary(&ctx.z, shared_secret, sizeof(shared_secret));

    // Cetak hasil shared secret
    Serial.println("Shared secret:");
    for (size_t i = 0; i < sizeof(shared_secret); i++) { Serial.printf("%02X", shared_secret[i]); }
    Serial.println();

    // Derive session key via HKDF
    doHkdf(shared_secret, session_key, sizeof(session_key), salt, sizeof(salt), info, sizeof(info));
    
    // Print the derived session key
    Serial.print("Derived session key (hex): ");
    printHex(session_key, sizeof(session_key));

    Serial.println("[ESP32] Session key derived successfully");

    // Clean up
    mbedtls_ecdh_free(&ctx);
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_entropy_free(&entropy);

}

// Konfigurasi Pin ADC
#define ECG_PIN 36 // Pin ADC tempat sensor ECG terhubung

WiFiClient espClient;
PubSubClient client(espClient);


void connect_wifi() {
  delay(10);
  Serial.println();
  Serial.print("Menghubungkan ke ");
  Serial.println(WIFI_SSID);

  WiFi.begin(WIFI_SSID, WIFI_PASSWORD);
  while (WiFi.status() != WL_CONNECTED) {
    delay(500);
    Serial.print(".");
  }

  Serial.println("");
  Serial.println("WiFi terhubung");
  Serial.print("IP address: ");
  Serial.println(WiFi.localIP());
}

void connect_mqtt() {
  // Loop hingga terhubung ke broker MQTT
  while (!client.connected()) {
    Serial.print("Menghubungkan ke MQTT...");
    if (client.connect("ESP32Client")) {
      Serial.println("terhubung");
    } else {
      Serial.print("gagal, rc=");
      Serial.print(client.state());
      Serial.println(" mencoba lagi dalam 5 detik");
      delay(5000);
    }
  }
}

void doEncrypt(char *plainText, uint8_t *ciphertext, uint8_t *tag, uint8_t *iv,  uint8_t *key, const char* ad) {

    // Inisialisasi Ascon128
    Ascon128 cipher;

    // Set kunci dan IV
    if (!cipher.setKey(key, 16)) {
        Serial.println("Gagal menyetel kunci");
        return;
    }

    if (!cipher.setIV(iv, 16)) {
        Serial.println("Gagal menyetel IV");
        return;
    }

    // Tambahkan associated data
    cipher.addAuthData(ad, strlen(ad));

    // Lakukan enkripsi pesan
    cipher.encrypt(ciphertext, (const uint8_t *)plainText, strlen(plainText));

    // Hitung tag autentikasi
    cipher.computeTag(tag, 16);

    // Cetak hasil enkripsi
    Serial.println("Pesan terenkripsi:");
    for (size_t i = 0; i < strlen(plainText); i++) {
        Serial.printf("%02X ", ciphertext[i]);
    }
    Serial.println();

    // Cetak tag autentikasi
    Serial.println("Tag autentikasi:");
    for (size_t i = 0; i < 16; i++) {
        Serial.printf("%02X ", tag[i]);
    }
    Serial.println();

    Serial.print("AD: ");
    Serial.print("AD (string): ");
    Serial.println(ad);
}

void setup() {
    // put your setup code here, to run once:
    Serial.begin(115200);
    // Initialize wifi & mqtt 
    connect_wifi();
    client.setServer(MQTT_SERVER, MQTT_PORT);
    doKeyExchange();
    // konfigurasi waktu NTP
    setupTime();
}

void loop() {
    // put your main code here, to run repeatedly:
    Serial.println("==== Wifi & MQTT Test ====");
    if (WiFi.status() != WL_CONNECTED) {
        Serial.println("WiFi disconnected. Reconnecting...");
        connect_wifi();
    }
    
    if (!client.connected()) {
        connect_mqtt();
    }
    client.loop();

    // Baca data dari sensor ECG
    // int ecgValue = analogRead(ECG_PIN);
    int ecgValue = random(200, 900); // Generate random ECG value between 200 and 900

    // timestamp
    // time_t now = time(nullptr);
    // char ad[16];
    // snprintf(ad, sizeof(ad), "%ld", now);  // ubah timestamp jadi string

    // timestamp sekarang dalam ms
    uint64_t nowMs = getEpochMillis();
    char ad[16];
    snprintf(ad, sizeof(ad), "%llu", nowMs);
    Serial.printf("ESP Time (ms): %llu\n", nowMs);

    // int ecgValue = 271;
    // Konversi integer ke string
    char ecgValueStr[4]; // Pastikan buffer cukup besar
    sprintf(ecgValueStr, "%d", ecgValue);
    // test 
    Serial.print("ECG Value: ");
    Serial.println(ecgValue);

    Serial.println("==== Test Generate IV & Salt ====");
    uint8_t iv[16];

    generateSecureRandom(iv, 16);

    Serial.println("Generated IV:");
    for (size_t i = 0; i < 16; i++) {
        Serial.printf("%02X ", iv[i]);
    }

    Serial.println("==== ASCON AEAD TEST ====");
     // Buffer untuk output ciphertext dan tag
    uint8_t ciphertext[strlen(ecgValueStr)];
    uint8_t tag[16];

    // Print the derived session key
    Serial.print("Derived session key (hex): ");
    printHex(session_key, sizeof(session_key));

    // Panggil fungsi enkripsi
    doEncrypt(ecgValueStr, ciphertext, tag, iv, session_key, ad);

    Serial.println();

    // Gabungkan ciphertext dan tag menjadi satu array
    size_t ciphertextLen = sizeof(ciphertext);
    size_t totalLength = ciphertextLen + sizeof(tag);
    uint8_t *ciphertextAndTag = (uint8_t *)malloc(totalLength);
    if (ciphertextAndTag == nullptr) {
        Serial.println("Gagal mengalokasikan memori untuk ciphertextAndTag");
        return;
    }
    memcpy(ciphertextAndTag, ciphertext, ciphertextLen);
    memcpy(ciphertextAndTag + ciphertextLen, tag, sizeof(tag));

    // Konversi hasil gabungan ke Base64
    String ivBase64 = base64::encode(iv, 16);
    String ciphertextAndTagBase64 = base64::encode(ciphertextAndTag, totalLength);

    // Bebaskan memori yang digunakan untuk buffer gabungan
    free(ciphertextAndTag);

    // Buat payload JSON menggunakan ArduinoJson
    StaticJsonDocument<200> jsonDoc;
    jsonDoc["iv"] = ivBase64;
    jsonDoc["ad"] = ad;
    jsonDoc["msg"] = ciphertextAndTagBase64;

    String jsonPayload;
    serializeJson(jsonDoc, jsonPayload);

    // Cetak payload JSON
    Serial.println("Payload JSON:");
    Serial.println(jsonPayload);

    // Publish ke MQTT
    if (client.connected()) {
        client.publish(MQTT_PUBLISH_TOPIC, jsonPayload.c_str());
        Serial.println("Data terenkripsi dipublikasikan ke MQTT.");
    } else {
        Serial.println("Gagal mempublikasikan ke MQTT: tidak terhubung.");
    }

    // Delay sebelum loop berikutnya
    delay(500);
}