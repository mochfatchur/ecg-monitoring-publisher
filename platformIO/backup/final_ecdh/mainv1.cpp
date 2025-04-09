#include <Arduino.h>
#include <ArduinoJson.h>
#include <Crypto.h>
#include <CryptoLW.h>
#include <Ascon128.h>

#include <base64.h>

#include <WiFi.h>
#include "app_config.h"

#include <PubSubClient.h>

// HKDF
#include <SHA256.h>
#include <HKDF.h>


// ECDH
#include "public_key.h"
#include "mbedtls/ecdh.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/entropy.h"


// ECDH Main
// Kunci Publik Bob (statis)
const char bob_public_key_hex[] = CLIENT_PUBLIC_KEY;
const uint8_t associatedData[] = "ascon"; 

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

// Fungsi untuk menjalankan ECDH
void ecdhGenerateSharedKey(unsigned char *public_key, size_t *public_key_len,
                 unsigned char *shared_secret, size_t *shared_secret_len) {
    // Inisialisasi struktur mbedTLS
    mbedtls_ecdh_context ecdh;
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_entropy_context entropy;

    const char *pers = "ecdh_example";

    // Inisialisasi struktur
    mbedtls_ecdh_init(&ecdh);
    mbedtls_ctr_drbg_init(&ctr_drbg);
    mbedtls_entropy_init(&entropy);

    // Seed untuk RNG
    if (mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy,
                              (const unsigned char *)pers, strlen(pers)) != 0) {
        Serial.println("Failed to seed RNG");
        goto cleanup;
    }

    // Generate kunci ECDH (Alice)
    if (mbedtls_ecp_group_load(&ecdh.grp, MBEDTLS_ECP_DP_SECP256R1) != 0) {
        Serial.println("Failed to load curve");
        goto cleanup;
    }

    if (mbedtls_ecdh_gen_public(&ecdh.grp, &ecdh.d, &ecdh.Q,
                                mbedtls_ctr_drbg_random, &ctr_drbg) != 0) {
        Serial.println("Failed to generate public key");
        goto cleanup;
    }

    // Menulis public key Alice ke buffer
    if (mbedtls_ecp_point_write_binary(&ecdh.grp, &ecdh.Q,
                                       MBEDTLS_ECP_PF_UNCOMPRESSED, public_key_len,
                                       public_key, 65) != 0) {
        Serial.println("Failed to write public key");
        goto cleanup;
    }

    Serial.println("Public Key Alice Generated:");
    for (size_t i = 0; i < *public_key_len; i++) {
        Serial.printf("%02X", public_key[i]);
    }
    Serial.println();

    // Konversi kunci publik Bob dari HEX ke byte array
    unsigned char bob_public_key[65];
    hexStringToBytes(bob_public_key_hex, bob_public_key, sizeof(bob_public_key));

    // Parse public key Bob
    if (mbedtls_ecp_point_read_binary(&ecdh.grp, &ecdh.Qp,
                                      bob_public_key, sizeof(bob_public_key)) != 0) {
        Serial.println("Failed to parse Bob's public key");
        goto cleanup;
    }

    // Hitung shared secret
    if (mbedtls_ecdh_calc_secret(&ecdh, shared_secret_len,
                                 shared_secret, 32,
                                 mbedtls_ctr_drbg_random, &ctr_drbg) != 0) {
        Serial.println("Failed to compute shared secret");
        goto cleanup;
    }

    // Serial.println("Shared Secret:");
    // for (size_t i = 0; i < *shared_secret_len; i++) {
    //     Serial.printf("%02X", shared_secret[i]);
    // }
    // Serial.println();

cleanup:
    // Bersihkan resource
    mbedtls_ecdh_free(&ecdh);
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_entropy_free(&entropy);
}



// Ascon cipher instance
Ascon128 ascon;

// Encryption and decryption buffers
uint8_t plaintext[16];   // Data to encrypt (sensor data)
uint8_t ciphertext[16];  // Encrypted data
uint8_t decrypted[16];   // Decrypted data
uint8_t tag[16];         // tag

// ============= test data =================



// Konfigurasi WiFi
// Nama_SSID
const char* ssid = WIFI_SSID;
// Password_SSID
const char* password = WIFI_PASSWORD;

// Konfigurasi MQTT
const char* mqtt_server = MQTT_SERVER;
const char* mqtt_topic = MQTT_PUBLISH_TOPIC;

// Konfigurasi Pin ADC
#define ECG_PIN 36 // Pin ADC tempat sensor ECG terhubung

WiFiClient espClient;
PubSubClient client(espClient);


void connect_wifi() {
  delay(10);
  Serial.println();
  Serial.print("Menghubungkan ke ");
  Serial.println(ssid);

  WiFi.begin(ssid, password);
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

void doEncrypt(char *plainText, uint8_t *ciphertext, uint8_t *tag, uint8_t *iv,  uint8_t *key) {
    // Pesan dan data autentikasi
    const char *authData = "ascon";

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
    cipher.addAuthData(authData, strlen(authData));

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
}



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




void setup() {
    // put your setup code here, to run once:
    Serial.begin(115200);
    // Initialize wifi & mqtt 
    connect_wifi();
    client.setServer(mqtt_server, MQTT_PORT);
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
    Serial.println();

    const size_t saltLen = 16;
    uint8_t salt_test[saltLen];

    generateSecureRandom(salt_test, saltLen);

    Serial.println("Generated Salt:");
    for (size_t i = 0; i < saltLen; i++) {
        Serial.printf("%02X ", salt_test[i]);
    }
    Serial.println();

    Serial.println("==== ECDH Test ====");
    unsigned char public_key[65];
    size_t public_key_len;
    unsigned char shared_secret[32];
    size_t shared_secret_len;

    ecdhGenerateSharedKey(public_key, &public_key_len, shared_secret, &shared_secret_len);
    Serial.println("Shared Secret:");
    for (size_t i = 0; i < shared_secret_len; i++) {
        Serial.printf("%02X", shared_secret[i]);
    }
    Serial.println();
    Serial.println("==== HKDF TEST ====");

    // Buffer untuk kunci hasil derivasi
    uint8_t derived_key[16]; // Output key 16 byte

    // Panggil fungsi dengan parameter
    doHkdf(shared_secret, derived_key, sizeof(derived_key), salt_test, sizeof(salt_test), info, sizeof(info));
    
    Serial.println("==== ASCON AEAD TEST ====");
     // Buffer untuk output ciphertext dan tag
    uint8_t ciphertext[strlen(ecgValueStr)];
    uint8_t tag[16];

    // Panggil fungsi enkripsi
    doEncrypt(ecgValueStr, ciphertext, tag, iv, derived_key);

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
    String saltBase64 = base64::encode(salt_test, saltLen);
    String ciphertextAndTagBase64 = base64::encode(ciphertextAndTag, totalLength);
    String publicKeyBase64 = base64::encode(public_key, public_key_len);

    // Bebaskan memori yang digunakan untuk buffer gabungan
    free(ciphertextAndTag);

    // Buat payload JSON menggunakan ArduinoJson
    StaticJsonDocument<200> jsonDoc;
    jsonDoc["iv"] = ivBase64;
    jsonDoc["salt"] = saltBase64;
    jsonDoc["msg"] = ciphertextAndTagBase64;
    jsonDoc["pb"] = publicKeyBase64;

    String jsonPayload;
    serializeJson(jsonDoc, jsonPayload);

    // Cetak payload JSON
    Serial.println("Payload JSON:");
    Serial.println(jsonPayload);

    // Publish ke MQTT
    if (client.connected()) {
        client.publish("ecg/data", jsonPayload.c_str());
        Serial.println("Data terenkripsi dipublikasikan ke MQTT.");
    } else {
        Serial.println("Gagal mempublikasikan ke MQTT: tidak terhubung.");
    }

    // Delay sebelum loop berikutnya
    delay(5000);
}