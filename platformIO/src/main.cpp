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

// AES
#include <mbedtls/aes.h>
#include "mbedtls/gcm.h"
#include "mbedtls/cipher.h"

// ECDH
#include "public_key.h"
#include "mbedtls/ecdh.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/entropy.h"

// timestamp
#include <time.h>


// setup NTP untuk timestamp
void setupTime() {
  Serial.println("==== Sinkronisasi Waktu NTP ====");
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

// TESTING ITERASI
const int TOTAL_ITERASI = 100;
int iterasiSekarang = 0;
bool sudahSelesai = false;
unsigned long encryptTimes[TOTAL_ITERASI];
uint32_t heapUsages[TOTAL_ITERASI];

// TEST Waktu Enkripsi
unsigned long measureEncryptionTime(std::function<void()> encryptFn) {
    unsigned long start = micros();
    encryptFn();
    return micros() - start;
}

// TEST Penggunaan Memori
unsigned long measureEncryptWithHeap(std::function<void()> encryptFn, uint32_t* heapUsedOut) {
    // Ambil heap sebelum enkripsi
    
    uint32_t heapBefore = ESP.getFreeHeap();
    // Catat waktu mulai
    unsigned long start = micros();

    // fungsi enkripsi yang akan diukur
    encryptFn(); 

    // Hitung waktu yang dibutuhkan untuk melakukan enkripsi data
    unsigned long elapsed = micros() - start;
    // Ambil heap setelah enkripsi 
    uint32_t heapAfter = ESP.getFreeHeap(); 

    // Hitung penggunaan heap
    *heapUsedOut = (heapBefore > heapAfter) ? (heapBefore - heapAfter) : 0; 

    // Mengembalikan waktu yang dibutuhkan untuk enkripsi dalam mikrodetik
    return elapsed; 
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
    Serial.println("POST Request ke: " + url);
    http.begin(url);
    http.addHeader("Content-Type", "application/json");
  
    String requestBody;
    serializeJson(jsonDoc, requestBody);
  
    Serial.println("payload request yang dikirimkan:");
    Serial.println(requestBody);
  
    int httpCode = http.POST(requestBody);
  
    if (httpCode > 0) {
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
}


void doKeyExchange() {
    Serial.println("=== Pembangkitan Kunci Publik dan Privat (IoT) ===");
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

    Serial.print("Kunci Publik IoT(hex): ");
    printHex(client_pub, olen);
    Serial.println("=== Kunci Publik milik IoT Dihasilkan ===\n");


    // Pembangkitan Salt
    Serial.println("=== Pembangkitan Salt ===");
    const size_t saltLen = 16;
    uint8_t salt[saltLen];
    generateSecureRandom(salt, saltLen);
    Serial.print("Salt (hex): ");
    printHex(salt, saltLen);
    Serial.println("=== Salt Dihasilkan ===");

    // Encode to base64
    String saltBase64 = base64::encode(salt, saltLen);
    String pub_b64 = base64::encode(client_pub, olen);
    // Buat payload JSON menggunakan ArduinoJson
    StaticJsonDocument<256> payload;
    payload["pub_key"] = pub_b64;
    payload["device_id"] = DEVICE_ID;
    payload["salt"] = saltBase64;

    // Send to server
    Serial.println("\n=== Memulai Pertukaran Kunci Publik IoT-Server ===");
    unsigned int len = 0;
    postPubKeyExchange(payload, server_pub, &len);
    Serial.print("Kunci Publik server (hex): ");
    printHex(server_pub, len);
    Serial.println("=== Kunci Publik Server Diterima ===\n");
    
    // Load server public key
    mbedtls_ecp_point_read_binary(&ctx.grp, &ctx.Qp, server_pub, len);

    // Derive shared secret
    mbedtls_ecdh_compute_shared(&ctx.grp, &ctx.z, &ctx.Qp, &ctx.d, mbedtls_ctr_drbg_random, &ctr_drbg);
    mbedtls_mpi_write_binary(&ctx.z, shared_secret, sizeof(shared_secret));

    // Hitung kunci bersama (ECDH)
    Serial.println("=== Memulai Perhitungan Kunci Bersama ===");
    Serial.print("Kunci Bersama (hex): ");
    printHex(shared_secret, sizeof(shared_secret));
    Serial.println("=== Kunci Bersama Dihasilkan ===");

    // Penurunan Kunci Enkripsi (HKDF)
    Serial.println("\n=== Memulai Penurunan Kunci Enkripsi (HKDF) ===");
    doHkdf(shared_secret, session_key, sizeof(session_key), salt, sizeof(salt), info, sizeof(info));
    // Print the derived session key
    Serial.print("Kunci Enkripsi (hex): ");
    printHex(session_key, sizeof(session_key));
    Serial.println("=== Kunci Sesi Dihasilkan ===");

    // Clean up
    mbedtls_ecdh_free(&ctx);
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_entropy_free(&entropy);

}

// Konfigurasi Pin ADC
#define ECG_PIN 36 // Pin ADC tempat sensor ECG terhubung

WiFiClient espClient;
PubSubClient client(espClient);

// Subscribe ke topik MQTT
const char* mqttCmdTopic = MQTT_SUBSCRIBE_TOPIC;

void connect_wifi() {
  delay(10);
  Serial.println("==== Setup WiFi ====");
  Serial.print("Menghubungkan ke ");
  Serial.println(WIFI_SSID);

  WiFi.begin(WIFI_SSID, WIFI_PASSWORD);
  while (WiFi.status() != WL_CONNECTED) {
    delay(500);
    Serial.print(".");
  }

  Serial.println("WiFi terhubung!");
  Serial.print("IP address: ");
  Serial.println(WiFi.localIP());
  Serial.println("==== Setup WiFi Selesai ====");
}

void connect_mqtt() {
  // Loop hingga terhubung ke broker MQTT
  Serial.println("\n==== Setup MQTT ====");
  while (!client.connected()) {
    Serial.print("Menghubungkan ke MQTT...");
    if (client.connect("ESP32Client")) {
      Serial.println("terhubung");
      client.subscribe(mqttCmdTopic);
      Serial.print("Subscribed to: ");
      Serial.println(mqttCmdTopic);
    } else {
      Serial.print("gagal, rc=");
      Serial.print(client.state());
      Serial.println(" mencoba lagi dalam 5 detik");
      delay(5000);
    }
  }
  Serial.println("==== Setup MQTT Selesai ====\n");
}

void callback(char* topic, byte* payload, unsigned int length) {
  Serial.print("[MQTT] Message arrived on topic: ");
  Serial.println(topic);

  // Copy payload to string
  String messageStr;
  for (unsigned int i = 0; i < length; i++) {
    messageStr += (char)payload[i];
  }

  Serial.print("Payload: ");
  Serial.println(messageStr);

  // Parse JSON
  StaticJsonDocument<256> doc;
  DeserializationError error = deserializeJson(doc, messageStr);

  if (error) {
    Serial.print("JSON parse failed: ");
    Serial.println(error.c_str());
    return;
  }

  // Check type
  const char* type = doc["type"];
  if (type && String(type) == "keyExchangeRequest") {
    const char* reason = doc["reason"];
    Serial.print("Key exchange requested due to: ");
    Serial.println(reason ? reason : "unknown");

    doKeyExchange();
  }
}

void doEncrypt(char *plainText, uint8_t *ciphertext,
               uint8_t *tag, uint8_t *iv,
               uint8_t *key, const char* ad) {

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
    Serial.print("ciphertext EKG (hex): ");
    printHex(ciphertext, strlen(plainText));

    // Cetak tag autentikasi
    Serial.print("Tag autentikasi:");
    printHex(tag, 16);

    Serial.print("AD (timestamp): ");
    Serial.println(ad);
}

void doEncryptAESGCM(char *plaintext, uint8_t *ciphertext,
                     uint8_t *tag, uint8_t *iv, uint8_t *key,
                     uint8_t *associatedData, size_t adLen) {
    // Inisialisasi konteks GCM
    mbedtls_gcm_context gcm;
    mbedtls_gcm_init(&gcm);
    mbedtls_gcm_setkey(&gcm, MBEDTLS_CIPHER_ID_AES, key, 128);
    mbedtls_gcm_crypt_and_tag(&gcm, MBEDTLS_GCM_ENCRYPT,
                              strlen(plaintext), iv, 16,
                              associatedData, adLen,
                              (const uint8_t *) plaintext, ciphertext,
                              16, tag);
    // Cetak hasil enkripsi
    Serial.print("ciphertext EKG (hex): ");
    printHex(ciphertext, strlen(plaintext));

    // Cetak tag autentikasi
    Serial.print("Tag autentikasi (hex): ");
    printHex(tag, 16);

    mbedtls_gcm_free(&gcm);
}

void setup() {
    // put your setup code here, to run once:
    Serial.begin(115200);
    // Initialize wifi & mqtt 
    Serial.println();
    connect_wifi();
    Serial.println();

    Serial.println("==== Inisiasi MQTT ====");
    client.setServer(MQTT_SERVER, MQTT_PORT);
    client.setCallback(callback);
    connect_mqtt();
    Serial.println("==== Setup MQTT berhasil ====");

    Serial.println();
    doKeyExchange();
    Serial.println();

    // konfigurasi waktu NTP
    setupTime();
}

void loop() {
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

    // timestamp sekarang dalam ms
    uint64_t nowMs = getEpochMillis();
    char ad[16];
    snprintf(ad, sizeof(ad), "%llu", nowMs);
    // Serial.printf("ESP Time (ms): %llu\n", nowMs);

    // Konversi integer ke string
    char ecgValueStr[4]; // Pastikan buffer cukup besar
    sprintf(ecgValueStr, "%d", ecgValue);
    Serial.print("Nilai EKG: ");
    Serial.println(ecgValue);

    uint8_t iv[16];
    generateSecureRandom(iv, 16);

     // Buffer untuk output ciphertext dan tag
    uint8_t ciphertext[strlen(ecgValueStr)];
    uint8_t tag[16];

    // Panggil fungsi enkripsi
    uint32_t heapUsed = 0;
    // unsigned long waktuEncrypt = measureEncryptWithHeap([&]() {
    //     doEncrypt(ecgValueStr, ciphertext, tag, iv, session_key, ad);
    // }, &heapUsed);

    unsigned long waktuEncrypt = measureEncryptWithHeap([&]() {
        doEncryptAESGCM(ecgValueStr, ciphertext, tag, iv, session_key, (uint8_t *) ad, strlen(ad));
    }, &heapUsed);

    // Simpan waktu
    if (iterasiSekarang < TOTAL_ITERASI) {
        encryptTimes[iterasiSekarang] = waktuEncrypt;
        heapUsages[iterasiSekarang] = heapUsed;

        iterasiSekarang++;

        // Tambahkan info iterasi
        Serial.print("Iterasi ke-");
        Serial.print(iterasiSekarang);
        Serial.print("/");
        Serial.println(TOTAL_ITERASI);
        // Serial.print(": Waktu = ");
        // Serial.print(waktuEncrypt);
        // Serial.print(" µs | Heap = ");
        // Serial.print(heapUsed);
        // Serial.println(" byte");
    }

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
    Serial.println("Payload yang akan di-publish:");
    Serial.println(jsonPayload);

    // Publish ke MQTT
    if (client.connected()) {
        client.publish(MQTT_PUBLISH_TOPIC, jsonPayload.c_str());
        Serial.println("Data terenkripsi dipublikasikan ke MQTT.\n");
    } else {
        Serial.println("Gagal mempublikasikan ke MQTT: tidak terhubung.");
    }

    // Setelah 100 iterasi, tampilkan hasil
    if (iterasiSekarang == TOTAL_ITERASI && !sudahSelesai) {
        unsigned long totalTime = 0;
        uint32_t totalHeap = 0;

        for (int i = 0; i < TOTAL_ITERASI; i++) {
            totalTime += encryptTimes[i];
            totalHeap += heapUsages[i];
        }

        float rataTime = totalTime / (float)TOTAL_ITERASI;
        float rataHeap = totalHeap / (float)TOTAL_ITERASI;

        // float variance = 0;
        // for (int i = 0; i < TOTAL_ITERASI; i++) {
        //     float diff = encryptTimes[i] - rataRata;
        //     variance += diff * diff;
        // }
        // float stddev = sqrt(variance / TOTAL_ITERASI);

        Serial.println("\n========== Hasil Benchmark ==========");
        Serial.print("Jumlah iterasi: ");
        Serial.println(TOTAL_ITERASI);
        Serial.print("Rata-rata waktu enkripsi: ");
        Serial.print(rataTime);
        Serial.println(" µs");
        Serial.print("Rata-rata penggunaan heap: ");
        Serial.print(rataHeap);
        Serial.println(" byte");
        Serial.println("=====================================");
        // Serial.print("Standar deviasi: ");
        // Serial.print(stddev);
        // Serial.println(" µs");
        // Serial.println("==============================================");

        sudahSelesai = true;
    }

    // Delay sebelum loop berikutnya
    delay(500);
}