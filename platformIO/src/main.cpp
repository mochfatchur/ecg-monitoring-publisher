#include <Arduino.h>
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

// Fungsi untuk menjalankan ECDH
void runECDHTest() {
    // Inisialisasi struktur mbedTLS
    mbedtls_ecdh_context ecdh;
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_entropy_context entropy;

    // Buffer untuk kunci
    unsigned char public_key[65];
    size_t public_key_len;
    unsigned char shared_secret[32];
    size_t shared_secret_len;

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
                                       MBEDTLS_ECP_PF_UNCOMPRESSED, &public_key_len,
                                       public_key, sizeof(public_key)) != 0) {
        Serial.println("Failed to write public key");
        goto cleanup;
    }

    Serial.println("Public Key Alice Generated:");
    for (size_t i = 0; i < public_key_len; i++) {
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
    if (mbedtls_ecdh_calc_secret(&ecdh, &shared_secret_len,
                                 shared_secret, sizeof(shared_secret),
                                 mbedtls_ctr_drbg_random, &ctr_drbg) != 0) {
        Serial.println("Failed to compute shared secret");
        goto cleanup;
    }

    Serial.println("Shared Secret:");
    for (size_t i = 0; i < shared_secret_len; i++) {
        Serial.printf("%02X", shared_secret[i]);
    }
    Serial.println();

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


void setup_wifi() {
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
}

void reconnect() {
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


void setup() {
    // put your setup code here, to run once:
    Serial.begin(115200);
    // Initialize wifi & mqtt 
    setup_wifi();
    client.setServer(mqtt_server, MQTT_PORT);
    // Initialize Ascon cipher
    ascon.clear();
    ascon.setKey(key, sizeof(key));
    ascon.setIV(iv, sizeof(iv));
}


void doEncrypt() {
    // Pesan dan data autentikasi
    const char *plainText = "271";
    const char *authData = "ascon";

    // Inisialisasi Ascon128
    Ascon128 cipher;

    // Set kunci dan IV
    if (!cipher.setKey(key, sizeof(key))) {
        Serial.println("Gagal menyetel kunci");
        return;
    }
    
    if (!cipher.setIV(iv, sizeof(iv))) {
        Serial.println("Gagal menyetel IV");
        return;
    }
    
    // Tambahkan associated data
    cipher.addAuthData(authData, strlen(authData));

    // Buffer untuk hasil enkripsi
    uint8_t encryptedOutput[16];
    uint8_t tag[16];

    // Lakukan enkripsi pesan
    cipher.encrypt(encryptedOutput, (const uint8_t *)plainText, strlen(plainText));

    // Hitung tag autentikasi
    cipher.computeTag(tag, sizeof(tag));

    // Cetak hasil enkripsi
    Serial.println("Pesan terenkripsi:");
    for (size_t i = 0; i < strlen(plainText); i++) {
        Serial.printf("%02X ", encryptedOutput[i]);
    }
    Serial.println();

    // Cetak tag autentikasi
    Serial.println("Tag autentikasi:");
    for (size_t i = 0; i < sizeof(tag); i++) {
        Serial.printf("%02X ", tag[i]);
    }
    Serial.println();
}


void hkdfTest() {
     // Contoh shared_key (hasil ECDH, 32 byte)
    const uint8_t shared_key[32] = {
        0xA1, 0xB2, 0xC3, 0xD4, 0xE5, 0xF6, 0x07, 0x18,
        0x29, 0x3A, 0x4B, 0x5C, 0x6D, 0x7E, 0x8F, 0x90,
        0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
        0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00
    };

    // Contoh salt dan info
    const uint8_t salt[] = {0x01, 0x02, 0x03, 0x04}; // Salt untuk HKDF
    const uint8_t info[] = {0x05, 0x06, 0x07, 0x08}; // Info opsional

    // Buffer untuk kunci hasil derivasi
    uint8_t derived_key[16]; // Output key 16 byte

    // Menggunakan HKDF dengan SHA-256
    hkdf<SHA256>(
        derived_key,          // Output buffer
        sizeof(derived_key),  // Panjang output yang diinginkan (16 byte)
        shared_key,           // Input Key Material (32 byte)
        sizeof(shared_key),   // Panjang shared_key (32 byte)
        salt,                 // Salt
        sizeof(salt),         // Panjang salt
        info,                 // Info opsional
        sizeof(info)          // Panjang info
    );

    // Cetak kunci hasil derivasi
    Serial.println("Derived Key (16 bytes):");
    for (size_t i = 0; i < sizeof(derived_key); i++) {
        Serial.printf("%02X ", derived_key[i]);
    }
    Serial.println();
}

void loop() {
    // put your main code here, to run repeatedly:
    Serial.println("==== Wifi & MQTT Test ====");
    if (!client.connected()) {
        reconnect();
    }
    client.loop();

    // Baca data dari sensor ECG
    // int ecgValue = analogRead(ECG_PIN);
    int ecgValue = 271;
    Serial.print("ECG Value: ");
    Serial.println(ecgValue);

    // Konversi data ke string dan kirim ke broker MQTT
    char message[10];
    sprintf(message, "%d", ecgValue);
    client.publish(mqtt_topic, message);

    Serial.println("==== ECDH Test ====");
    runECDHTest();
    
    Serial.println("==== HKDF TEST ====");
    hkdfTest();

    Serial.println("==== ASCON AEAD TEST ====");
    doEncrypt();

    Serial.println();

    // Delay sebelum loop berikutnya
    delay(5000);
}