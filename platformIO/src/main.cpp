#include <Arduino.h>
#include <Crypto.h>
#include <CryptoLW.h>
#include <Ascon128.h>
#include <ascon.h>

#include <base64.h>  // Gunakan base64 bawaan ESP32

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


void setup() {
  // put your setup code here, to run once:
  Serial.begin(115200);
  // Initialize Ascon cipher
    ascon.clear();
    ascon.setKey(key, sizeof(key));
    ascon.setIV(iv, sizeof(iv));
}


void encryptAndDecryptSensorData() {
    // Generate random sensor data
    int sensorValue = random(0, 1024); // Simulate sensor values between 0 and 1023
    Serial.print("Generated Sensor Value: ");
    Serial.println(sensorValue);

    // Convert sensor value to plaintext (simple conversion, fits into 16 bytes)
    memset(plaintext, 0, sizeof(plaintext));
    plaintext[0] = (sensorValue >> 8) & 0xFF;  // High byte
    plaintext[1] = sensorValue & 0xFF;         // Low byte

    // Encrypt the sensor data
    ascon.clear();
    ascon.setKey(key, sizeof(key));
    ascon.setIV(iv, sizeof(iv));
    ascon.encrypt(ciphertext, plaintext, sizeof(plaintext));

    Serial.print("Encrypted Data: ");
    for (size_t i = 0; i < sizeof(ciphertext); i++) {
        Serial.print(ciphertext[i], HEX);
        Serial.print(" ");
    }
    Serial.println();

    // Decrypt the encrypted data
    ascon.clear();
    ascon.setKey(key, sizeof(key));
    ascon.setIV(iv, sizeof(iv));
    ascon.decrypt(decrypted, ciphertext, sizeof(ciphertext));

    // Convert decrypted data back to sensor value
    int decryptedSensorValue = (decrypted[0] << 8) | decrypted[1];
    Serial.print("Decrypted Sensor Value: ");
    Serial.println(decryptedSensorValue);
}


void encryptAndDecryptWithAD() {
    int sensorValue = random(0, 1024); 
    Serial.print("Generated Sensor Value: ");
    Serial.println(sensorValue);

    // Konversi nilai sensor ke plaintext
    memset(plaintext, 0, sizeof(plaintext));
    plaintext[0] = (sensorValue >> 8) & 0xFF;  
    plaintext[1] = sensorValue & 0xFF;

    // Enkripsi
    ascon.clear();
    ascon.setKey(key, sizeof(key));
    ascon.setIV(iv, sizeof(iv));
    ascon.addAuthData(associatedData, sizeof(associatedData));
    ascon.encrypt(ciphertext, plaintext, sizeof(plaintext));
    ascon.computeTag(tag, sizeof(tag));

    Serial.print("Encrypted Data (size: ");
    Serial.print(sizeof(ciphertext));
    Serial.print(" bytes): ");
    for (size_t i = 0; i < sizeof(ciphertext); i++) {
        Serial.printf("%02X ", ciphertext[i]);
    }
    Serial.println();
    
    Serial.print("Tag (size: ");
    Serial.print(sizeof(tag));
    Serial.print(" bytes): ");
    for (size_t i = 0; i < sizeof(tag); i++) {
        Serial.printf("%02X ", tag[i]);
    }
    Serial.println();

    // Base64 encoding hasil dekripsi
    String base64Encoded = base64::encode(ciphertext, sizeof(ciphertext));
    Serial.print("Encrypted Data (Base64): ");
    Serial.println(base64Encoded);

    // Dekripsi
    ascon.clear();
    ascon.setKey(key, sizeof(key));
    ascon.setIV(iv, sizeof(iv));
    ascon.addAuthData(associatedData, sizeof(associatedData));
    ascon.decrypt(decrypted, ciphertext, sizeof(ciphertext));
    
    if (ascon.checkTag(tag, sizeof(tag))) {
        Serial.println("Tag Valid: Data is authenticated.");

        // Base64 encoding hasil dekripsi
        String base64Encoded = base64::encode(decrypted, sizeof(decrypted));
        Serial.print("Decrypted Data (Base64): ");
        Serial.println(base64Encoded);
    } else {
        Serial.println("Tag Invalid: Data authentication failed!");
    }
    Serial.println();
}



void loop() {
    // put your main code here, to run repeatedly:
    // Serial.println("Starting ECDH Test...");
    // runECDHTest();
    // Buffer untuk kunci privat dan publik
    uint8_t private1[21];
    uint8_t private2[21];
    uint8_t public1[40];
    uint8_t public2[40];
    // Buffer untuk shared secret
    uint8_t secret1[20];
    uint8_t secret2[20];
    
    // ascon test
    // encryptAndDecryptSensorData();
    encryptAndDecryptWithAD();

    // Delay sebelum loop berikutnya
    delay(5000);
}