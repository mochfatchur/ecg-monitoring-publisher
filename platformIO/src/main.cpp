#include <Arduino.h>
#include <uECC.h>
#include <esp_system.h> // Untuk fungsi esp_fill_random

#include <mbedtls/hkdf.h>
#include <mbedtls/sha256.h>

extern "C" {

// Fungsi Random Number Generator (RNG) menggunakan hardware RNG ESP32
static int RNG(uint8_t *dest, unsigned size) {
    esp_fill_random(dest, size); // Mengisi array dengan angka acak
    return 1; // Berhasil
}

} // extern "C"

void setup() {
  // put your setup code here, to run once:
  Serial.begin(115200);
  Serial.println("Testing ECC on ESP32");

  // Set RNG untuk digunakan oleh library micro-ecc
  uECC_set_rng(&RNG);
}

void loop() {
  // put your main code here, to run repeatedly:
  // Memilih kurva elliptic curve (secp160r1)
    const struct uECC_Curve_t *curve = uECC_secp160r1();

    // Buffer untuk kunci privat dan publik
    uint8_t private1[21];
    uint8_t private2[21];
    uint8_t public1[40];
    uint8_t public2[40];

    // Buffer untuk shared secret
    uint8_t secret1[20];
    uint8_t secret2[20];

    // Membuat pasangan kunci pertama
    unsigned long a = millis();
    if (!uECC_make_key(public1, private1, curve)) {
        Serial.println("Failed to generate key pair 1");
        return;
    }
    unsigned long b = millis();
    Serial.print("Made key 1 in "); Serial.println(b - a);

    // Membuat pasangan kunci kedua
    a = millis();
    if (!uECC_make_key(public2, private2, curve)) {
        Serial.println("Failed to generate key pair 2");
        return;
    }
    b = millis();
    Serial.print("Made key 2 in "); Serial.println(b - a);

    // Menghitung shared secret 1
    a = millis();
    if (!uECC_shared_secret(public2, private1, secret1, curve)) {
        Serial.println("Shared secret calculation failed (1)");
        return;
    }
    b = millis();
    Serial.print("Shared secret 1 in "); Serial.println(b - a);

    // Menghitung shared secret 2
    a = millis();
    if (!uECC_shared_secret(public1, private2, secret2, curve)) {
        Serial.println("Shared secret calculation failed (2)");
        return;
    }
    b = millis();
    Serial.print("Shared secret 2 in "); Serial.println(b - a);

    // Memeriksa apakah kedua shared secret identik
    if (memcmp(secret1, secret2, 20) != 0) {
        Serial.println("Shared secrets are not identical!");
    } else {
        Serial.println("Shared secrets are identical");
    }

    // Gunakan HKDF untuk menurunkan kunci dari shared secret
    uint8_t asconKey[16]; // Kunci 128 bit untuk Ascon
    const char *salt = "ascon-kdf-salt"; // Salt opsional
    const char *info = "ascon-key-derivation"; // Info tambahan opsional

    int result = mbedtls_hkdf(
        mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), // Fungsi hash
        (const uint8_t *)salt, strlen(salt),         // Salt
        secret1, 20,                                 // Input: shared secret
        (const uint8_t *)info, strlen(info),         // Info tambahan
        asconKey, 16                                 // Output: kunci untuk Ascon
    );

    if (result != 0) {
        Serial.println("HKDF key derivation failed!");
        return;
    }

    // Cetak hasil kunci Ascon (opsional, hanya untuk debug)
    Serial.print("Ascon key: ");
    for (int i = 0; i < 16; i++) {
        Serial.printf("%02X", asconKey[i]);
    }
    Serial.println();


    // Delay sebelum loop berikutnya
    delay(5000);
}

// put function definitions here:
int myFunction(int x, int y) {
  return x + y;
}