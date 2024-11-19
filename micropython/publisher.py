from env import mqtt_broker_ip, topic, delay_send
import time
import ubinascii
import machine
from umqtt.simple import MQTTClient
import random
import os
import json

# crypt lib
import ascon

# crypt cred
variant = "Ascon-128"

# Default MQTT server to connect to
SERVER = mqtt_broker_ip
CLIENT_ID = ubinascii.hexlify(machine.unique_id())
TOPIC = topic


def reset():
    print("Resetting...")
    time.sleep(5)
    machine.reset()


def base64_encode(data):
    # Fungsi base64 encoder menggunakan b2a_base64 dari ubinascii
    return ubinascii.b2a_base64(data).decode('utf-8').strip()


def main():
    mqttClient = MQTTClient(CLIENT_ID, SERVER, keepalive=60)
    mqttClient.connect()
    print("Connected to MQTT  Broker :: ", SERVER)

    while True:
        # read data sensor
        random_temp = random.randint(20, 50)

        # generate key and nonce/IV
        nonce = os.urandom(16)
        key = os.urandom(16)

        # Get plaintext
        plaintext = str(random_temp).encode('utf-8')

        # Generate associated data
        device_id = CLIENT_ID.decode('utf-8')  # Device ID based on machine unique ID
        timestamp = str(int(time.time()))  # Current timestamp as a string
        sensor_type = "ecg"  # Data type description

        # Format associated data string
        associateddata = (device_id + "|" + timestamp + "|" + sensor_type).encode('utf-8')

        # Encrypt
        ciphertext = ascon.ascon_encrypt(key, nonce, associateddata, plaintext, variant)

        # Mengonversi ciphertext, nonce, dan public key ke Base64
        ciphertext_base64 = base64_encode(ciphertext)
        nonce_base64 = base64_encode(nonce)
        public_key_base64 = base64_encode(key)

        # format payload
        payload = {
            "data": ciphertext_base64,
            "nonce": nonce_base64,
            "public_key": public_key_base64,
            'associated_data': associateddata
        }

        # Publishing data
        print("Publishing ECG :: ", random_temp)
        mqttClient.publish(TOPIC, json.dumps(payload))

        # delay
        time.sleep(delay_send)
    mqttClient.disconnect()


if __name__ == "__main__":
    try:
        main()
    except OSError as e:
        print("Error: " + str(e))
        reset()
