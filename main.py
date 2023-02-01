from typing import Union
import aiohttp

from fastapi import FastAPI
from base64 import b64decode, b64encode
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5, AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad


app = FastAPI()

enc_key_response = "trkNAC1pBc1tLV19dypHpn1lkROrw+JMUHP62212ppWYcznd6lAl6rh5hk0+yQbfEz2IGQxVW/uC2XtQXzqc2IPgB3bZMSD80z+390BQot5nCdpnCEm6JnVHO0Mvliwhp88NgOm2saSgIAoY+p04slhou54n4z8rpK3193ZJIREVsN69k5U6XbR+KAYXI2OQ3GhaveFLXqK3aza//M4Ap1xAFQmIU6ScGtoaW62ZYr/WiPpZOG9CC6d6hzOqi34rqTnPdC4fF55JyMM0Sdqep4iAc0Fn/331jBzgXvJFeJ4i9oEZyuViMobHVdF8nFeNEWrh5ePFVJa1SfIhTNNykQ=="
enc_data_response = "oGd5snQd5CREWece9fiqPnisQwLZaLhzYFqyD7KeRzdjA17EHJL9maMDC3U01P+dC+d4Gki9qhLf1RM0VclUVrHiX+8kVVxVdZeWsTywj4+4FfLd8/GlSPZ7PbTbOs2jRlg8Vt8r7C+w5XQxoXwB3s2qnK0EnPepRZn3I532JC129laDVzbSRySyuaP1FGJvrOlsMhSP+edztf+t19Q2hTABbOiBhT+F+BShD96YRdvdlOd3mJlvLoWkPMgxAAJdteRrDegbn+XYeC4pKVgBEu3d0lt9YdYcQ01PicnufLw="


# Generating payload mets to send api request
api_test_key = 'xUHvlTOtkLn37jnuG0Yp8zr2kivgRg6j'
src_app = 'bankly'
ref_no = '20190704000084'
mer_id = 'FLP0000001'
mer_pass = 'admin12345'
product = 'VP01'
pro_cat = 36
linkMobile = '9944838952'
tran_remark = 'FLIPKART Card Mobile Number link'


@app.get("/")
def read_root():
    # decryptPayloadUsingPublicKey(enc_key_response)
    return {"Hello": "World"}

# Complete implementation of encryption and decription


@app.get("/send-test-request")
async def send_test_request():
    # Decrypting encrypted key to get session key,
    # to be used in AES decryption
    random_string = 'fgetdh3564hegde5'
    session_key_in_bytes = b64encode(random_string)
    # session_key_in_bytes = get_random_bytes(16)
    encrypted_session_key_in_bytes = encrypt_using_public_key(
        session_key_in_bytes)

    payload_data_to_be_encrypted = f'<xml><ReferenceNumber>{ref_no}</ReferenceNumber><MerchantId>{mer_id}</MerchantId><MerchantPassword>{mer_pass}</MerchantPassword><Product>{product}</Product><ProductCategory>{pro_cat}</ProductCategory><MobileNumber>{linkMobile}</MobileNumber><TransactionRemark>{tran_remark}</TransactionRemark></xml>'

    encrypted_payload_aes_cbc_json = encrypt_payload_with_aes_cbc(
        session_key_in_bytes, payload_data_to_be_encrypted)

    # Data to be packaged
    encrypted_data = encrypted_payload_aes_cbc_json['encrypted_payload_txt']
    iv = encrypted_payload_aes_cbc_json['iv']
    enc_session_key = b64encode(encrypted_session_key_in_bytes)

    # Sending POST request
    async with aiohttp.ClientSession() as session:
        # Generate random string for request id

        header = {'Content-Type': 'application/json',
                  "apikey": api_test_key, "SrcApp": src_app, 'Accept': 'application/json'}

        request_data = {
            "requestId": "",
            "service": 'LOP',
            "encryptedKey": enc_session_key,
            "oaepHashingAlgorithm": "NONE",
            "iv": "",
            "encryptedData": encrypted_data,
            "clientInfo": "",
            "optionalParam": ""
        }

        endpoint_url = 'https://apibankingonesandbox.icicibank.com/api/v1/pcms-chw?service=LinkedMobile'

        async with session.post(endpoint_url, headers=header, data=request_data) as response:
            #  decrypting response
            print(response.json)

    return {"Hello": "World"}


@app.get("/encrypt-test")
def encrypt_test():
    # Decrypting encrypted key to get session key,
    # to be used in AES decryption
    session_key_in_bytes = get_random_bytes(16)
    encrypted_session_key_in_bytes = encrypt_using_public_key(
        session_key_in_bytes)

    payload_data_to_be_encrypted = f'<xml><ReferenceNumber>{ref_no}</ReferenceNumber><MerchantId>{mer_id}</MerchantId><MerchantPassword>{mer_pass}</MerchantPassword><Product>{product}</Product><ProductCategory>{pro_cat}</ProductCategory><MobileNumber>{linkMobile}</MobileNumber><TransactionRemark>{tran_remark}</TransactionRemark></xml>'

    encrypted_payload_aes_cbc_json = encrypt_payload_with_aes_cbc(
        session_key_in_bytes, payload_data_to_be_encrypted)

    encrypted_data = encrypted_payload_aes_cbc_json['encrypted_payload_txt']
    iv = encrypted_payload_aes_cbc_json['iv']

    # Send api request to ICICI server

    return {"IV": iv}


@app.get("/decrypt-test")
def decrypt_test():
    enc_key_response = "trkNAC1pBc1tLV19dypHpn1lkROrw+JMUHP62212ppWYcznd6lAl6rh5hk0+yQbfEz2IGQxVW/uC2XtQXzqc2IPgB3bZMSD80z+390BQot5nCdpnCEm6JnVHO0Mvliwhp88NgOm2saSgIAoY+p04slhou54n4z8rpK3193ZJIREVsN69k5U6XbR+KAYXI2OQ3GhaveFLXqK3aza//M4Ap1xAFQmIU6ScGtoaW62ZYr/WiPpZOG9CC6d6hzOqi34rqTnPdC4fF55JyMM0Sdqep4iAc0Fn/331jBzgXvJFeJ4i9oEZyuViMobHVdF8nFeNEWrh5ePFVJa1SfIhTNNykQ=="
    enc_data_response = "oGd5snQd5CREWece9fiqPnisQwLZaLhzYFqyD7KeRzdjA17EHJL9maMDC3U01P+dC+d4Gki9qhLf1RM0VclUVrHiX+8kVVxVdZeWsTywj4+4FfLd8/GlSPZ7PbTbOs2jRlg8Vt8r7C+w5XQxoXwB3s2qnK0EnPepRZn3I532JC129laDVzbSRySyuaP1FGJvrOlsMhSP+edztf+t19Q2hTABbOiBhT+F+BShD96YRdvdlOd3mJlvLoWkPMgxAAJdteRrDegbn+XYeC4pKVgBEu3d0lt9YdYcQ01PicnufLw="

    # Decrypting encrypted key to get session key,
    # to be used in AES decryption
    decrypted_session_key_in_bytes = decrypt_using_private_key(
        enc_key_response)

    decrypted_payload = decrypt_payload_with_aes_cbc(
        decrypted_session_key_in_bytes, enc_data_response)

    return {"decrypted_session_key": decrypted_session_key_in_bytes.decode('utf-8'), "decrypted_payload": decrypted_payload[15:].decode('utf-8'), }


# Decrypt string using public key
def decrypt_using_private_key(value: str):

    # Importing private key
    rsa_key = RSA.importKey(open('secrets/bankly-private.pem').read())
    cipher = PKCS1_v1_5.new(rsa_key)
    sentinel = get_random_bytes(16)

    return cipher.decrypt(b64decode(value), sentinel)


def encrypt_using_public_key(bytes):
    rsa_key = RSA.importKey(open('secrets/icici.cer').read())
    cipher = PKCS1_v1_5.new(rsa_key)
    enc_key = cipher.encrypt(bytes)
    return enc_key


def encrypt_payload_with_aes_cbc(session_key_in_bytes, payload: str):
    cipher = AES.new(session_key_in_bytes, AES.MODE_CBC)
    cipher_bytes = cipher.encrypt(pad(b64decode(payload), AES.block_size))
    iv = b64encode(cipher.iv)
    cypher_text = b64encode(cipher_bytes)

    return {"encrypted_payload_txt": cypher_text, "iv": iv}


# Decription, following ICICI guidelines
def decrypt_payload_with_aes_cbc(session_key_in_bytes, payload: str):
    payload_in_bytes = b64decode(payload)

    # First 16 bytes is IV, from encryptedData
    IV = payload_in_bytes[:16]

    cipher = AES.new(session_key_in_bytes, AES.MODE_CBC, IV)
    return cipher.decrypt(payload_in_bytes)
