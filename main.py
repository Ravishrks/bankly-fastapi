import random
import string
from typing import Union
# import aiohttp

from fastapi import FastAPI
from base64 import b64decode, b64encode
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5, AES, PKCS1_OAEP
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad

import http3
import rsa
# import requests
import json


client = http3.AsyncClient()


app = FastAPI()

enc_key_response = "trkNAC1pBc1tLV19dypHpn1lkROrw+JMUHP62212ppWYcznd6lAl6rh5hk0+yQbfEz2IGQxVW/uC2XtQXzqc2IPgB3bZMSD80z+390BQot5nCdpnCEm6JnVHO0Mvliwhp88NgOm2saSgIAoY+p04slhou54n4z8rpK3193ZJIREVsN69k5U6XbR+KAYXI2OQ3GhaveFLXqK3aza//M4Ap1xAFQmIU6ScGtoaW62ZYr/WiPpZOG9CC6d6hzOqi34rqTnPdC4fF55JyMM0Sdqep4iAc0Fn/331jBzgXvJFeJ4i9oEZyuViMobHVdF8nFeNEWrh5ePFVJa1SfIhTNNykQ=="
enc_data_response = "oGd5snQd5CREWece9fiqPnisQwLZaLhzYFqyD7KeRzdjA17EHJL9maMDC3U01P+dC+d4Gki9qhLf1RM0VclUVrHiX+8kVVxVdZeWsTywj4+4FfLd8/GlSPZ7PbTbOs2jRlg8Vt8r7C+w5XQxoXwB3s2qnK0EnPepRZn3I532JC129laDVzbSRySyuaP1FGJvrOlsMhSP+edztf+t19Q2hTABbOiBhT+F+BShD96YRdvdlOd3mJlvLoWkPMgxAAJdteRrDegbn+XYeC4pKVgBEu3d0lt9YdYcQ01PicnufLw="


# Generating payload mets to send api request
api_test_key = 'xUHvlTOtkLn37jnuG0Yp8zr2kivgRg6j'
src_app = 'bankly'
ref_no = '20190704000084'
mer_id = 'FLP0000001'
mer_pass = 'admin12345'
product = 'VV01'
pro_cat = "1"
linkMobile = '9944838952'
tran_remark = 'FLIPKART Card Mobile Number link'
endpoint_url = 'https://apibankingonesandbox.icicibank.com/api/v1/pcms-chw?service=LinkedMobile'


@app.get("/")
def read_root():
    # decryptPayloadUsingPublicKey(enc_key_response)
    return {"Hello": "World"}

# Complete implementation of encryption and decription


@app.get("/send-test-request")
async def send_test_request():
    # Decrypting encrypted key to get session key,
    # to be used in AES decryption

    random_16_string = ''.join(random.choice(
        string.ascii_uppercase + string.digits) for _ in range(16))
    encrypted_session_key_in_bytes = encrypt_using_public_key(random_16_string)

    payload_data_to_be_encrypted = f'<xml><ReferenceNumber>{ref_no}</ReferenceNumber><MerchantId>{mer_id}</MerchantId><MerchantPassword>{mer_pass}</MerchantPassword><Product>{product}</Product><ProductCategory>{pro_cat}</ProductCategory><MobileNumber>{linkMobile}</MobileNumber><TransactionRemark>{tran_remark}</TransactionRemark></xml>'

    encrypted_payload_aes_cbc_json = encrypt_payload_with_aes_cbc(
        random_16_string.encode(), payload_data_to_be_encrypted)

    encrypted_data = encrypted_payload_aes_cbc_json['encrypted_payload_txt']
    iv = encrypted_payload_aes_cbc_json['iv']

    request_data = {
        "requestId": "",
        "service": "",
        "encryptedKey": "jXwyhjY7tMmQuxFQCBq6lHTUbW4OjD01G88mAZEtfqXi2L8NDnFWIO44bcx2b7OEO14YPlBtn8MqpgsZNNCoZ+/jru8BuPOfF0aSFx060qNA8dDXaQ6sVtyV2xiT3/WrKy3m5kQAVmygy7PqIeV/rSOA4rH0SNNZuz996DEj3yub9YW327Af1Rh5nysADKJSiBdZpbCFAYaALEnU+sG/Y67bp60lEd27ek84f1cdb+EzwWcv78ISBSefmZ5QfSsLUAYzNE6BEX2Bps7pIXjdrD3L+4+Rl8WNCCUPZFtPYKK5KnvO/wICfN7Qo3/h1IHr6Ni77KUilFogV2YZMeL0xAppvgXlK7A0Cz8rnLv1JE/Ha7nvHxCf8kGQKuSBUnGiufLj0yLFR+3us58NzeX6s7iMByHfRMRcRDzmWcGel85cfwhUSzaBfJVsguohmNKqNgpphaR5s4FoHtRTzHEP83dAFR6edmtQ70d3Au6areI5XPi7aJJ7gttDnuciRXmzmpB4heWmlqd1wxAg+bsGyHRMGt2bGNBFQUYyGOJPkWCM8Zl+LTASFqpoyrlly5JnPIN5IMjzf9WNXm8L3wjQMt5KRRmFl5NGJUsDMGOWQRfiszDxBUtpmimfuo/CVddOu0htChvh5CU1L/8EFkWDZZrt2VWR/taA9ja4X0/wOUw=",
        "oaepHashingAlgorithm": "NONE",
        "iv": "",
        "encryptedData": "OTY3OTI4N2MyMjc0ODQ1ONHs9UlFeXlM6wOKEsTYfn0DAsm9Z7KIl2fqgoZyXgLDQVTQ00fIUmTBw1T27DxGBnSF2Z/hq6wF+d+TeH6XOKLl9uCuvo8C9/aHBP0eDT5xf8ohFYSaZzfmPVr+sGZ/tjuhrnu8mSqbK90RCbuYRj2EjBFbhnB21VmXgYYHAQIt0Oqhp/F3yCyLlRvv7PvfHSy5LruVCjrbLK2W1IxdGDa+b+cq1A5u3tfz96orVtZpQnz55ZTh8MXoT4q8bHPA4W6g7924oCzxIVxRH/yY2x7RWrxwLwWDc3/QgQfT21xo7yq00j2soR95OjhIIsDz2ZzY2JyymOo+ckldMxX0JDHP56opVI+GTvO2fgIxG8p+tMD3A2yyq350/os+lJtmc8LzihhkzVfrFCFvUvMoK5qw/8uFb9Q7auZTdT65PKMF",
        "clientInfo": "",
        "optionalParam": ""
    }

    headers = {'Content-Type': 'application/json',
               'apikey': 'xUHvlTOtkLn37jnuG0Yp8zr2kivgRg6j', 'SrcApp': 'bankly', 'Accept': 'application/json'}

    # r = await client.post(endpoint_url, data=request_data, headers=headers)
    r = await client.post('https://apibankingonesandbox.icicibank.com/api/v1/pcms-chw?service=LinkedMobile', data=json.dumps(request_data), headers=headers)

    print(r.status_code)
    print(r.text)
    print(r.json())

    return {"Hello": "World"}


@app.get("/encrypt-test")
def encrypt_test():
    # Decrypting encrypted key to get session key,
    # to be used in AES decryption
    random_16_string = ''.join(random.choice(
        string.ascii_uppercase + string.digits) for _ in range(16))
    encrypted_session_key_in_bytes = encrypt_using_public_key(random_16_string)

    payload_data_to_be_encrypted = f'<xml><ReferenceNumber>{ref_no}</ReferenceNumber><MerchantId>{mer_id}</MerchantId><MerchantPassword>{mer_pass}</MerchantPassword><Product>{product}</Product><ProductCategory>{pro_cat}</ProductCategory><MobileNumber>{linkMobile}</MobileNumber><TransactionRemark>{tran_remark}</TransactionRemark></xml>'

    encrypted_payload_aes_cbc_json = encrypt_payload_with_aes_cbc(
        random_16_string.encode(), payload_data_to_be_encrypted)

    encrypted_data = encrypted_payload_aes_cbc_json['encrypted_payload_txt']
    iv = encrypted_payload_aes_cbc_json['iv']

    # Send api request to ICICI server

    return {"IV": iv, "encData": encrypted_data, "encKey": b64encode(encrypted_session_key_in_bytes)}


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


def encrypt_using_public_key(value: str):
    rsa_public_key = RSA.importKey(open('secrets/icici.cer').read())
    return rsa.encrypt(value.encode(), rsa_public_key)


def encrypt_payload_with_aes_cbc(session_key_in_bytes, payload: str):
    cipher = AES.new(session_key_in_bytes, AES.MODE_CBC)
    cipher_bytes = cipher.encrypt(pad(payload.encode(), AES.block_size))
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
