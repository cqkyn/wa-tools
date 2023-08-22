'''
requirements:
    pycryptodome
    gunicorn -w 4 -b 0.0.0.0:7729 main:app
'''

import json
import base64
from hashlib import pbkdf2_hmac

from Crypto.Cipher import AES
from flask import Flask, jsonify, request

app = Flask(__name__)

TOKEN_RAW = [
    0x41, 0x04, 0x1d, 0x40, 0x11, 0x18, 0x56, 0x91, 0x02, 0x90,
    0x88, 0x9f, 0x9e, 0x54, 0x28, 0x33, 0x7b, 0x3b, 0x45, 0x53
]
# 0x39, 0x31, 0x39, 0x33, 0x34, 0x38, 0x30, 0x37, 0x37, 0x36, 0x31, 0x35,0x20,

# 0xf3, 0xed, 0xf1, 0x0d, 0xec, 0xc4, 0x3d, 0x1f, 0x1c, 0x2e,
# 0x87, 0xa7, 0x64, 0x87, 0xea, 0x18, 0x55, 0x2c, 0x91, 0x95

# 0x41, 0x04, 0x1d, 0x40, 0x11, 0x18, 0x56, 0x91, 0x02, 0x90,
# 0x88, 0x9f, 0x9e, 0x54, 0x28, 0x33, 0x7b, 0x3b, 0x45, 0x53
TOKEN = bytes(map(lambda x: x ^ 0x12, TOKEN_RAW))


def base64_decode(text):
    return base64.b64decode(text + '==')


def decrypt(password, iv, salt, ciphertext):
    password_ = TOKEN + password
    password_ = ''.join(map(chr, password_)).encode()  # b'\x83' => b'\xc2\x83'
    key = pbkdf2_hmac('sha1', password_, salt, 16, 16)
    return AES.new(key, AES.MODE_OFB, iv).decrypt(ciphertext)


def decrypt_keypair(keypair_pwd_enc):
    json_text = keypair_pwd_enc.replace('&quot;', '"').replace('\/', '/')
    json_data = json.loads(json_text)
    version, ciphertext, iv, salt, password = json_data

    assert version == 2
    ciphertext = base64_decode(ciphertext)
    iv = base64_decode(iv)
    salt = base64_decode(salt)
    password = password.encode()

    result = decrypt(password, iv, salt, ciphertext)
    # print(len(result))
    if len(result) == 64:
        private = base64.b64encode(result[:32]).decode()
        public = base64.b64encode(result[-32:]).decode()
    else:
        public = "error"
        private = "error"

    data = {
        'public': public,
        'private': private
    }

    return jsonify(data)


def test():
    client_static_keypair_pwd_enc = '[2,&quot;f4LO5goAJ2NPUKFDcHOYPO\/W6XQPoh9Lz\/QV5CSfE+A9cSGH+r2LYzCPWtDIMyf0Dmk0tbeDx7HHSLWq6s1m1w&quot;,&quot;diMgk8FaeYgT9mfBrWdcBw&quot;,&quot;pxvfQA&quot;,&quot;kVgiI9X7UyuVRlJDtN+tWQ&quot;]'
    result = decrypt_keypair(client_static_keypair_pwd_enc)
    print('client_static_keypair:\n' + result)


@app.route('/api', methods=['POST'])
def api():
    # [2,&quot;H\/I4EAJayHzUKW2BA7zoy5XQfNYcWFYggvROPBnITG+xVITvkMwyPzh5fKNCJR5LOVOWK3kvZdb6CtI6eUMfpg&quot;,&quot;egOzoOkhi4rqAIRf0bZ69Q&quot;,&quot;9L2MKw&quot;,&quot;+WRrrImJhKJk8eVChuLO7w&quot;]
    # 16723689753,
    # LRp/H6pTGoeoBFWJvl6PgGkIOA/0bQIIxg6Fsh7+yAc=,
    # GOW/s4YYvJdo32OwFpYP4JBrUmLL32ECneR7rvzPyU0=,
    # S1cMBXSU591ENbRkKqOzroQ+M/ReNhLTEur2eUPyaAo=,
    # eISIaqBpv6emxARH3+0YYy1ywrrNUHEzQ2D4Sk3NC30=,ODVhNDJkMGUtZWUzNC00MGJhLWE=
    base64_param = request.form.get('base64')
    if base64_param:
        try:
           # decoded_data = base64.b64decode(base64_param)
           # client_static_keypair_pwd_enc = decoded_data.decode('utf-8')
            result = decrypt_keypair( base64_param )
            return result
        except Exception:
            return 'Error occurred while processing base64 data'
    else:
        return 'Missing base64 parameter'


if __name__ == '__main__':
    app.run(host='0.0.0.0')

