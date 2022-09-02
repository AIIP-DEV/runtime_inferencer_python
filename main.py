import datetime as dt
import base64
import json

import requests
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Hash import SHA256, SHA1
from Crypto.Signature import pss


class AIRuntime:
    PEM_FORMAT = "-----BEGIN PUBLIC KEY-----\n{0}\n-----END PUBLIC KEY-----\n"

    def __init__(self, access_key_id, access_key, model_id):
        self._baseEndpoint = "https://aiip.skcc.com"
        self._tokenValidMinutes = 10
        self._access_key_id = access_key_id
        self._access_key = access_key
        self._model_Id = model_id
        self._rsa_key = self.extract_rsa_key()
        self._token = self.get_token()

    def extract_rsa_key(self):
        pem_data = self.PEM_FORMAT.format(self._access_key)
        rsa_key = RSA.importKey(pem_data)
        return rsa_key

    def get_endpoint(self):
        return self._baseEndpoint + "/api/runtime/ifservice/predict"

    def get_token(self):
        _msg = str(int(dt.datetime.now().timestamp() - 1))
        _cipher = PKCS1_OAEP.new(key=self._rsa_key, hashAlgo=SHA256, mgfunc=lambda x, y: pss.MGF1(x, y, SHA1))
        _enc_str = _cipher.encrypt(str.encode(_msg))
        _b64_encoded_str = base64.b64encode(_enc_str)

        _headers = dict()
        _headers["Content-Type"] = "application/json"
        _payload = dict()
        _payload["keyId"] = self._access_key_id
        _payload["encMessage"] = bytes.decode(_b64_encoded_str)
        _payload["duration"] = self._tokenValidMinutes
        url = "https://aiip.skcc.com/api/common/backend/admin/api/keyauth"
        res = requests.post(url, headers=_headers, json=_payload)
        if res.status_code == 200:
            token = res.content.decode("utf-8")
            return token
        else:
            print("Error: ", str(res.content.decode("utf-8")))

    def predict(self, model_id, data):

        json_data = json.loads(ai_runtime.get_token())
        token = json_data['result']

        return self.predict_exec(model_id, data, token)

    def predict_exec(self, model_id, data, token):
        _headers = dict()
        _headers["Content-Type"] = "application/json"
        _headers["Api-Auth-Token"] = token
        _payload = data
        _url = self.get_endpoint() + "/" + model_id
        _res = requests.post(_url, headers=_headers, json=_payload)

        if _res.status_code == 200:
            _result = str(_res.content.decode("utf-8"))
            return _result
        else:
            print("Error: ", str(_res.content.decode("utf-8")))


# apiKeyId = "{input your apiKeyId}"
# apiKey = "{input your apiKey}"
# modelId = "{input your modelId}"

# example
apiKeyId = "ED23A3B575C2"
apiKey = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAnYpPCa3MwqLj55DSrxCswp3rUgcMTuKFMCc76YtMjHB7h44r330had" \
         "lHehCqIp9uUKGjg6f4u0pUTinK8CCB75/lrC94PPV0AgFHog3EX0BRfvI1GovIdhaJzJvqsAB9VKMRa9YJUbmNXfDddKfcFLu8" \
         "7xgtVsF9linxeihchbUicFgOS3wOP26OyrHTXybYYLp5KjkegvFzF9LmI4ZBkyoNVJcr2Mm6lxqqEnOPdIawuPTToetzxEDJE9" \
         "RrOmE5LPmJcgWIkMOC+v/ptZnnx/YkXj236e6NNGk+DeK1/i5gojpZ1x5IXiyaWhKb5uwgY1cXSBCdTENnl9ONqhh33QIDAQAB"

modelId = "mdl-58aa2b86-d268-4c2b-889c-6eac2472abf5"

data = {
    "instances": [
        [5.1, 3.5, 1.4, 0.2, ""],
        [4.6, 3.1, 1.5, 0.2, ""]
    ],
    "labels": ["sepal_length", "sepal_width", "petal_length", "petal_width", "variety"]
}

try:
    ai_runtime: AIRuntime = AIRuntime(access_key_id=apiKeyId, access_key=apiKey, model_id=modelId)

    predict_result = ai_runtime.predict(modelId, data)
    print(predict_result)

except Exception as e:
    print(e)
