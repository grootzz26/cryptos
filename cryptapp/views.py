from django.shortcuts import render
from rest_framework.decorators import api_view

from .aes import *
import json
from django.http.response import JsonResponse
from rest_framework.decorators import api_view

# Create your views here.
# encryption_key = "ab5c2975cc1d0c0e"
encryption_key = "ab5c10da63470c0e"
# encryption_key = "ab5c2975cc1d0c0e4531107ca0a349c10da63471e5c9e175b85d20b7c089fb11"
# encryption_key = "4eca7a168aa5d6401e588e00c0b288e8"

class KeyRotation:
    salt = "4eca7a168aa5d6401e588e00c0b288e8"
    main_key = "ab5c2975cc1d0c0e4531107ca0a349c10da63471e5c9e175b85d20b7c089fb11"

    @classmethod
    def code1(cls):
        pass

    @classmethod
    def code2(cls):
        pass

    @classmethod
    def code3(cls):
        pass

    @classmethod
    def code4(cls):
        pass

    @classmethod
    def execute(cls, request):
        code = request.GET.get("code")
        method_name = "code" + code
        enc_key = getattr(cls, method_name)()
        return enc_key


@api_view(["GET", "POST"])
def encode(request):
    enc_key = KeyRotation.execute(request)
    response = json.dumps(request.data).encode("utf-8")
    encoded_response = dict(result=encrypt(encryption_key, response))
    return JsonResponse(encoded_response)

@api_view(["GET"])
def decode(request):
    payload = request.GET.get("token")
    decrypted_payload = decrypt(encryption_key, payload)
    return JsonResponse(json.loads(decrypted_payload))