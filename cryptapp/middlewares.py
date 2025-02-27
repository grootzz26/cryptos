import re
import json
import base64
import logging
from django.http import HttpResponse
from django.utils.deprecation import MiddlewareMixin

from . import aes
from apps.security import helper
import random

LOGGER = logging.getLogger("myplex_service.apps.security.middleware")

PAYLOAD_PARAM_NAME = "payload"
RESPONSE_PARAM_NAME = "response"

REQ_HEADER_NAME = "HTTP_X_MYPLEX_PLATFORM"

ROTATIONS = {
    1: "RL-4",
    2: "MID-8",
    3: "LR-4",
    4: "ALT-2",
    5: "ALT-1"
}
SALT = "YTNiYmJkZjUzMGQ4ZmVmOTU1NmViMGNlNmViYmI0MTI="
encryption_key = "ODk3ODcxYjQ2YTBkNDI3MTgzZDY0MmE3OTAyYmIxZTlmYWM4ZTFkZDNjMTA2YzQ0M2UzODQxMTI3MTg0MWE1Zg=="
VERSION = 1


def decrypt(encryption_key, payload):
    decrypted_payload = aes.decrypt(encryption_key, payload)
    return json.loads(decrypted_payload)


def encrypt(encryption_key, payload):
    return aes.encrypt(encryption_key, payload)

def is_valid_encryption_request(request_path):
    valid_end_point = []
    if request_path in valid_end_point:
        return True
    return False

def key_rotation_logic(request, lock_key):
    token = request.META.get("Authorization")
    my_list = [1, 2, 3, 4, 5]
    random_element = random.choice(my_list)


class HttpSecurityMiddleware(MiddlewareMixin):
    """
    Middleware that handles temporary messages.
    """

    def process_request(self, request):
        request_path = request.path.strip().lower()
        if is_valid_encryption_request(request_path):
            platform = helper.get_request_header(request)
            has_support = helper.is_platform_supports_encryption(platform)
            if platform and has_support:
                try:
                    encryption_key = helper.get_key(request, request_path, platform)
                except Exception as e:
                    LOGGER.exception(e)
                    return HttpResponse(result.to_json(), content_type='application/json', status=400)
                LOGGER.info(
                    "Middleware Execute for Platform %s, Request Path %s with Request Method %s, encryption key %s",
                    platform, request_path, request.method, encryption_key)
                payload, query_info = None, None
                if request.method == "GET":
                    payload = request.GET.get(PAYLOAD_PARAM_NAME, None)
                    request.GET = request.GET.copy()
                    query_info = request.GET
                elif request.method == "POST":
                    payload = request.POST.get(PAYLOAD_PARAM_NAME, None)
                    request.POST = request.POST.copy()
                    query_info = request.POST

                params_size = len(list(query_info.items()))
                LOGGER.info("QUERY INFO %s", str(list(query_info.items())))
                if request.method in ["POST", "GET"] and not (params_size <= 3 and params_size >= 2):
                    result = BadRequestResult()
                    LOGGER.info("Invalid Request with more than Two Parameters Platform %s IP %s", platform,
                                helper.get_client_ip(request))
                    return HttpResponse(result.to_json(), content_type='application/json', status=400)

                if not encryption_key:
                    LOGGER.info("Empty Encryption key %s IP %s", platform, helper.get_client_ip(request))

                if payload and encryption_key:
                    try:
                        request_payload = decrypt(encryption_key, payload)
                    except Exception as e:
                        LOGGER.exception(e)
                        result = BadRequestResult()
                        return HttpResponse(result.to_json(), content_type='application/json', status=400)
                    LOGGER.info("REQUEST PAYLOAD %s", str(request_payload))
                    if not request_payload:
                        result = BadRequestResult()
                        LOGGER.info("Unable to Decrypt Payload payload %s IP %s", platform,
                                    helper.get_client_ip(request))
                        return HttpResponse(result.to_json(), content_type='application/json', status=400)
                    query_info.pop(PAYLOAD_PARAM_NAME)
                    query_info.update(request_payload)
            else:
                LOGGER.info("Invalid Request Plaform %s IP %s", platform, helper.get_client_ip(request))
                result = BadRequestResult()
                return HttpResponse(result.to_json(), content_type='application/json', status=400)
        else:
            return None

    def process_response(self, request, response):
        request_path = helper.get_request_path(request)
        if helper.is_valid_encryption_request(request_path):
            if (response.status_code in range(200, 300)):
                platform = helper.get_request_header(request)
                encryption_key = helper.get_key(request, request_path, platform)
                response_data = dict()
                response_data[RESPONSE_PARAM_NAME] = encrypt(encryption_key, response.content.decode('utf-8'))
                response_data["version"] = VERSION
                response.content = json.dumps(response_data).encode('utf-8')
                LOGGER.info("Successfully Encrypted %s", helper.get_client_ip(request))
            else:
                LOGGER.info("Invalid Status Code. Not Decrypting IP %s", helper.get_client_ip(request))
        return response
