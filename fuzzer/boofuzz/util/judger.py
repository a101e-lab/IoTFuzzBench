import json
import xml.etree.ElementTree as ET
from http_parser.parser import HttpParser
from urllib.parse import urlparse, parse_qs


def parameters_type_judge(parameters_ori_string):
    try:
        # XML parse
        type = ''
        count = 0
        myroot = ET.fromstring(parameters_ori_string)
        for item in myroot.iter():
            count = count + 1
        if (count != 0):
            type = 'xml'
        else:
            type = 'unknown'
        return type
    except:
        # JSON parse
        try:
            type = ''
            count = 0
            json_dict = json.loads(parameters_ori_string)
            for item in json_dict:
                count = count + 1
            if (count != 0):
                type = 'json'
            else:
                type = 'unknown'
            return type
        except:
            # POST normal parse
            try:
                type = ''
                count = 0
                parameters = parse_qs(parameters_ori_string)
                for parameter in parameters:
                    count = count + 1
                if (count != 0):
                    type = 'post_normal'
                else:
                    type = 'unknown'
                return type
            except:
                type = 'unknown'
                return type


def login_required_judge(payload):
    # Determine whether the message is a login message

    # payload = payload.decode()
    # payload = payload.lower()
    parser = HttpParser()
    parser.execute(payload, len(payload))
    method = parser.get_method()
    if (parser.is_headers_complete()):
        if (method == 'POST' and
                'login' in parser.get_url().lower() and
                ('text/html' in parser.get_headers()['Accept'].lower() or '*/*' in parser.get_headers()[
                    'Accept'].lower())):
            return True
        else:
            return False
    else:
        return False


def creat_judge(payload):
    # Determine whether the request needs to be fuzzed

    request_method = ''

    if (payload[:4] == b'POST'):
        request_method = 'POST'
        parameters_ori_string = payload[payload.find(b'\r\n\r\n') + 4:]

        parameters_ori_string = parameters_ori_string.decode('utf-8')
        parameters = parse_qs(parameters_ori_string)
        if (parameters and b'login' not in payload):
            return True, 'POST'

    elif (payload[:3] == b'GET'):
        parser = HttpParser()
        parser.execute(payload, len(payload))
        if (not parser.is_headers_complete()):
            return False, request_method
        url = parser.get_url()
        path = parser.get_path()
        parameters_ori_string = url[len(path) + 1:]
        if (len(parameters_ori_string) != 0):
            try:
                parameters = parse_qs(parameters_ori_string)
                if (len(parameters) >= 2):
                    return True, 'GET'
                else:
                    return False, 'GET'
            except:
                print(b'[X] parse Error!: ' + parameters_ori_string)
                return False, 'GET'

    return False, request_method
