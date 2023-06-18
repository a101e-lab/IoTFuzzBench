import requests
from bs4 import BeautifulSoup
from http_parser.parser import HttpParser
import re


def login_message_analysis(payload):
    # Analyze the message to find the dynamically changing authentication string

    posis_list = []
    parser = HttpParser()
    parser.execute(payload, len(payload))
    if (parser.is_headers_complete()):
        headers_dict = parser.get_headers()
        headers_dict.pop('Cookie')
        headers_dict.pop('Content-Length')
        # Obtain the authentication request URL during the first login
        full_url = 'http://' + headers_dict['Host'] + parser.get_url()
        requests.get(full_url)

        resp = requests.get(full_url, headers=headers_dict)
        if resp.status_code == 200:
            data_1 = resp.text
            bs = BeautifulSoup(data_1, 'html.parser')
            http_item_1 = bs.find_all(string=re.compile('http'))
            if (http_item_1):
                url_case1 = http_item_1[0]
                pattern = re.compile(r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\(\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+')
                url_case1 = re.findall(pattern, url_case1)[0]
            else:
                # token in cookie
                headers_1 = resp.headers

        # time.sleep(3)

        # Obtain the authentication request URL during the second login
        full_url = 'http://' + headers_dict['Host'] + parser.get_url()
        resp = requests.get(full_url, headers=headers_dict)
        if resp.status_code == 200:
            data_2 = resp.text
            bs = BeautifulSoup(data_2, 'html.parser')
            http_item_2 = bs.find_all(string=re.compile('http'))
            if (http_item_2):
                url_case2 = http_item_2[0]
                pattern = re.compile(
                    r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\(\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+')
                url_case2 = re.findall(pattern, url_case2)[0]

        if (http_item_1 and http_item_2):
            # Compare the two authentication request URLs to obtain different positions in the URL
            if (len(url_case1) != 0 and len(url_case2) != 0):
                posi = 0
                for i in range(min(len(url_case1), len(url_case2))):
                    if (url_case1[i] != url_case2[i]):
                        posi = i
                        break
                if (posi != 0):
                    begin = url_case1[:posi].rfind('/')
                    end = url_case1.find('/', posi)
                    random_str = url_case1[begin + 1:end]

                    # Bug fixed. Prevent the length of the url from changing due to the change of host, resulting in inaccurate offset.
                    request_path = url_case1[len('http://' + headers_dict['Host']):]
                    path_random_begin = request_path.find(random_str)
                    path_random_end = path_random_begin + len(random_str)

                    posis_list = [path_random_begin, path_random_end, headers_dict, parser]
                    return True, ['TOKEN_URL', posis_list]
            else:
                return False, ['TOKEN_URL', posis_list]

            return False, ['TOKEN_URL', posis_list]
        else:
            # token in cookie
            if (parser.get_method() == 'POST'):
                data = payload[payload.find(b'\r\n\r\n') + 4:]
                resp = requests.post(full_url, headers=headers_dict, data=data, allow_redirects=False)
                res_headers = resp.headers

                # cookie = res_headers['Set-Cookie']

                post_payload = data
                posis_list = [post_payload, res_headers, headers_dict, parser]
                return True, ['TOKEN_COOKIE', posis_list]
    else:
        print(payload)
        print('Parse failed!')
        return False, ['TOKEN_URL', posis_list]
