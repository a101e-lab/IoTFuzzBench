from util.judger import *
from scapy.all import *
from http_parser.parser import HttpParser
from urllib.parse import parse_qs
import hashlib
import xml.etree.ElementTree as ET
from util.pcap_filter import *
from util.analyst import *


def parser_get_ori_headers_list(parser, if_set_cookie=False):
    # Loop combination of original headers and to list

    headers_dict = parser.get_headers()
    ori_headers = []
    for item in headers_dict:
        # Bug Fixed. Specifying the Content-Length incorrectly will cause the request message
        # to be truncated incorrectly, failing to achieve the expected effect
        if (item == 'Content-Length'):
            continue
        if (item == 'Cookie' and if_set_cookie == True):
            ori_headers.append(item)
            ori_headers.append(': ')
            ori_headers.append('set_dynamic_cookie')
            ori_headers.append('\\r\\n')
        else:
            ori_headers.append(item)
            ori_headers.append(': ')
            ori_headers.append(headers_dict[item])
            ori_headers.append('\\r\\n')
    return ori_headers


def post_normal_build_factory(build_utils, parameters_ori_string):
    s_static_string_front,s_static_string_param, s_static_string_tail, s_string_front, s_string_param, s_string_tail = build_utils
    count = 0
    parameters_template = ''

    parameters = parse_qs(parameters_ori_string)
    for parameter in parameters:
        if (count == 0):
            parameter_name_line = s_static_string_front + parameter + '=' + s_static_string_tail + '\n'
            # Bug fixed. Fix the bug that unexpected \r\n appears in the parameter
            # parameter_value_fuzz_single_line = \
            #     s_string_front + \
            #     parameters[parameter][0].replace(b'\r', b'\\r').replace(b'\n', b'\\n').decode('utf-8') + \
            #     s_string_param + \
            #     parameter.decode('utf-8') + \
            #     s_string_tail + '\n'
            parameter_value_fuzz_single_line = \
                s_string_front + \
                parameters[parameter][0].replace('\r', '\\r').replace('\n', '\\n') + \
                s_string_param + \
                parameter + \
                s_string_tail + '\n'

            # parameter_value_fuzz_single_line = \
            #     s_from_file_string_front + \
            #     parameters[parameter][0].decode('utf-8') + \
            #     s_from_file_string_param + \
            #     parameter.decode('utf-8') + \
            #     s_from_file_string_tail
        else:
            parameter_name_line = s_static_string_front + '&' + parameter + '=' + s_static_string_tail + '\n'

            # Bug fixed. Fix the bug that unexpected \r\n appears in the parameter
            # parameter_value_fuzz_single_line = \
            #     s_string_front + \
            #     parameters[parameter][0].replace(b'\r', b'\\r').replace(b'\n', b'\\n').decode('utf-8') + \
            #     s_string_param + \
            #     parameter.decode('utf-8') + \
            #     s_string_tail + '\n'
            parameter_value_fuzz_single_line = \
                s_string_front + \
                parameters[parameter][0].replace('\r', '\\r').replace('\n', '\\n') + \
                s_string_param + \
                parameter + \
                s_string_tail + '\n'

            # parameter_value_fuzz_single_line = \
            #     s_from_file_string_front + \
            #     parameters[parameter][0].decode('utf-8') + \
            #     s_from_file_string_param + \
            #     parameter.decode('utf-8') + \
            #     s_from_file_string_tail
        parameters_template = parameters_template + parameter_name_line + parameter_value_fuzz_single_line
        count = count + 1
    return parameters_template


def unknown_build_factory(build_utils, parameters_ori_string):
    s_static_string_front, s_static_string_param, s_static_string_tail, s_string_front, s_string_param, s_string_tail = build_utils

    parameters_template = s_static_string_front + parameters_ori_string + s_static_string_tail + '\n'
    return parameters_template


def xml_build_factory(build_utils, parameters_ori_string):
    s_static_string_front, s_static_string_param, s_static_string_tail, s_string_front, s_string_param, s_string_tail = build_utils

    parameters_template = ''
    myroot = ET.fromstring(parameters_ori_string)
    print(parameters_ori_string)
    fuzz_param_list = []
    for item in myroot.iter():
        temp_count = 0
        for child in item:
            temp_count = temp_count + 1
            break
        if (temp_count == 0 and item.text != None):
            key = item.tag.split('}')[1]
            single_item = [key, item.text]
            fuzz_param_list.append(single_item)

    # Pretty print xml
    import xml.dom.minidom
    dom = xml.dom.minidom.parseString(parameters_ori_string)
    pretty_xml_as_string = dom.toprettyxml()
    parameters_ori_string = pretty_xml_as_string

    for fuzz_item in fuzz_param_list:
        fuzz_key, fuzz_param = fuzz_item
        posi = 0
        while (len(parameters_ori_string) != 0):

            posi = parameters_ori_string.find(fuzz_param, posi, )

            line_begin = parameters_ori_string.rfind('\n', 0, posi)
            line_end = parameters_ori_string.find('\n', posi, )
            single_line_string = parameters_ori_string[line_begin + 1:line_end]

            if (fuzz_key in single_line_string and fuzz_param in single_line_string):
                temp_front_string = parameters_ori_string[:posi]
                temp_tail_string = parameters_ori_string[posi + len(fuzz_param):]
                parameters_ori_string = temp_tail_string

                temp_front_string = temp_front_string.replace('\t', '')
                temp_front_string = temp_front_string.replace('\n', '')

                parameter_front_line = s_static_string_front + temp_front_string + s_static_string_tail + '\n'
                parameters_template = parameters_template + parameter_front_line

                parameter_value_fuzz_single_line = \
                    s_string_front + \
                    fuzz_param + \
                    s_string_param + \
                    fuzz_key + \
                    s_string_tail + '\n'
                parameters_template = parameters_template + parameter_value_fuzz_single_line
                print(parameters_template)
                break
            else:
                posi = posi + 1
                continue

    if (len(parameters_ori_string) != 0):
        parameters_ori_string = parameters_ori_string.replace('\t', '')
        parameters_ori_string = parameters_ori_string.replace('\n', '')

        parameter_front_line = s_static_string_front + parameters_ori_string + s_static_string_tail + '\n'
        parameters_template = parameters_template + parameter_front_line
        print(parameters_template)

    return parameters_template


def parameters_build(parameters_ori_string,fuzz_policy = 'pdfuzzergen'):
    s_static_string_front = '        s_static(\''
    s_static_string_param = ''
    s_static_string_tail = '\')'

    s_string_front = '        s_string(\''
    s_string_param = '\',fuzzable=True, max_len=1000000,name=\''
    s_string_tail = '\')'

    if(fuzz_policy == 'pdfuzzergen'):
        build_utils = [s_static_string_front, s_static_string_param ,s_static_string_tail, s_string_front, s_string_param, s_string_tail]
    elif(fuzz_policy == 'boo_reversal'):
        build_utils = [s_string_front, s_string_param, s_string_tail,s_static_string_front, s_static_string_param ,s_static_string_tail]
    else:
        # 默认采用 pdfuzzergen 策略，优先 fuzz 参数
        build_utils = [s_static_string_front, s_static_string_param, s_static_string_tail, s_string_front,
                       s_string_param, s_string_tail]

    # Bug fixed. Handle abnormal post requests generated by fuzz
    # try:
    #     parameters_type = parameters_type_judge(parameters_ori_string)
    #
    #     parameters = parse_qs(parameters_ori_string)
    # except:
    #     print(b'[X] parse Error!: ' + parameters_ori_string)
    #     return -1

    parameters_template = ''
    parameters_type = parameters_type_judge(parameters_ori_string)
    if (parameters_type == 'xml'):
        parameters_template = xml_build_factory(build_utils, parameters_ori_string)
    elif (parameters_type == 'json'):
        parameters_template = unknown_build_factory(build_utils, parameters_ori_string)
    elif (parameters_type == 'post_normal'):
        parameters_template = post_normal_build_factory(build_utils, parameters_ori_string)
    elif (parameters_type == 'unknown'):
        parameters_template = unknown_build_factory(build_utils, parameters_ori_string)
    else:
        parameters_template = unknown_build_factory(build_utils, parameters_ori_string)

    return parameters_template


# 构建fuzz模板的POST头
def http_header_build(payload, if_analysis_success=False, analysis_result=[],fuzz_policy = 'pdfuzzergen'):
    parser = HttpParser()
    parser.execute(payload, len(payload))

    s_static_string_front = '        s_static(\''
    s_static_string_tail = '\')'

    s_string_front = '        s_string(\''
    s_string_param = '\',fuzzable=True, max_len=1000000,name=\''
    s_string_tail = '\')'

    s_bytes_front = '        s_bytes(\''
    s_bytes_param = '\',fuzzable=True, max_len=1000000,name=\''
    s_bytes_tail = '\')'

    s_from_file_string_front = '        s_from_file(\''
    s_from_file_string_param = '\', filename=\'increasing_length.txt\', fuzzable=True, name=\''
    s_from_file_string_tail = '\')'

    request_method = ''

    if (if_analysis_success):
        request_method, param = analysis_result
        if (request_method == 'TOKEN_URL'):
            path_dynamic_begin, path_dynamic_end, headers_dict, login_parser = param
        elif (request_method == 'TOKEN_COOKIE'):
            post_payload, res_headers, headers_dict, login_parser = param

        # path_dynamic_begin, path_dynamic_end, headers_dict, login_parser = analysis_result

    if (payload[:4] == b'POST'):
        http_version_string = ' HTTP/1.1\\r\\n'
        header_template = ''

        if (request_method == 'TOKEN_URL'):
            # Set fuzz rules for dynamically changing fields in the URL
            header_queue = [parser.get_method(), ' ', parser.get_url()[:path_dynamic_begin]]
            for i in header_queue:
                single_line = s_static_string_front + i + s_static_string_tail + '\n'
                header_template = header_template + single_line

            dynamic_str_template = '        s_string("", size=-1, fuzzable=False, name="ping_dynamic_url")\n'
            header_template = header_template + dynamic_str_template

            header_queue = [parser.get_url()[path_dynamic_end:], http_version_string]
            for i in header_queue:
                single_line = s_static_string_front + i + s_static_string_tail + '\n'
                header_template = header_template + single_line
        elif (request_method == 'TOKEN_COOKIE'):
            # Set default fuzz rules in URL
            header_queue = [parser.get_method(), ' ', parser.get_url(), http_version_string]
            if_set_cookie = True
            header_queue = header_queue + parser_get_ori_headers_list(parser, if_set_cookie)

            for i in header_queue:
                if (i == 'set_dynamic_cookie'):
                    dynamic_str_template = '        s_string("", size=-1, fuzzable=False, name="set_dynamic_cookie")\n'
                    header_template = header_template + dynamic_str_template
                else:
                    single_line = s_static_string_front + i + s_static_string_tail + '\n'
                    header_template = header_template + single_line
        else:
            # Set default fuzz rules in URL
            header_queue = [parser.get_method(), ' ', parser.get_url(), http_version_string]
            header_queue = header_queue + parser_get_ori_headers_list(parser)

            for i in header_queue:
                single_line = s_static_string_front + i + s_static_string_tail + '\n'
                header_template = header_template + single_line

        header_queue = [parser.get_method(), ' ', parser.get_url(), http_version_string]
        header_queue = header_queue + parser_get_ori_headers_list(parser)

        # for i in header_queue:
        #     single_line = s_static_string_front + i + s_static_string_tail + '\n'
        #     header_template = header_template + single_line

        header_template = header_template + s_static_string_front + '\\r\\n' + s_static_string_tail + '\n'
        if(payload.find(b'\r')==-1):
            payload = payload.replace(b'\n',b'\r\n')
        parameters_ori_string = payload[payload.find(b'\r\n\r\n') + 4:]
        # header_template = header_template + parameters_build(parameters_ori_string)

        if(fuzz_policy == 'pdfuzzergen'):
            header_template = header_template + parameters_build(parameters_ori_string.decode('utf-8'))
        elif(fuzz_policy == 'boo_default'):
            single_line = s_string_front + parameters_ori_string.decode('utf-8') +s_string_param + s_string_tail + '\n'
            header_template = header_template + single_line
        elif(fuzz_policy == 'boo_byte'):
            single_line = s_bytes_front + parameters_ori_string.decode('utf-8') + s_bytes_param + s_bytes_tail + '\n'
            header_template = header_template + single_line
        elif (fuzz_policy == 'boo_reversal'):
            header_template = header_template + parameters_build(parameters_ori_string.decode('utf-8'),fuzz_policy)
        else:
            # default pdfuzzergen policy
            print('default')
            header_template = header_template + parameters_build(parameters_ori_string.decode('utf-8'))

        return header_template

    elif (payload[:3] == b'GET'):

        http_version_string = ' HTTP/1.1\\r\\n'
        header_template = ''

        # 'http://'+parser.get_headers()['Host']+parser.get_path()
        # path_dynamic_begin
        # aaa = parser.get_path()[path_dynamic_begin:path_dynamic_end]

        if (request_method == 'TOKEN_URL'):
            # Set fuzz rules for dynamically changing fields in the URL
            header_queue = [parser.get_method(), ' ', parser.get_path()[:path_dynamic_begin]]
            for i in header_queue:
                single_line = s_static_string_front + i + s_static_string_tail + '\n'
                header_template = header_template + single_line

            dynamic_str_template = '        s_string("", size=-1, fuzzable=False, name="ping_dynamic_url")\n'
            header_template = header_template + dynamic_str_template

            header_queue = [parser.get_path()[path_dynamic_end:], '?']
            for i in header_queue:
                single_line = s_static_string_front + i + s_static_string_tail + '\n'
                header_template = header_template + single_line
        elif (request_method == 'TOKEN_COOKIE'):
            # Set default fuzz rules in URL
            header_queue = [parser.get_method(), ' ', parser.get_url(), http_version_string]
            if_set_cookie = True
            header_queue = header_queue + parser_get_ori_headers_list(parser, if_set_cookie)

            for i in header_queue:
                if (i == 'set_dynamic_cookie'):
                    dynamic_str_template = '        s_string("", size=-1, fuzzable=False, name="set_dynamic_cookie")\n'
                    header_template = header_template + dynamic_str_template
                else:
                    single_line = s_static_string_front + i + s_static_string_tail + '\n'
                    header_template = header_template + single_line
        else:
            # Set default fuzz rules in URL
            header_queue = [parser.get_method(), ' ', parser.get_path(), '?']
            for i in header_queue:
                single_line = s_static_string_front + i + s_static_string_tail + '\n'
                header_template = header_template + single_line

        url = parser.get_url()
        path = parser.get_path()

        parameters_ori_string = url[len(path) + 1:]
        if (type(parameters_ori_string) == str):
            parameters_ori_string = parameters_ori_string.encode()

        if(fuzz_policy == 'pdfuzzergen'):
            header_template = header_template + parameters_build(parameters_ori_string.decode('utf-8'))
        elif(fuzz_policy == 'boo_default'):
            single_line = s_string_front + parameters_ori_string.decode('utf-8') +s_string_param + s_string_tail + '\n'
            header_template = header_template + single_line
        elif(fuzz_policy == 'boo_byte'):
            single_line = s_bytes_front + parameters_ori_string.decode('utf-8') + s_bytes_param + s_bytes_tail + '\n'
            header_template = header_template + single_line
        elif (fuzz_policy == 'boo_reversal'):
            header_template = header_template + parameters_build(parameters_ori_string.decode('utf-8'),fuzz_policy)
        else:
            # default pdfuzzergen policy
            print('default')
            header_template = header_template + parameters_build(parameters_ori_string.decode('utf-8'))


        header_queue = [http_version_string]
        header_queue = header_queue + parser_get_ori_headers_list(parser)
        for i in header_queue:
            single_line = s_static_string_front + i + s_static_string_tail + '\n'
            header_template = header_template + single_line

        header_template = header_template + s_static_string_front + '\\r\\n' + s_static_string_tail + '\n'
        # parameters_ori_string = payload[payload.find(b'\r\n\r\n') + 4:]
        return header_template


def callback_get_auth_token_func_build(payload, analysis_result):
    # Build the callback_get_auth_token function
    request_method, param = analysis_result
    if (request_method == 'TOKEN_URL'):
        begin, end, headers_dict, login_parser = param
        get_auth_token_func_template = ''

        # 1. Build get_auth_token_func header
        get_auth_token_func_header = """
    def callback_get_auth_token(target, fuzz_data_logger, session, *args, **kwargs):
        # Get authenticated token from login response

        fuzz_data_logger.log_check('[*] sending  login requests')
        try:

            headers = {\n"""
        get_auth_token_func_template = get_auth_token_func_template + get_auth_token_func_header

        # 2. Build get_auth_token_func parameter
        parameter_header = '               "'
        parameter_middler = '": "'
        parameter_tailer = '",\n'

        for i in headers_dict:
            single_key = i
            single_value = headers_dict[i]
            single_parameter = parameter_header + single_key + parameter_middler + single_value + parameter_tailer
            get_auth_token_func_template = get_auth_token_func_template + single_parameter

        get_auth_token_func_template = get_auth_token_func_template + '}\n'

        # 3. Build get_auth_token_func request

        login_url = 'http://' + headers_dict['Host'] + login_parser.get_url()

        request_template = """        resp = requests.get('""" + login_url + """',headers=headers)\n"""
        get_auth_token_func_template = get_auth_token_func_template + request_template

        # 4. Build get_auth_token_func tailer and position of dynamic string
        request_dynamic_posi_begin = len('http://' + headers_dict['Host']) + begin
        request_dynamic_posi_end = len('http://' + headers_dict['Host']) + end
        dynamic_posi_str = str(request_dynamic_posi_begin) + ':' + str(request_dynamic_posi_end)

        get_auth_token_func_tailer_begin = """        fuzz_data_logger.log_check('[*] receiving authenticated')
            if resp.status_code == 200:
                data = resp.text

                bs = BeautifulSoup(data, 'html.parser')
                http_item = bs.find_all(string=re.compile('http'))
                url_random_part=''
                if (http_item):
                    url_case1 = http_item[0]
                    pattern = re.compile(r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\(\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+')
                    url_case1 = re.findall(pattern, url_case1)[0]
                    url_random_part = url_case1["""

        get_auth_token_func_tailer_end = """]
                s_get("Request").names['ping_dynamic_url']._value = url_random_part
                fuzz_data_logger.log_pass('[*] authenticated succeed!')
                fuzz_data_logger.log_info("[*] receiving random url :" + url_random_part)
        except:
            fuzz_data_logger.log_fail('[x] receiving failed')
    """
        get_auth_token_func_tailer = get_auth_token_func_tailer_begin + dynamic_posi_str + get_auth_token_func_tailer_end
        get_auth_token_func_template = get_auth_token_func_template + get_auth_token_func_tailer
        # print(get_auth_token_func_template)
        return get_auth_token_func_template

    elif (request_method == 'TOKEN_COOKIE'):
        post_payload, res_headers, headers_dict, login_parser = param

        get_auth_token_func_template = ''

        # 1. Build get_auth_token_func header
        get_auth_token_func_header = """
def callback_get_auth_token(target, fuzz_data_logger, session, *args, **kwargs):
    # Get authenticated token from login response

    fuzz_data_logger.log_check('[*] sending  login requests')
    try:

        headers = {\n"""
        get_auth_token_func_template = get_auth_token_func_template + get_auth_token_func_header

        # 2. Build get_auth_token_func parameter
        parameter_header = '               "'
        parameter_middler = '": "'
        parameter_tailer = '",\n'

        for i in headers_dict:
            single_key = i
            single_value = headers_dict[i]
            single_parameter = parameter_header + single_key + parameter_middler + single_value + parameter_tailer
            get_auth_token_func_template = get_auth_token_func_template + single_parameter

        get_auth_token_func_template = get_auth_token_func_template + '}\n'

        # 3. Build get_auth_token_func request

        login_url = 'http://' + headers_dict['Host'] + login_parser.get_url()

        data_string = """        data = \'""" + post_payload.decode() + '\'\n'
        get_auth_token_func_template = get_auth_token_func_template + data_string
        request_template = """        resp = requests.post('""" + login_url + """',headers=headers,data=data, allow_redirects=False)\n
"""

        get_auth_token_func_template = get_auth_token_func_template + request_template

        # 4. Build get_auth_token_func tailer and position of dynamic string
        # request_dynamic_posi_begin = len('http://' + headers_dict['Host']) + begin
        # request_dynamic_posi_end = len('http://' + headers_dict['Host']) + end
        # dynamic_posi_str = str(request_dynamic_posi_begin) + ':' + str(request_dynamic_posi_end)

        get_auth_token_func_tailer = """        fuzz_data_logger.log_check('[*] receiving authenticated')
        if resp.status_code == 200:
            # data = resp.text
            res_headers = resp.headers
            cookie = res_headers['Set-Cookie']
            s_get("Request").names['set_dynamic_cookie']._value = cookie
            # bs = BeautifulSoup(data, 'html.parser')
            # http_item = bs.find_all(string=re.compile('http'))
            # url_random_part=''
            # if (http_item):
            #     url_case1 = http_item[0]
            #     pattern = re.compile(r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\(\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+')
            #     url_case1 = re.findall(pattern, url_case1)[0]
            #     url_random_part = url_case1[]
            # s_get("Request").names['ping_dynamic_url']._value = url_random_part
            fuzz_data_logger.log_pass('[*] authenticated succeed!')
            fuzz_data_logger.log_info("[*] receiving cookie:" + cookie)
    except:
        fuzz_data_logger.log_fail('[x] receiving failed')
        """
        # get_auth_token_func_tailer = get_auth_token_func_tailer
        get_auth_token_func_template = get_auth_token_func_template + get_auth_token_func_tailer
        # print(get_auth_token_func_template)
        return get_auth_token_func_template


# 生成Boofuzz模板
def build_fuzz_template(target_ip, target_port, payload, start_time, if_analysis_success=False, analysis_result=[],fuzz_policy='pdfuzzergen'):
    # Bug fixed. Calculate the original payload hash value as the session name to avoid session reuse.
    templates_dir = 'templates_created/'
    if (not os.path.exists(templates_dir)):
        os.mkdir(templates_dir)

    # windows环境下生成模板时用
    # start_time = start_time.replace(":","-")

    # 创建文件夹存放生成的fuzz模板
    # 避免fuzz模板产生过多结果，分析时无法找到对应的结果
    if (not os.path.exists('templates_created/' + start_time)):
        os.mkdir('templates_created/' + start_time)

    session_dir = 'session_log/'
    session_dir = os.path.join('templates_created/' + start_time, session_dir)
    if (not os.path.exists(session_dir)):
        os.mkdir(session_dir)

    templates_dir += start_time

    m = hashlib.md5()
    m.update(payload)
    payload_hash_value = m.hexdigest()
    
    session_name = os.path.join(session_dir, payload_hash_value)

    fuzz_result_log_filename = 'fuzz_result.log'
    if (not os.path.exists(os.path.join(templates_dir, fuzz_result_log_filename))):
        with open(os.path.join(templates_dir, fuzz_result_log_filename),'w') as f1:
            f1.write('Begin fuzz!\n')

    # os.mknod(os.path.join(templates_dir, fuzz_result_log_filename))

    import_header = """
from boofuzz import *
import requests
import argparse
import re
from bs4 import BeautifulSoup
"""

    get_web_status_func = """
def get_web_status():

    # check web state by send http requests

    # Increase robustness
    Abnormal_response_count=0
    for i in range(4):
        try:
            for i in range(5):
                r = requests.get('http://'+ip,timeout=5)
                #if r.status_code < 400:
                if r.status_code>=400:
                    Abnormal_response_count=Abnormal_response_count+1
            if(Abnormal_response_count<5):
                return True
            else:
                return False
        except Exception :
            # print(traceback.format_exc())
            pass
    return False
"""

    callback_judge_web_state_func = """
def callback_judge_web_state(target, fuzz_data_logger, session,*args, **kwargs):
    'judge web status'
    fuzz_data_logger.log_check('[*] judging web server state..')
    status_web_server = get_web_status()
    if status_web_server:
        fuzz_data_logger.log_pass('[*] web server status OK')
    else :
        with open('""" + fuzz_result_log_filename + """','a') as f1:
            f1.write('""" + 'fuzz_template_' + payload_hash_value + '.py' + \
                                    """ Failed!\\n')
        fuzz_data_logger.log_fail('[x] web server status FAILED')
        exit(1)
                                """

    pre_login_func = ''
    if (if_analysis_success):
        pre_login_func = callback_get_auth_token_func_build(payload, analysis_result)
        # print(pre_login_func)
        print()

    caller_func = """
if __name__ == "__main__":
    ip = \"""" + target_ip + """\"
    port = """ + target_port + """
    main(ip,port)
"""
    main_func_header = """
def main(ip,port):

    s_initialize(name="Request")
    with s_block("Request-Line"):
"""
    if (if_analysis_success):
        main_func_fuzzcontent = http_header_build(payload, if_analysis_success, analysis_result)
    else:
        main_func_fuzzcontent = http_header_build(payload,fuzz_policy=fuzz_policy)
    if (main_func_fuzzcontent == -1):
        return -1

    if (if_analysis_success):
        call_callback_template = '                         pre_send_callbacks=[callback_get_auth_token],\n'
    else:
        call_callback_template = ''

    main_func_fuzz_header = """
    session = Session(
        target=Target(connection = SocketConnection(ip,port,proto='tcp')),
        keep_web_open=False,
        session_filename=\"""" + session_name + \
                            """\",
                                post_test_case_callbacks=[callback_judge_web_state],\n"""

    main_func_fuzz_tailer = """
                         # tenda 的路由器有些异常，在 post_test_case_callbacks无法检测出异常，所以在重启回调函数处也增加异常检测
                         restart_callbacks =[callback_judge_web_state] 
                     )
    session.connect(s_get("Request"))
    session.fuzz()    
                 """
    main_func_fuzz = main_func_fuzz_header + call_callback_template + main_func_fuzz_tailer

    final_fuzz_template = import_header + get_web_status_func + callback_judge_web_state_func + pre_login_func + \
                          main_func_header + main_func_fuzzcontent + main_func_fuzz + caller_func
    payload_hash_value = 'fuzz'
    with open(os.path.join(templates_dir, 'fuzz_template_' + payload_hash_value + '.py'), 'w') as f1:
        f1.write(final_fuzz_template)
    # print(final_fuzz_template)


def parser_get_ori_headers(parser):
    # Loop combination of original headers

    headers_dict = parser.get_headers()
    ori_headers = b''
    for item in headers_dict:
        ori_headers = ori_headers + item.encode('utf-8') + b': ' + headers_dict[item].encode('utf-8') + b'\r\n'
    return ori_headers


def parser2rawpayload(parser):
    # Convert parser to raw payload

    orign_payload = b''
    orign_payload = orign_payload + parser.get_method().encode('utf-8') + b' ' + parser.get_url().encode(
        'utf-8') + b' HTTP/1.1\r\n'
    orign_payload = orign_payload + parser_get_ori_headers(parser) + b'\r\n'
    return orign_payload


# 对数据包进行分析和生成fuzz模板
def fuzz_template_generation_by_pcap(monitor_pcap_file, start_time):
    task_list = []

    # while (1):
    # time.sleep(1)

    # 1. Test read and send pcap
    # 对采集到的流量包进行简单过滤
    # v0.1版本仅分析POST包

    output_file_name = pcap_filter(monitor_pcap_file)
    pkt = rdpcap(output_file_name)

    # 2.Test read,parse and regroup single packet payload
    sessions = pkt.sessions()
    if_analysis_success = False
    analysis_result = []
    for session in sessions:
        for packet in sessions[session]:
            time.sleep(0.05)
            # 仅选择TCP且要求端口为80
            if packet[TCP].sport or packet[TCP].dport == 80:
                payload = bytes(packet['TCP'].payload)

                # Add completed tasks to the completed task queue
                # 生成每条报文的hash值，每次仅对没有分析过的报文进行分析
                m = hashlib.md5()
                m.update(payload)
                payload_hash_value = m.hexdigest()

                if (payload_hash_value in task_list):
                    continue
                else:
                    task_list.append(payload_hash_value)

                login_required = login_required_judge(payload)

                if (login_required):
                    if_analysis_success, analysis_result = login_message_analysis(payload)

                # # 对报文进行解析
                # p = HttpParser()
                # p.execute(payload, len(payload))
                # if (p.is_headers_complete()):
                #     pass
                #     # res = parser2rawpayload(p)
                #     # if (res != payload):
                #     #     print('[-] ERROR!')
                #     #     print(res)
                #     #     print(payload)
                #     # else:
                #     #     print(payload)
                # else:
                #     print(payload)
                #     print('Parse failed!')

                if_fuzz, request_method = creat_judge(payload)

                if (if_fuzz):
                    # For the time being, only post requests are considered
                    # 生成fuzz模板
                    if (payload[:4] == b'POST'):

                        target_ip = packet[IP].dst
                        target_port = packet[TCP].dport
                        print(payload_hash_value.encode('utf-8') + b':' + payload)
                        build_fuzz_template(target_ip, str(target_port), payload, start_time, if_analysis_success,
                                            analysis_result)
                        # post_header_build(payload)
                    elif (payload[:3] == b'GET'):
                        target_ip = packet[IP].dst
                        target_port = packet[TCP].dport
                        print(payload_hash_value.encode('utf-8') + b':' + payload)
                        build_fuzz_template(target_ip, str(target_port), payload, start_time, if_analysis_success,
                                            analysis_result)


def fuzz_template_generation_by_seed(input_seed_file, target_ip,target_port,fuzz_policy, start_time):

    with open(input_seed_file,'r') as f1:
        seed_content = f1.read()

    payload = seed_content.encode()
    if_analysis_success = False
    analysis_result = []
    policy = ''
    build_fuzz_template(target_ip, str(target_port), payload, start_time, if_analysis_success,
                        analysis_result,fuzz_policy)
    return
