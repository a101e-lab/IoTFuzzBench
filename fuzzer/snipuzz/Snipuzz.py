import requests
from urllib.parse import urlparse, parse_qs, urlencode
import json
import re
import copy
import math
from http.server import BaseHTTPRequestHandler
from io import BytesIO
import random
import string
import pandas as pd
from scipy import spatial
from math import *
from struct import pack, unpack
import argparse
import time
import socket
import sys
from http_parser.parser import HttpParser


class HTTPRequest(BaseHTTPRequestHandler):
    def __init__(self, request_text):
        self.rfile = BytesIO(request_text)
        self.raw_requestline = self.rfile.readline()
        self.error_code = self.error_message = None
        self.parse_request()

    def send_error(self, code, message):
        self.error_code = code
        self.error_message = message


def levenshteinDistance(s1, s2):
    # 编辑距离函数

    if(s1==s2):
        return 0

    if len(s1) > len(s2):
        s1, s2 = s2, s1

    distances = range(len(s1) + 1)
    for i2, c2 in enumerate(s2):
        distances_ = [i2 + 1]
        for i1, c1 in enumerate(s1):
            if c1 == c2:
                distances_.append(distances[i1])
            else:
                distances_.append(1 + min((distances[i1], distances[i1 + 1], distances_[-1])))
        distances = distances_
    return distances[-1]


class Snipuzz:

    def __init__(self, target_host, target_port, raw_request):
        self.target_host = target_host
        self.target_port = target_port
        self.raw_request = raw_request
        self.protocol_type = ''
        self.send_require_list = []

    def socker_send(self, host, port, raw_data,timeout =3):
        # 基于 socket TCP 向指定IP指定端口发送数据报文
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((host, port))
            s.settimeout(timeout)
            try:
                # Set the whole string
                s.sendall(raw_data)
            except socket.error:
                # Send failed
                print('--------------------------------------')
                print('Send failed')
                print('--------------------------------------')
                sys.exit()
            #         print('Message send successfully')

            # Now receive data
            all_receive_data = b''
            reply = True
            try:
                while reply:
                    reply = ''
                    reply = s.recv(4096)
                    all_receive_data = all_receive_data + reply
            except socket.error:
                print('--------------------------------------')
                print(socket.error)
                print(raw_data)
                print('--------------------------------------')
                return ''
        return all_receive_data

    def http_covert_2_rawdata(self, request_method, request_path, request_param, request_header_dict,
                              request_data_body):
        # 根据 http 请求参数，转化为原始HTTP报文数据
        raw_data = b''

        # 修复变异后 Content-Length 没有动态变换的 Bug
        if(request_method == 'POST'):
            request_header_dict['Content-Length']=str(len(request_data_body))

        raw_data = raw_data + request_method.encode() + b' ' + request_path.encode() + request_param.encode() + b' HTTP/1.1\r\n'
        for key in request_header_dict:
            raw_data = raw_data + key.encode() + b': ' + request_header_dict[key].encode() + b'\r\n'

        raw_data = raw_data + b'\r\n'
        raw_data = raw_data + request_data_body.encode()


        return raw_data

    def upnp_convert_2_rawdata(self, request_method, request_path, request_param, request_header_dict,request_data_body):
        # 根据 upnp 请求参数，转化为原始UPNP报文数据
        raw_data = b''

        if request_data_body:
            request_header_dict['Content-Length']=str(len(request_data_body))

        raw_data = raw_data + request_method.encode() + b' ' + request_path.encode() + request_param.encode() + b' HTTP/1.0\r\n'
        for key in request_header_dict:
            raw_data = raw_data + key.encode() + b': ' + request_header_dict[key].encode() + b'\r\n'

        raw_data = raw_data + b'\r\n'
        raw_data = raw_data + request_data_body.encode()

        # print(b'---'+raw_data)
        return raw_data


    def delete_char_one_by_one_mutation(self, host, port, raw_data):
        # 逐字节删除发送的消息，接收响应消息，并计算自相似性

        # 识别协议类型
        protocol_type = self.protocol_identification(raw_data)
        self.protocol_type = protocol_type

        category = {}
        category_num = 0

        # 如果是HTTP协议，则进行报文格式识别
        # 对于 GET 报文，默认对 URL 中的参数进行逐字节删除
        # 对于 POST 报文，默认对于请求体中的负载参数进行逐字节删除
        if (protocol_type == 'HTTP'):

            # 解析HTTP请求数据
            parser = HttpParser()
            parser.execute(raw_data, len(raw_data))

            request = HTTPRequest(raw_data)
            request_method = request.command
            # request_method = 'GET'
            request_url = parser.get_url()
            request_path = parser.get_path()
            request_header_dict = dict(request.headers)
            request_param = ''
            request_data_body_str = ''

            if (request_method == 'GET'):
                request_param = request_url[len(request_path):]
            elif (request_method == 'POST'):
                content_len = int(request.headers.get('Content-Length'))
                request_data_body_str = request.rfile.read(content_len).decode()

            # 根据请求类型，判断需要变异的数据
            response_dict = {}
            response_dict['mutation'] = {}
            if (request_method == 'GET'):
                response_dict['ori_data_str'] = request_param
            elif (request_method == 'POST'):
                response_dict['ori_data_str'] = request_data_body_str

            self.send_require_list = [request_method, request_path, request_param,
                                      request_header_dict,
                                      request_data_body_str]

            # 逐字节进行删除需变异数据，并发送，接收响应结果，计算自相似性
            for posi in range(len(response_dict['ori_data_str'])):
                mutation_data = ''
                mutation_data = response_dict['ori_data_str'][0:posi] + response_dict['ori_data_str'][posi + 1:]

                if (request_method == 'GET'):
                    request_param = mutation_data
                elif (request_method == 'POST'):
                    request_data_body_str = mutation_data

                # 1s 内连续发送两次请求，并计算自自相似性
                response_1_text = self.http_request_send(host, port, request_method, request_path, request_param,
                                                         request_header_dict,
                                                         request_data_body_str)
                response_2_text = self.http_request_send(host, port, request_method, request_path, request_param,
                                                         request_header_dict,
                                                         request_data_body_str)
                # 计算两个响应之间的编辑距离
                self_distances = levenshteinDistance(response_1_text, response_2_text)
                # 基于编辑距离计算自相似性
                max_len = max(len(response_1_text), len(response_2_text))
                if(max_len == 0):
                    self_saimilarity =1
                else:
                    self_saimilarity = 1 - (self_distances / max_len)


                response_dict['mutation'][posi] = {}
                response_dict['mutation'][posi]['response_1'] = response_1_text
                response_dict['mutation'][posi]['response_2'] = response_2_text
                response_dict['mutation'][posi]['self_saimilarity'] = self_saimilarity

                if (response_1_text not in category):
                    category[response_1_text] = category_num
                    category_num = category_num + 1
            return response_dict, category
    
        elif (protocol_type == 'upnp'):
            # 解析upnp请求数据
            parser = HttpParser()
            request = HTTPRequest(raw_data)
            parser.execute(raw_data, len(raw_data))

            request_method = parser.get_method()
            request_url = parser.get_url()
            request_path = parser.get_path()
            request_header_dict = parser.get_headers()
            request_param = ''
            request_data_body_str = ''
            

            for index,line in enumerate(raw_data.split(b'\n')):
                # 当前行长度为0并且不是最后一行（说明下面还有要发送的数据）
                if len(line)==0 and  index != len(raw_data.split(b'\n'))-1:
                    request_data_body_str = b'\n'.join(raw_data.splitlines()[index:]).decode().strip()
                    break       
            
            if not request_data_body_str:
                request_param = parser.get_query_string()

            # 根据请求类型，判断需要变异的数据
            response_dict = {}
            response_dict['mutation'] = {}
            if request_data_body_str:
                response_dict['ori_data_str'] = request_data_body_str
            else:
                response_dict['ori_data_str'] = request_param

            self.send_require_list = [request_method, request_path, request_param,
                                      request_header_dict,
                                      request_data_body_str]
            print(self.send_require_list)
            # 逐字节进行删除需变异数据，并发送，接收响应结果，计算自相似性
            for posi in range(len(response_dict['ori_data_str'])):
                mutation_data = ''
                mutation_data = response_dict['ori_data_str'][0:posi] + response_dict['ori_data_str'][posi + 1:]

                if request_data_body_str:
                    request_data_body_str = mutation_data    
                elif (request_method):
                    request_param = mutation_data

                # 1s 内连续发送两次请求，并计算自自相似性
                response_1_text = self.upnp_request_send(host, port, request_method, request_path, request_param,
                                                         request_header_dict,
                                                         request_data_body_str)
                response_2_text = self.upnp_request_send(host, port, request_method, request_path, request_param,
                                                         request_header_dict,
                                                         request_data_body_str)
                # 计算两个响应之间的编辑距离
                self_distances = levenshteinDistance(response_1_text, response_2_text)
                # 基于编辑距离计算自相似性
                max_len = max(len(response_1_text), len(response_2_text))
                if(max_len == 0):
                    self_saimilarity =1
                else:
                    self_saimilarity = 1 - (self_distances / max_len)


                response_dict['mutation'][posi] = {}
                response_dict['mutation'][posi]['response_1'] = response_1_text
                response_dict['mutation'][posi]['response_2'] = response_2_text
                response_dict['mutation'][posi]['self_saimilarity'] = self_saimilarity

                if (response_1_text not in category):
                    category[response_1_text] = category_num
                    category_num = category_num + 1
            return response_dict, category

        # 需要变异的数据为原始所有数据
        elif (protocol_type == 'RAW_DATA'):

            response_dict = {}
            response_dict['ori_data_str'] = raw_data
            response_dict['mutation'] = {}
            category = {}
            category_num = 0

            for posi in range(len(response_dict['ori_data_str'])):
                mutation_data = ''
                mutation_data = response_dict['ori_data_str'][0:posi] + response_dict['ori_data_str'][posi + 1:]

                # 1s 内连续发送两次请求，并计算自自相似性
                response_1_text = self.socker_send(host, port, mutation_data)
                response_2_text = self.socker_send(host, port, mutation_data)

                # 计算两个响应之间的编辑距离
                self_distances = levenshteinDistance(response_1_text, response_2_text)
                # 基于编辑距离计算自相似性
                max_len = max(len(response_1_text), len(response_2_text))
                self_saimilarity = 1 - (self_distances / max_len)

                response_dict['mutation'][posi] = {}
                response_dict['mutation'][posi]['response_1'] = response_1_text
                response_dict['mutation'][posi]['response_2'] = response_2_text
                response_dict['mutation'][posi]['self_saimilarity'] = self_saimilarity

                if (response_1_text not in category):
                    category[response_1_text] = category_num
                    category_num = category_num + 1
            return response_dict, category

    def http_request_send(self, host, port, request_method, request_path, request_param, request_header_dict,
                          request_data_body_str):
        # HTTP 协议发送函数
        # 先根据HTTP各请求参数组装原始报文，再将原始报文发送出去

        # 1.根据HTTP各请求参数组装原始报文
        raw_data = self.http_covert_2_rawdata(request_method, request_path, request_param, request_header_dict,
                                              request_data_body_str)
        # 2.将原始报文发送给指定IP的指定端口
        response_text = self.socker_send(host, port, raw_data)

        return response_text

    def upnp_request_send(self, host, port, request_method, request_path, request_param, request_header_dict,
                          request_data_body_str):
        # 1.根据upnp各请求参数组装原始报文
        raw_data = self.upnp_convert_2_rawdata(request_method, request_path, request_param, request_header_dict,request_data_body_str)
        # 2.将原始报文发送给指定IP的指定端口
        response_text = self.socker_send(host, port, raw_data)

        return response_text

    def response_feature_extraction(self, category_pool, response):
        # 提取响应报文特征
        self_saimilarity = category_pool[response]['self_saimilarity']
        response_length = len(response)

        alphabetic_segments_number = sum(chr(c).isalpha() for c in response)
        numeric_segments_number = sum(chr(c).isdigit() for c in response)
        spaces_segments__number = sum(chr(c).isspace() for c in response)
        symbol_segments_number = len(
            response) - alphabetic_segments_number - numeric_segments_number - spaces_segments__number

        response_feature = [self_saimilarity, response_length, alphabetic_segments_number, numeric_segments_number,
                            symbol_segments_number]
        return response_feature

    def calc_euclidean_distance(self, response_feature_list_1, response_feature_list_2):
        # 计算欧几里得距离
        squares = [(p - q) ** 2 for p, q in zip(response_feature_list_1, response_feature_list_2)]
        euclidean_distance = round(sum(squares) ** 0.5, 2)
        return euclidean_distance

    def find_min_distance(self, distance_dict):
        # 找到所有点中距离最接近的两个点及其最短距离
        min_distance = 999999999
        min_i_pos = 0
        min_j_pos = 0
        for i in distance_dict:
            for j in distance_dict[i]:
                if (distance_dict[i][j] < min_distance):
                    min_distance = distance_dict[i][j]
                    min_i_pos = i
                    min_j_pos = j
                # 如果遇到距离为0，则一定为最短距离，直接返回
                if (min_distance == 0):
                    break
        return min_i_pos, min_j_pos, min_distance

    def merge_category(self, new_snippet, keep_category_num, del_category_num):
        # 合并两个响应类别，将删除的类别替换成新的类别
        for i in new_snippet:
            temp_category_num = new_snippet[i]['category_num']
            if (temp_category_num == del_category_num):
                new_snippet[i]['category_num'] = keep_category_num
        return new_snippet

    def update_snippet(self, new_snippet):
        # 更新 snippet
        updated_new_snippet = {}
        pass_flag = 0
        sum_change_num = 0
        for i in new_snippet.keys():

            update_i = i - sum_change_num
            if (pass_flag == 1):
                pass_flag = 0
                continue
            if (i + 1 >= len(new_snippet)):
                updated_new_snippet[update_i] = new_snippet[i]
                continue

            if (new_snippet[i]['category_num'] != new_snippet[i + 1]['category_num']):

                updated_new_snippet[update_i] = new_snippet[i]
            else:
                updated_new_snippet[update_i] = {}
                updated_new_snippet[update_i]['snippet_position'] = new_snippet[i]['snippet_position'] + \
                                                                    new_snippet[i + 1][
                                                                        'snippet_position']
                updated_new_snippet[update_i]['response'] = new_snippet[i]['response']
                updated_new_snippet[update_i]['category_num'] = new_snippet[i]['category_num']
                pass_flag = 1
                sum_change_num = sum_change_num + 1

        #             display(pd.DataFrame.from_dict(new_snippet, orient='index'))
        #             display(pd.DataFrame.from_dict(updated_new_snippet, orient='index'))
        return updated_new_snippet

    def snippets_hierarchical_clustering(self, initial_snippet, category_pool):
        # Snippet 凝聚层次聚类
        snippet_pool = [initial_snippet]

        for cate in category_pool:
            category_vector = self.response_feature_extraction(category_pool, cate)
        #         print(category_vector)

        category_pool_copy_list = [cate for cate in category_pool]

        iteration_snippet = copy.deepcopy(initial_snippet)

        # display(pd.DataFrame.from_dict(iteration_snippet, orient='index'))

        while (len(category_pool_copy_list) > 1):

            new_snippet = copy.deepcopy(iteration_snippet)
            distance_dict = {}
            for i in range(len(category_pool_copy_list)):
                for j in range(i + 1, len(category_pool_copy_list)):
                    response_feature_list_i = self.response_feature_extraction(category_pool,
                                                                               category_pool_copy_list[i])
                    response_feature_list_j = self.response_feature_extraction(category_pool,
                                                                               category_pool_copy_list[j])
                    response_feature_distance = self.calc_euclidean_distance(response_feature_list_i,
                                                                             response_feature_list_j)
                    if (i not in distance_dict):
                        distance_dict[i] = {j: response_feature_distance}
                    else:
                        distance_dict[i][j] = response_feature_distance

            min_i_pos, min_j_pos, min_distance = self.find_min_distance(distance_dict)

            global_min_i_pos = category_pool[category_pool_copy_list[min_i_pos]]['num']
            global_min_j_pos = category_pool[category_pool_copy_list[min_j_pos]]['num']
            #         print(global_min_i_pos, global_min_j_pos,min_distance)
            del category_pool_copy_list[min_j_pos]

            keep_category_num = global_min_i_pos
            del_category_num = global_min_j_pos
            new_snippet = self.merge_category(new_snippet, keep_category_num, del_category_num)
            new_snippet = self.update_snippet(new_snippet)
            snippet_pool.append(new_snippet)
            iteration_snippet = copy.deepcopy(new_snippet)
        #         display(pd.DataFrame.from_dict(iteration_snippet, orient='index'))
        return snippet_pool

    def single_data_mutation(self, data, mutation_operation):
        # 单个数据字段的变异
        if (mutation_operation == 'invariant'):
            mutation_data = data
        elif (mutation_operation == 'empty'):
            mutation_data = ''
        elif (mutation_operation == 'byte_flip'):
            mutation_data = data[::-1]
        elif (mutation_operation == 'data_boundary'):
            if (data.isdigit()):
                mutation_data = '65535'
            else:
                mutation_data = data
        elif (mutation_operation == 'dictionary'):
            if (data == 'true'):
                mutation_data = 'false'
            elif (data == 'false'):
                mutation_data = 'true'
            else:
                mutation_data = data
        elif (mutation_operation == 'repeat'):
            mutation_data = data * 1000
        else:
            mutation_data = data
        return mutation_data

    def single_snip_mutations(self, pseudo_mutation_data_list):
        # 进行单个 snippet 的变异
        mutation_operations_pool = ['invariant', 'empty', 'byte_flip', 'data_boundary', 'dictionary', 'repeat']
        mutation_data_list = []
        #     print(pseudo_mutation_data_list)
        for data in pseudo_mutation_data_list:
            mutation_data = ''
            mutation_operation_random_id = random.randint(0, len(mutation_operations_pool) - 1)
            mutation_operation = mutation_operations_pool[mutation_operation_random_id]
            mutation_data = self.single_data_mutation(data, mutation_operation)
            mutation_data_list.append(mutation_data)
        #     print(mutation_data_list)
        return mutation_data_list

    # def http_sender(request_mutation_data_dict, mutation_data_pool):
    # request_mutation_data_dict
    # mutation_data_pool

    def snipuzz_fuzz_driver(self, mutation_data_pool, runtime=60):
        # 按照时间去驱动，运行指定时间 变异一次，发送一次数据
        #     runtime = 1 # 10 minutes
        now_time = time.time()
        target_time = now_time + runtime * 60

        # method = request_mutation_data_dict['request_method']
        # request_url = request_mutation_data_dict['request_url']
        # request_header_dict = request_mutation_data_dict['request_header_dict']
        # request_data_body_str = request_mutation_data_dict['request_data_body_str']

        send_require_list = self.send_require_list
        request_method = ''
        request_path = ''
        request_param = ''
        request_header_dict = {}
        request_data_body_str = ''


        if (self.protocol_type == 'HTTP' or self.protocol_type == 'upnp'):
            request_method, request_path, request_param, request_header_dict, request_data_body_str = send_require_list

        runtime_response_pool = {}
        mutation_count = 0

        while (now_time < target_time):
            pseudo_mutation_data_list_id = random.randint(0, len(mutation_data_pool) - 1)
            pseudo_mutation_data_list = mutation_data_pool[pseudo_mutation_data_list_id]
            mutation_data_list = self.single_snip_mutations(pseudo_mutation_data_list)
            mutation_send_data = ''.join(mutation_data_list)

            response_1_text = ''
            if (self.protocol_type == 'HTTP'):
                if (request_method == 'GET'):
                    response_1_text = self.http_request_send(self.target_host, self.target_port, request_method,
                                                             request_path, mutation_send_data,
                                                             request_header_dict,
                                                             request_data_body_str)
                elif (request_method == 'POST'):
                    response_1_text = self.http_request_send(self.target_host, self.target_port, request_method,
                                                             request_path, request_param,
                                                             request_header_dict,
                                                             mutation_send_data)
            elif(self.protocol_type == 'upnp'):
                if not request_data_body_str:
                    response_1_text = self.upnp_request_send(self.target_host, self.target_port, request_method,
                                                             request_path, mutation_send_data,
                                                             request_header_dict,
                                                             request_data_body_str)
                else:
                    response_1_text = self.upnp_request_send(self.target_host, self.target_port, request_method,
                                                             request_path, request_param,
                                                             request_header_dict,
                                                             mutation_send_data)                
            elif (self.protocol_type == 'RAW_DATA'):
                response_1_text = self.socker_send(self.target_host, self.target_port, mutation_send_data)


            if (response_1_text not in runtime_response_pool):
                runtime_response_pool[response_1_text] = mutation_data_list
            mutation_count = mutation_count + 1
            now_time = time.time()
            print('Mutation count: ', mutation_count)
        return runtime_response_pool

    def construct_category_pool(self, response_dict, category):
        # 构造初始响应类别池

        category_pool = {}
        for cate in category:
            category_pool[cate] = {}
            category_pool[cate]['num'] = category[cate]
            category_pool[cate]['self_saimilarity'] = 0
        for res in response_dict["mutation"]:
            category_pool[response_dict["mutation"][res]['response_1']]['self_saimilarity'] = \
                response_dict["mutation"][res]['self_saimilarity']
        # 打印响应类别池
        # print(category_pool)
        return category_pool

    def constructing_initial_snippet(self, response_dict, category):
        # 构造初始 snippet
        # 1）根据相邻字节的响应，计算相似性，合并具有相似响应的字节到同一个类别里
        last_resp = response_dict['mutation'][0]
        single_snippet = []
        init_all_snippet = []
        for resp_num in range(0, len(response_dict['mutation'])):
            distances = levenshteinDistance(response_dict['mutation'][resp_num]['response_1'], last_resp['response_1'])
            # 基于编辑距离计算自相似性
            max_len = max(len(response_dict['mutation'][resp_num]['response_1']), len(last_resp['response_1']))
            if(max_len==0):
                saimilarity = 1
            else:
                saimilarity = 1 - (distances / max_len)
            if (saimilarity >= response_dict['mutation'][resp_num]['self_saimilarity'] or saimilarity >= last_resp[
                'self_saimilarity']):
                single_snippet.append(resp_num)
            else:
                init_all_snippet.append(single_snippet)
                single_snippet = [resp_num]
            last_resp = response_dict['mutation'][resp_num]
        # init_all_snippet = init_all_snippet[1:]
        # 打印初始snippet的划分
        # print(init_all_snippet)
        if(len(init_all_snippet)==0):
            init_all_snippet.append(single_snippet)

        # 2）构造初始 snippet
        initial_snippet = {}
        for snippet_num in range(len(init_all_snippet)):
            initial_snippet[snippet_num] = {}
            initial_snippet[snippet_num]['snippet_position'] = init_all_snippet[snippet_num]
            initial_snippet[snippet_num]['response'] = response_dict['mutation'][init_all_snippet[snippet_num][0]][
                'response_1']
            initial_snippet[snippet_num]['category_num'] = category[initial_snippet[snippet_num]['response']]
        # initial_snippet
        # pd.DataFrame.from_dict(initial_snippet, orient='index')
        return initial_snippet

    def extract_snippet_pool_data_list(self, response_dict, snippet_pool):
        # 从snippet_pool中，提取需要变异的 snippet 数据列表

        ori_data_str = response_dict['ori_data_str']
        mutation_data_pool = []

        for snippet in snippet_pool:
            mutation_data = []
            posi_flag = 0
            for snip in snippet:
                sni_data = ori_data_str[posi_flag:posi_flag + len(snippet[snip]['snippet_position'])]
                posi_flag = posi_flag + len(snippet[snip]['snippet_position'])
                mutation_data.append(sni_data)
            mutation_data_pool.append(mutation_data)
        return mutation_data_pool

    def snipuzz_main(self):
        # Snipuzz 主函数

        raw_request = self.raw_request

        # 逐字节删除，收集响应报文
        print('[+] Delete byte by byte, collecting response messages...')
        response_dict, category = self.delete_char_one_by_one_mutation(self.target_host, self.target_port, raw_request)

        # 打印原始响应字典
        # print(json.dumps(response_dict, indent=4, sort_keys=True))

        # 构造初始响应类别池
        print('[+] Constructing initial response category pool...')
        category_pool = self.construct_category_pool(response_dict, category)

        # 构造初始 snippet
        print('[+] Constructing the initial snippet...')
        initial_snippet = self.constructing_initial_snippet(response_dict, category)

        # 进行凝聚层次聚类，得到 snippet_pool
        print('[+] Agglomerative hierarchical clustering...')
        snippet_pool = self.snippets_hierarchical_clustering(initial_snippet, category_pool)

        # 从snippet_pool中，提取需要变异的 snippet 数据列表
        print('[+] Start building the snippet data list...')
        mutation_data_pool = self.extract_snippet_pool_data_list(response_dict, snippet_pool)
        print('[+] The snippet data list is constructed!')

        # 根据snippet数据列表池驱动变异
        print('[+] Start snipuzz fuzzing!')
        runtime_response_pool = self.snipuzz_fuzz_driver(mutation_data_pool, runtime=1)
        print('Reponse results num: ', len(runtime_response_pool))



    def protocol_identification(self, raw_data):
        http_method = ['GET','POST','HEAD','OPTIONS','PUT','PATCH','DELETE','TRACE','CONNECT',]
        upnp_method = ['SUBSCRIBE','NOTIFY',]
        parser = HttpParser()
        parser.execute(raw_data, len(raw_data))
        request_method = parser.get_method().upper()

        if request_method in http_method:
            protocol_type = 'HTTP'       
        elif request_method in upnp_method:
            protocol_type = 'upnp'
        else:
            protocol_type = 'RAW_DATA'

        return protocol_type


def main():
    # 幂等报文
    zte_raw_request_1 = b"""POST /common_page/PortForwarding_lua.lua HTTP/1.1
Host: 192.168.5.1
Content-Length: 200
Accept: application/xml, text/xml, */*; q=0.01
X-Requested-With: XMLHttpRequest
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.159 Safari/537.36
Content-Type: application/x-www-form-urlencoded; charset=UTF-8
Origin: http://192.168.5.1
Referer: http://192.168.5.1/
Accept-Encoding: gzip, deflate
Accept-Language: zh-CN,zh;q=0.9
Connection: close

IF_ACTION=Apply&Enable=1&_InstID=DEV.NAT.PtMapping1&InternalClient=192.168.5.97&Alias=daaas&Server=&Protocol=TCP&ExternalPort=66&InternalPort=10055&Btn_cancel_PortForwarding=&Btn_apply_PortForwarding="""



    parser = argparse.ArgumentParser(description="Automatically generate fuzzers")
    parser.add_argument("host", help="the target host")
    parser.add_argument("port", help="the target port")
    parser.add_argument("raw_data_file", help="the raw data file name")
    args = parser.parse_args()


    if args.host and args.port and args.raw_data_file:
        with open(args.raw_data_file,'r') as f1:
            raw_data = f1.read().encode()
        args.port = int(args.port)
        snipuzz_fuzzer = Snipuzz(args.host, args.port, raw_data)
        snipuzz_fuzzer.snipuzz_main()
    else:
        parser.print_help()


if __name__ == '__main__':
    main()
