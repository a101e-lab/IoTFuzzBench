import ast
import copy
import json
import string
import xml.sax
import base64
import urllib
import xmltodict
import re
from urllib.parse import *
import xml.etree.ElementTree as ET
from http_parser.parser import HttpParser
import http_parser


# 0. 数据格式识别及解析类
# e.g. json、xml、key-value
class ParseDataFormat():
    def __init__(self):
        self.raw_data = ''
        self.data_format = ''

    def recognize(self, data):
        # 识别目标数据结构
        if self.is_json(data):
            data_format = 'json'
        elif self.is_xml(data):
            data_format = 'xml'
        elif self.is_keyvalue(data):
            data_format = 'kv'
        else:
            print('未识别数据类型')
            data_format = 'raw'
        return data_format

    def is_json(self, raw_data):
        try:
            data = json.loads(raw_data)
            # json 在解析数字字符串时，会认为其是正确的语法，不会报错。例如 json.loads('50') 不会报错
            # 所以这里增加一个限制，只有当解析成字典时才认为有效
            if (type(data) == type({})):
                self.data_format = 'json'
                return True
            else:
                return False
        except ValueError:
            return False

    def is_xml(self, raw_data):
        try:
            Handler = xml.sax.ContentHandler()
            xml.sax.parseString(raw_data, Handler)
        except xml.sax.SAXParseException:
            return False
        self.data_format = 'xml'
        return True

    def is_keyvalue(self, raw_data):
        if self.parse_kv_pairs(raw_data, b'&', b'='):
            self.data_format = 'kv'
            return True
        else:
            return False

    def parse_kv_pairs(self, raw_data, item_sep=b"&", value_sep=b"="):
        # 识别键值对格式的数据的辅助函数
        """Parse key-value pairs from a shell-like text."""

        if type(raw_data) == type(''):
            raw_data = raw_data.encode()

        if b'=' not in raw_data:
            return False

        data_list = raw_data.split(item_sep)
        invalid_char_list = ['/', '#', '[', ']', '@', '!', '$', '&', "'", '(', ')', '*', ';', '=']
        invalid_char_list = [_char.encode() for _char in invalid_char_list]

        for word in data_list:
            data_list = word.split(value_sep)
            for data in data_list:
                for invalid_char in invalid_char_list:
                    if invalid_char in data:
                        return False
        return True

    # 解析目标数据结构
    def parse(self, data_format, data):
        if data_format == 'json':
            result = self.parse_json(data)
            # format = 'json'
        elif data_format == 'xml':
            result = self.parse_xml(data)
            # format = 'xml'
        # elif data_format == 'url':
        #     result = self.parse_url(data)
        #     # format = 'url'
        elif data_format == 'kv':
            result = self.parse_kv(data)
            # format = 'kv'
        else:
            # 未知数据格式直接按照
            print('不支持的数据格式！')
            result = None
            # rules = None
            # format = 'raw'
        return result  # rules, format

    def parse_json(self, data):
        result = json.loads(data)
        # print(result)
        # rules = copy.deepcopy(result)
        # self.list_dictionary(rules)
        # print('解析输入json数据格式：')
        # print(rules)
        return result

    def parse_xml(self, data):
        # 添加attr_prefix=''属性，防止默认会在属性前加@前缀
        xml_dict = xmltodict.parse(data, attr_prefix='')
        result = json.loads(json.dumps(xml_dict))
        # print(result)
        # rules = copy.deepcopy(result)
        # self.list_dictionary(rules)
        # print('解析xml数据格式：')
        # print(rules)
        return result

    # def parse_url(self, data):
    #     params = urllib.parse.urlparse(data).query
    #     if len(params) == 0:
    #         params = urllib.parse.urlparse(data).path
    #     params = urllib.parse.parse_qs(params.decode())
    #     result = {key: params[key][0] for key in params}
    #     coding_parser = ParseCoding()
    #     rules = {key: coding_parser.parse(params[key][0]) for key in params}
    #     print(result)
    #     print(rules)
    #     return result, rules

    def parse_kv(self, raw_data, item_sep=b"&", value_sep=b"="):

        # data = data.split(b'&')
        result = {}
        # for item in data:
        # result = urllib.parse.parse_qs(data)

        if type(raw_data) == type(''):
            raw_data = raw_data.encode()

        kv_list = raw_data.split(item_sep)

        for word in kv_list:
            single_key, single_value = word.split(value_sep)
            result[single_key] = single_value
            print()

        # result = {item(b'=')[0]: item.split(b'=')[1] for item in data}
        # coding_parser = ParseCoding()
        # rules = {item(b'=')[0]: coding_parser.parse(item.split(b'=')[1]) for item in data}
        # print(result)
        # print(rules)
        return result

    # def list_dictionary(self, d):
    #     for key, values in d.items():
    #         if isinstance(values, list):
    #             self.get_list(values)
    #         elif isinstance(values, dict):
    #             self.list_dictionary(values)
    #         else:
    #             coding_parser = ParseCoding()
    #             # 获取编码类型
    #             d[key] = coding_parser.parse(values)
    #
    # def get_list(self, values):
    #     for index, item in enumerate(values):
    #         if type(item) == list:
    #             self.get_list(values)
    #         elif isinstance(item, dict):
    #             self.list_dictionary(item)
    #         else:
    #             coding_parser = ParseCoding()
    #             # 获取编码类型
    #             values[index] = coding_parser.parse(item)

    # def normalize(self, data, data_struct, data_format):
    #     if data_format == 'json':
    #         result = self.normalize_json(data, data_struct)
    #     elif data_format == 'xml':
    #         result = self.normalize_xml(data, data_struct)
    #     elif data_format == 'url':
    #         result = self.normalize_url(data, data_struct)
    #     else:
    #         print('不支持的数据格式！')
    #         result = data
    #     return result
    #
    # def normalize_json(self, data, data_struct):
    #     result = json.dumps(data)
    #     print('将输入数据格式转为json：')
    #     print(result)
    #     return result
    #
    # def normalize_xml(self, data, data_struct):
    #     data = ast.literal_eval(data)
    #     result = xmltodict.unparse(data)
    #     print('将输入数据格式转为xml：')
    #     print(result)
    #     return result
    #
    # def normalize_url(self, data, data_struct):
    #     result = urllib.parse.urlencode(data)
    #     print('将输入数据格式转为url：')
    #     print(result)
    #     return result
    #
    # def normalize_dictionary(self, d):
    #     for key, values in d.items():
    #         if isinstance(values, list):
    #             self.normalize_list(values)
    #         elif isinstance(values, dict):
    #             self.normalize_dictionary(values)
    #         else:
    #             coding_parser = ParseCoding()
    #             # 获取编码类型
    #             d[key] = coding_parser.parse(values)
    #
    # def normalize_list(self, values):
    #     for index, item in enumerate(values):
    #         if type(item) == list:
    #             self.normalize_list(values)
    #         elif isinstance(item, dict):
    #             self.normalize_dictionary(item)
    #         else:
    #             coding_parser = ParseCoding()
    #             # 获取编码类型
    #             values[index] = coding_parser.parse(item)


# 1. 数据编码类型识别、解码及编码类
# e.g. base64、url 编码
class ParseCoding():
    '''
    编码识别类:
        输入:原始数据 
        输出:编码类型
    '''

    def __init__(self, raw_data='') -> None:
        self.coding_type = ''
        self.raw_data = raw_data
        self.encode_dict = {
            'base64': 'base64_encode',
            'url': 'url_encode',
            'raw': 'default',
        }
        self.decode_dict = {
            'base64': 'base64_decode',
            'url': 'url_decode',
            'raw': 'default',
        }

    def parse(self, data):
        '''
        需要传入bytes类型的变量
        '''
        if self.is_base64(data):
            # print('这是base64编码')
            coding_type = 'base64'
        elif self.is_url(data):
            # print('这是url编码')
            coding_type = 'url'
        else:
            # print('未识别编码类型')
            coding_type = None
        return coding_type

    def is_base64(self, data):
        try:
            base64.b64decode(data).decode()
        except:
            return False
        self.coding_type = 'base64'
        return True

    def is_url(self, raw_data):
        try:
            if type(raw_data) == type(b''):
                raw_data = raw_data.decode()
            result = urllib.parse.unquote(raw_data)
            if '%' in raw_data and '%' not in result:
                self.data_format = 'url'
            else:
                return False
        except:
            return False
        return True

    def encode(self, data, coding_type):
        result = getattr(self, self.encode_dict[coding_type], self.default)(data)
        print(result)
        return result

    def decode(self, data, coding_type):
        result = getattr(self, self.decode_dict[coding_type], self.default)(data)
        print(result)
        return result

    def base64_encode(self, data):
        result = base64.b64encode(data)
        return result

    def url_encode(self, data):
        result = urllib.parse.quote(data)
        return result

    def base64_decode(self, data):
        result = base64.b64decode(data)
        return result

    def url_decode(self, data):
        result = urllib.parse.unquote(data)
        return result

    def default(self, data):
        print('未识别的编码方式')
        return None


# 2. 数据类型识别类
# e.g. 数字（number）、字母、协议关键字、MAC 地址等
class ParseDataType():

    def __init__(self, raw_data='') -> None:
        self.value_type = None

    def get_protocol_list(self, proto_file_name='utils/ip-protocol-numbers.json'):
        # 获得协议列表
        protocol_list = []
        with open(proto_file_name) as protocol_file:
            protocol_dict = json.load(protocol_file)
            for proto in protocol_dict:
                if protocol_dict[proto]['keyword'] not in protocol_list:
                    protocol_list.append(protocol_dict[proto]['keyword'].upper())
        return protocol_list

    def is_number(self, s):
        try:
            float(s)
            return True
        except ValueError:
            pass

        try:
            import unicodedata
            unicodedata.numeric(s)
            return True
        except (TypeError, ValueError):
            pass

        return False

    def is_printable_symbols(self, value_data):
        printable_symbols = string.printable[string.printable.find('Z') + 1:]
        for single_char in value_data:
            if single_char not in printable_symbols:
                return False
        return True

    def field_data_recognition(self, value_data):
        # 数据类型识别函数

        # value_data = 'www.baidu.com'
        # value_data = '192.168.1.7'
        # value_data = '3D:F2:0C:A6:B3:4F'
        # value_data = 'TCP'
        # value_data = None
        value_type = None

        if value_data:
            value_data = value_data.decode()

            if len(value_data) == 0:
                return None

            # 1. Judge according to the patterns of different data types
            type_expressions = {
                'domain': '^((?!-))(xn--)?[a-z0-9][a-z0-9-_]{0,61}[a-z0-9]{0,1}\.(xn--)?([a-z0-9\-]{1,61}|[a-z0-9-]{1,30}\.[a-z]{2,})$',
                'ipv4': '^((25[0-5]|(2[0-4]|1\d|[1-9]|)\d)(\.(?!$)|$)){4}$',
                'mac': '^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$',
                'url': '^(http|ftp|https):\/\/([\w\-_]+(?:(?:\.[\w\-_]+)+))([\w\-\.,@?^=%&:/~\+#]*[\w\-\@?^=%&/~\+#])?',
            }
            for expression in type_expressions:
                pattern = re.compile(type_expressions[expression], re.I)
                match_result = pattern.match(value_data)
                if match_result is not None:
                    value_type = expression
                    return value_type

            # 2. Judge according to the names of different protocols
            protocol_list = self.get_protocol_list()
            if value_data.upper() in protocol_list:
                value_type = 'protocol_name'
                return value_type

            # 3. Common data type judgment
            if self.is_number(value_data):
                value_type = 'number'
                return value_type

            if value_data.isalpha():
                value_type = 'alpha_num'
                return value_type

            if value_data.isalnum():
                value_type = 'alpha_num'
                return value_type

            if self.is_printable_symbols(value_data):
                value_type = 'symbol'
                return value_type

            if value_data.isprintable():
                value_type = 'str'
                return value_type
        else:
            return None

        if value_type is None:
            value_type = 'Unknown'
        return value_type


def snipuzz(data):
    coding_parser = ParseCoding()
    format_parser = ParseDataFormat()
    if coding_parser.parse(data) != 'raw':
        resolve_result, resolve_struct, resolve_format = format_parser.parse(format_parser.recognize(data), data)
    else:
        resolve_result, resolve_struct, resolve_format = format_parser.parse(format_parser.recognize(data), data)
        # print('逐字节变异')
    return data * 2


def main():
    test_str1 = b'''<s:Envelope s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/" xmlns:s="http://schemas.xmlsoap.org/soap/envelope/">
    <s:Body>
        <u:GetExternalIPAddress xmlns:u="urn:schemas-upnp-org:service:WANIPConnection:1#GetExternalIPAddress">
        </u:GetExternalIPAddress>
    </s:Body>
</s:Envelope>
    '''
    test_str2 = b'''module1=parentCtrlList&onlineList=DESKTOP-4UJKRFKs100000&parentCtrlURLFilterMode=forbid&urlList=google.com'''
    test_str3 = b'''<book id="1"><name>Java</name><author>Cay S. Horstmann</author><isbn lang="CN">1234567</isbn><tags><tag>Java</tag><tag>Network</tag></tags><pubDate/></book>
    '''
    test_str4 = b'''<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
<soap:Body>
	<ns2:sayHello xmlns:ns2="http://service.example.com/">
		<arg0>Leo</arg0>
		<arg1>31</arg1>
	</ns2:sayHello>
</soap:Body>
</soap:Envelope>
    '''
    test_str5 = b'''idftfyft5'''
    test_str6 = b'''UEA1NXcwcmQ='''
    test_str7 = '''%E5%86%AC%E8%87%B3%E5%88%B0%E4%BA%86'''
    test_str8 = b'''{ "people": [  { "firstName": "Brett", "lastName":"McLaughlin", "email": "brett@newInstance.com" },  { "firstName": "Jason","lastName":"Hunter", "email": "jason@servlets.com" },  { "firstName": "Elliotte", "lastName":"Harold", "email": "elharo@macfaq.com" }]}'''
    test_str9 = b'''<?xml version="1.0"?>
<data>
    <country name="Liechtenstein">
        <rank>1</rank>
        <year>2008</year>
        <gdppc>141100</gdppc>
        <neighbor name="Austria" direction="E"/>
        <neighbor name="Switzerland" direction="W"/>
    </country>
    <country name="Singapore">
        <rank>4</rank>
        <year>2011</year>
        <gdppc>UEA1NXcwcmQ=</gdppc>
        <neighbor name="Malaysia" direction="N"/>
    </country>
    <country name="Panama">
        <rank>68</rank>
        <year>2011</year>
        <gdppc>13600</gdppc>
        <neighbor name="Costa Rica" direction="W"/>
        <neighbor name="Colombia" direction="E"/>
    </country>
</data>'''

    test_str10 = b'''<?xml version="1.0"?>
<actors xmlns:fictional="http://characters.example.com"
        xmlns="http://people.example.com">
    <actor>
        <name>John Cleese</name>
        <fictional:character>Lancelot</fictional:character>
        <fictional:character>Archie Leach</fictional:character>
    </actor>
    <actor>
        <name>Eric Idle</name>
        <fictional:character>Sir Robin</fictional:character>
        <fictional:character>Gunther</fictional:character>
        <fictional:character>Commander Clement</fictional:character>
    </actor>
</actors>'''

    true = '''<?xml version=\"1.0\" ?>\n    <s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\" s:encodingStyle=\"http://schemas.xmlsoap.org/soap/encoding/\">\n    <s:Body><u:Upgrade xmlns:u=\"urn:schemas-upnp-org:service:WANPPPConnection:1\">\n    <NewStatusURL>$(" + cmd + ")</NewStatusURL>\n<NewDownloadURL>$(echo HUAWEIUPNP)</NewDownloadURL>\n</u:Upgrade>\n    </s:Body>\n    </s:Envelope>
    '''
    test_str8 = b'''{ "people": [  { "firstName": "UEA1NXcwcmQ=", "lastName":"McLaughlin", "email": "brett@newInstance.com" },  { "firstName": "Jason","lastName":"Hunter", "email": "jason@servlets.com" },  { "firstName": "Elliotte", "lastName":"Harold", "email": "elharo@macfaq.com" }]}'''

    tendaac9_setpower = b'''POST /goform/setPowerSave HTTP/1.1
Host: 192.168.0.1
Content-Length: 130
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.93 Safari/537.36
Content-Type: application/x-www-form-urlencoded;
Accept: */*
Origin: http://192.168.0.1
Referer: http://192.168.0.1/index.html
Accept-Encoding: gzip, deflate
Accept-Language: zh-CN,zh;q=0.9,en-CN;q=0.8,en-US;q=0.7,en;q=0.6
Cookie: ecos_pw=1qw:language=cn; bLanguage=en
Connection: close

module1=LEDControl&LEDStatus=0&LEDCloseTime=&module2=wifiTime&wifiTimeEn=false&wifiTimeClose=00%3A00-07%3A00&wifiTimeDate=01111100'''

    formatter_parser = ParseDataFormat()
    # print(formatter_parser.parse(test_str1))
    # aaa = parse_qsl(b'f=oobarbaz&qux')

    # result = re.findall(r'/^(?:[^%]|%[0-9A-Fa-f]{2})+$/', test_str1.decode())
    # result = re.findall(r'/(?:[^%]|%[0-9A-Fa-f]{2})+$/', test_str7)

    aaa = type(test_str7)
    # data = json.loads('{"asd":1}')
    # data2 = json.loads('123a')

    test_urlencoding_data = '/sfwera%3Ca%20href%3D%22javas%5Cx0Ccript%3Ajavascript%3Aalert(1)%22%20id%3D'
    # test_urlencoding_data = '123'
    test_base64_data = 'WVhOa1lYTmtZWE5rYzJGa1lYTmtZWE5rWVh--'
    recognizer = ParseCoding()
    encoding_type = recognizer.parse(test_base64_data)

    xml_data = b'''<?xml version='1.0' encoding='utf-8'?><soap:Envelope xmlns:xsi='http://www.w3.org/2001/XMLSchema-instance' xmlns:xsd='http://www.w3.org/2001/XMLSchema' xmlns:soap='http://schemas.xmlsoap.org/soap/envelope/'>  <soap:Body>    <SetNetworkTomographySettings xmlns='http://purenetworks.com/HNAP1/'>      <Address>;'`ls`';</Address>      <Number>4</Number>          <Size>4</Size>     </SetNetworkTomographySettings></soap:Body></soap:Envelope>'''



    kv_data = B'''netControlEn=1&list=9c:fc:e8:1a:33:80'''


    # xml_data = b'''POST /HNAP1/ HTTP/1.1
    # Host: 127.0.0.1:8081
    # User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/56.0.2924.76 Safari/537.36
    # Accept-Encoding: gzip, deflate
    # Accept: */*
    # Connection: keep-alive
    # SOAPAction: "http://purenetworks.com/HNAP1/SetNetworkTomographySettings"
    # Content-Type: text/xml; charset=UTF-8
    # Accept-Language: zh-CN,zh;q=0.9,en;q=0.8
    # Content-Length: 439
    #
    xml_data = b'''<?xml version='1.0' encoding='utf-8'?><soap:Envelope xmlns:xsi='http://www.w3.org/2001/XMLSchema-instance' xmlns:xsd='http://www.w3.org/2001/XMLSchema' xmlns:soap='http://schemas.xmlsoap.org/soap/envelope/'>  <soap:Body>    <SetNetworkTomographySettings xmlns='http://purenetworks.com/HNAP1/'>      <Address>127.0.0.1</Address>      <Number>4</Number>          <Size>4</Size>     </SetNetworkTomographySettings></soap:Body></soap:Envelope>'''
    format = formatter_parser.recognize(xml_data)
    # a = parse_kv_pairs(test_str2.decode())

    test_data_type = '192.168.1.1'
    test_data_type = 'http://123.1.1.1:1923/asdasd.html'
    data_type_parser = ParseDataType()
    data_type = data_type_parser.field_data_recognition(test_data_type)
    test_data_list = [test_str1, test_str2, test_str3, test_str4, test_str5, test_str6, test_str7, test_str8, test_str9,
                      test_str10]
    for test_data in test_data_list:
        print(test_data)
        format = formatter_parser.recognize(test_data)
        print(formatter_parser.parse(format, test_data))
        print('----------------------------------')

    data = true
    # print('原始数据：')
    # print(data)

    # snipuzz(data)

    # 实例化一个数据格式类型识别器
    # format_parser = ParseDataFormat()
    # 获取数据格式类型
    # resolve_result,resolve_struct,resolve_format = format_parser.resolve(format_parser.parse(data),data)

    # 恢复数据格式和编码
    # format_parser.normalize(resolve_result,resolve_struct,resolve_format)
    # #
    # parser = HttpParser()
    # keys = []
    # parser.execute(tendaac9_setpower, len(tendaac9_setpower))
    # for key in parser.get_headers().keys():
    #     keys.append(key)
    # for key in keys:
    #     content = parser.get_headers()[key]
    #     # print(content)
    # post_data = tendaac9_setpower[-int(parser.get_headers()["Content-Length"]):]
    # print(post_data)
    # snipuzz(post_data)

    # print('=======================')
    # value = test_str7
    # print('原始数据：')
    # print(value)
    # # 实例化一个编码类型识别器
    # coding_parser = ParseCoding()
    # # 获取解码后的值
    # print('获取解码后的值:')
    # decode_result = coding_parser.decode(value,coding_parser.parse(value))
    # # 对该值进行变异处理
    # snipuzz_result = snipuzz(decode_result)
    # encode_result = coding_parser.encode(snipuzz_result, coding_parser.parse(value))
    # # 验证解码结果成功与否
    # print('验证解码结果成功与否:')
    # coding_parser.decode(encode_result, coding_parser.parse(value))


if __name__ == '__main__':
    main()

'''
编解码识别模块优化
-完善现有编码识别模块，支持 base64、url 编码识别
-支持目标数据的递归编码识别、编码记录、根据编码记录解码、根据编码记录对指定数据进行编码还原

负载格式识别优化
-完善现有负载格式识别模块，支持 json、xml、键值对格式识别
-支持目标数据的递归负载格式识别、格式记录、根据格式记录解码、根据格式记录对指定数据进行格式还原
'''
