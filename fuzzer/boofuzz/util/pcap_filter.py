import os


# tshark对数据包进行处理
# v0.1版本仅处理POST包
def pcap_filter(input_file_name='test2.pcap',
                filter_string='http.request and http.accept contains \\"text/html\\" or http.request.method == \\"POST\\"'):
    # Only use http text packet

    output_file_name = input_file_name + '_filter.pcap'
    # check_call(['tshark','-r',input_file_name,'-Y','"'+filter_string+'"','-w','output_file_name'], stdout=DEVNULL, stderr=STDOUT)
    # tshark语句
    # -r:读取本地文件
    # -Y:过滤器的语法
    # -w:设置raw数据的输出文件
    command = 'tshark -r ' + input_file_name + ' -Y "' + filter_string + '" -w ' + output_file_name + '> /dev/null 2>&1'
    os.system(command)
    return output_file_name
