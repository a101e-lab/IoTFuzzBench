import subprocess
import os
import time


# 流量监听函数
# 默认监听ens33网卡，默认保存为'123.pacp'文件
def begin_traffic_monitoring(monitor_interface='ens33', output_monitor_pcap_file='123.pcap'):
    # Monitor the flow of the specified interface

    # Clear cache file
    if (os.path.exists(output_monitor_pcap_file)):
        os.system('rm ' + output_monitor_pcap_file)

    # Begin moniter, only monitor port 80 to reduce traffic file size
    print('[+] Begin monitoring!')
    pro = subprocess.Popen(('tcpdump', '-i', monitor_interface, 'tcp port 80', '-w', output_monitor_pcap_file),
                           shell=False,
                           stdin=None, stdout=None, stderr=None, close_fds=True, )
    return pro


# 结束流量监听
def end_traffic_monitoring(pro):
    # os.killpg(os.getpgid(pro.pid), signal.SIGTERM)  # Send the signal to all the process groups
    pro.terminate()


def traffic_monitoring(network_interface, monitor_pcap_file):
    # 子线程监听流量数据包
    # 需要将这里监听的网卡改成想监听的网卡，默认监听的是lo网卡
    pro = begin_traffic_monitoring(network_interface, monitor_pcap_file)
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        end_traffic_monitoring(pro)
