from asyncore import write
import subprocess
import os
import yaml
from os import walk
import importlib.util
import sys
import time
import socket
from multiprocessing import Pool, TimeoutError
import shutil
import docker

def yml_read(yml_file_path):
    with open(yml_file_path, "r") as stream:
        try:
            file_content = yaml.safe_load(stream)
        except yaml.YAMLError as exc:
            print(exc)
    return file_content


def build_image(dockerfile_path, image_name, context_path, firmware_path=''):
    if (firmware_path == ''):
        command = ['docker', 'build', '-f', dockerfile_path,
                   '--tag', image_name, context_path]
    else:
        command = ['docker', 'build', '--build-arg', 'FIRMWARE_PATH=' +
                   firmware_path, '-f', dockerfile_path, '--tag', image_name, context_path]
    cpu_options = ['--cpu-period', '100000', '--cpu-quota', '100000']
    command.extend(cpu_options)
    proc = subprocess.run(command)
    return proc


def build_container(container_name, env_path='', share_dir='',copy_file = ''):
    volume_name = 'vol_'+container_name
    delete_volume(volume_name)

    if len(env_path) == 0:
        command = ['docker', 'create', '-it', '-d', '--privileged',
                   '-P', '--mount', 'source='+volume_name+',target='+share_dir, '--name', container_name, container_name]
    else:
        command = ['docker', 'create',  '--env-file', env_path, '-it', '--privileged', '-P', '--mount', 'source=vol_'+container_name +
                   ',target='+share_dir, '--name', container_name, container_name]

    proc = subprocess.run(command)

    if(copy_file!=''):
        command = ['docker', 'cp', copy_file,container_name+':/']
        proc = subprocess.run(command)

    command = ['docker', 'start', container_name]
    proc = subprocess.run(command)
    return proc


def delete_container(container_name):
    container_down_flag = 0 
    container_exist_flag = 0
    command = 'docker ps -a --filter "name=' + \
            container_name+'"'
    result = subprocess.run(
        command, stdout=subprocess.PIPE, text=True, shell=True)
    result = result.stdout
    if (container_name in result):
        container_exist_flag = 1

    command = 'docker ps -a --filter "status=exited" --filter "name=' + \
            container_name+'" | awk "NR==2"'
    result = subprocess.run(
        command, stdout=subprocess.PIPE, text=True, shell=True)

    time.sleep(1)
    result = result.stdout

    if (container_name in result):
        container_down_flag = 1

    if(container_exist_flag == 1 and container_down_flag == 0):
        command = 'docker rm $(docker stop $(docker ps -a -q --filter="name=' + \
            container_name+'" --format="{{.ID}}"))'

        proc = subprocess.run(command, shell=True)
        return proc
    elif(container_exist_flag == 1 and container_down_flag == 1):

        command = 'docker rm $(docker ps -a -q --filter="name=' + \
            container_name+'" --format="{{.ID}}")'
        print(command)
        proc = subprocess.run(command, shell=True)
        return proc
    elif(container_exist_flag == 0):

        pass
        return 0

def delete_volume(volume_name):
    command = 'docker volume rm '+volume_name
    proc = subprocess.run(command, shell=True)
    return proc


def container_server_monitor(container_name, docker_forward_port, seed_content,moniter_http_flag=0):

    MONITORING_TIME = 10
    MAX_TRY = 4

    success_log_name = os.path.join('logs', container_name+'_success.log')
    fail_log_name = os.path.join('logs', container_name+'_fail.log')

    if os.path.exists(success_log_name):
        os.remove(success_log_name)
    if os.path.exists(fail_log_name):
        os.remove(fail_log_name)

    
    while (1):
        for count in range(MAX_TRY):
            if(moniter_http_flag == 0):
                try:
                    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                        s.settimeout(40)
                        s.connect(('0.0.0.0', docker_forward_port))
                        s.sendall(seed_content.encode())
                        data = s.recv(1024)
                        print('[+] Monitoring data: ', data)
                        if (data != b''):
                            time.sleep(MONITORING_TIME)
                            with open(success_log_name, 'w') as f1:
                                f1.write('Normal Service')
                            break
                        else:
                            time.sleep(MONITORING_TIME)
                            if (count == MAX_TRY-1):
                                print('[+] Server Down')
                                with open(fail_log_name, 'w') as f1:
                                    f1.write('Server Down')
                                return 0
                except:
                    pass
            elif(moniter_http_flag == 1):
                command = 'curl -s 0.0.0.0:'+str(docker_forward_port)+'/index.html'
                data = b''
                try:
                    data = subprocess.check_output(command, shell=True)
                except subprocess.CalledProcessError as grepexc:
                    pass
                print('[+] Monitoring data: ', data)
                if (data != b''):
                    time.sleep(MONITORING_TIME)

                    with open(success_log_name, 'w') as f1:
                        f1.write('Normal Service')
                    break
                else:
                    time.sleep(MONITORING_TIME)
                    if (count == MAX_TRY-1):
                        print('[+] Server Down')

                        with open(fail_log_name, 'w') as f1:
                            f1.write('Server Down')
                        return 0
            if(count == MAX_TRY-1):
                print('[+] Server Error!')

                with open(fail_log_name, 'w') as f1:
                    f1.write('Server Down')
                return -1

    return 0


def re_benchmark_monitor(docker_forward_port,test_seed):
    monitor_flag = 0


    SLEEP_TIME = 20
    WAIT_NUM = 20
    CHANGE_MONITOR_PERCENT = 2
    moniter_http_flag = 0
    for i in range(WAIT_NUM):
        print(i)
        if i <= WAIT_NUM/CHANGE_MONITOR_PERCENT:

            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.settimeout(60)
                    s.connect(('0.0.0.0', docker_forward_port))

                    print(test_seed)
                    s.sendall(test_seed.encode())

                    response = b""
                    while True:
                        chunk = s.recv(4096)
                        if len(chunk) == 0:     
                            break
                        response = response + chunk;

                    data = response
                    print(data)
                    if (data != b''):
                        monitor_flag = 1
                        break
                time.sleep(SLEEP_TIME)
            except:
                print('Timeout error')
                pass
        elif i == WAIT_NUM-1:
            monitor_flag = 0
            print('Benchmark server not start')
            break
        elif i > WAIT_NUM/CHANGE_MONITOR_PERCENT:
            moniter_http_flag = 1
            command = 'curl -s 0.0.0.0:'+str(docker_forward_port)+'/index.html'
            data = b''
            try:
                data = subprocess.check_output(command, shell=True)
            except subprocess.CalledProcessError as grepexc:
                pass
            print(data)
            if (data != b''):
                monitor_flag = 1
                break
            time.sleep(SLEEP_TIME)
    return monitor_flag

def fuzz_job(fuzzer_name,fuzzer_path,benchmark_name,benchmark_path,seed_name,result_base_dir = '../results/',MAX_WAIT_COUNT = 60):

    seed_name_lower = seed_name.lower()
    benchmark_env_dir = os.path.join(benchmark_path, 'env/')
    if not os.path.exists(benchmark_env_dir):
        os.mkdir(benchmark_env_dir)
    benchmark_env_path = os.path.join(benchmark_env_dir,benchmark_name+'_for_'+fuzzer_name+'_for_'+seed_name_lower+'.env')
    benchmark_dockerfile_path = os.path.join(benchmark_path, 'Dockerfile')
    benchmark_context_path = benchmark_path
    
    benchmark_container_name = benchmark_name+'_for_'+fuzzer_name+'_for_'+seed_name_lower
    
    benchmark_container_name = benchmark_container_name.lower()
    benchmark_image_name = benchmark_container_name.lower()
    
    benchmark_config_file_content = yml_read(
        os.path.join(benchmark_path, 'benchmark.yml'))
    
    remote_ip_addr = benchmark_config_file_content['ip_addr']
    remote_port = benchmark_config_file_content['port']
    if('interface' in benchmark_config_file_content):
        benchmark_interface = benchmark_config_file_content['interface']
    else:
        benchmark_interface = 'tap'
    benchmark_firmware_dir_path = os.path.join(benchmark_path, 'firmware')
    for dirpath, dirnames, filenames in walk(benchmark_firmware_dir_path):
        firmware_path = filenames[0]
        break
    firmware_path = 'firmware/'+firmware_path
    login_message_flag = False
    replay_login_message_file = ''
    replay_login_message_file_path = ''
    if('replay_login_message' in benchmark_config_file_content):
        login_message_flag = benchmark_config_file_content['replay_login_message']
        if(login_message_flag == True):
            replay_login_message_file =  benchmark_config_file_content['replay_login_message_file']
            replay_login_message_file_path = os.path.join(benchmark_path,replay_login_message_file)



    fuzzer_env_dir = os.path.join(fuzzer_path, 'env/')
    if not os.path.exists(fuzzer_env_dir):
        os.mkdir(fuzzer_env_dir)
    fuzzer_env_path = os.path.join(
        fuzzer_env_dir, benchmark_name+'_for_'+fuzzer_name+'_for_'+seed_name_lower+'.env')
    fuzzer_dockerfile_path = os.path.join(fuzzer_path, 'Dockerfile')
    fuzzer_context_path = fuzzer_path
    fuzzer_container_name = fuzzer_name+'_for_'+benchmark_name+'_for_'+seed_name_lower
    fuzzer_container_name = fuzzer_container_name.lower()
    fuzzer_image_name = fuzzer_container_name.lower()

    
    seed_path_list = []
    seed_path = os.path.join(benchmark_path, 'test_seed')
    for dirpath, dirnames, filenames in walk(seed_path):
        seed_path_list.extend(filenames)
        break

    
    if(seed_name not in seed_path_list):
        
        print('[+] Seed file not found!')
        exit(0)
    else:
        
        print('[+] Building the benchmark container...')
       
        proc = build_image(benchmark_dockerfile_path,
                        benchmark_image_name, benchmark_context_path, firmware_path)

        
        delete_container(benchmark_container_name)
        
        
        env_content = ''
        with open(benchmark_env_path, 'w') as f1:
            env_content += 'CONTAINER_NAME='+benchmark_container_name+'\n'
            env_content += 'REMOTE_IP='+remote_ip_addr+'\n'
            env_content += 'REMOTE_PORT='+str(remote_port)+'\n'
            env_content += 'FIRMWARE_PATH='+firmware_path+'\n'
            f1.write(env_content)

        
        share_dir = '/pcap'
        build_container(benchmark_container_name, benchmark_env_path, share_dir)

        
        command = '''docker port '''+benchmark_container_name+''' 80| awk '{ if(match($0,"0.0.0.0:")) { print substr($0,RSTART+RLENGTH) }}'
        '''
        docker_forward_port = subprocess.check_output(command, shell=True)
        docker_forward_port = docker_forward_port.decode().replace('\n', '')
        docker_forward_port = int(docker_forward_port)

        time.sleep(2)



        print('[+] Updating the seed...')

        with open(os.path.join(seed_path, seed_name)) as f1:
            seed_content = f1.read()

        updated_seed = seed_content
        test_seed = seed_content
        

        spec = importlib.util.spec_from_file_location(
            "update_seed", os.path.join(benchmark_path, 'update_seed.py'))
        update_seed = importlib.util.module_from_spec(spec)
        sys.modules["update_seed"] = update_seed
        spec.loader.exec_module(update_seed)


        SLEEP_TIME = 20
        WAIT_NUM = 50
        CHANGE_MONITOR_PERCENT = 2
        moniter_http_flag = 0
        for i in range(WAIT_NUM):
            print(i)
            if i <= WAIT_NUM/CHANGE_MONITOR_PERCENT:

                try:
                    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                        s.settimeout(60)
                        s.connect(('0.0.0.0', docker_forward_port))

                        print(test_seed)
                        s.sendall(test_seed.encode())

                        response = b""
                        while True:
                            chunk = s.recv(4096)
                            if len(chunk) == 0:     
                                break
                            response = response + chunk

                        data = response
                        print(data)
                        if (data != b''):
                            break
                    time.sleep(SLEEP_TIME)
                except:
                    print('Timeout error')
                    pass
            elif i == WAIT_NUM-1:
                print('Benchmark server not start')
                if(remote_port == 1900 or remote_port == 49152):
                    break
                exit(-1)
            elif i > WAIT_NUM/CHANGE_MONITOR_PERCENT:
                moniter_http_flag = 1
                command = 'curl -s 0.0.0.0:'+str(docker_forward_port)+'/index.html'
                data = b''
                try:
                    data = subprocess.check_output(command, shell=True)
                except subprocess.CalledProcessError as grepexc:

                    pass
                print(data)
                if (data != b''):
                    break
                time.sleep(SLEEP_TIME)
                


        
        if('tap' in benchmark_interface):
            command = '''docker exec -it '''+benchmark_container_name + \
                ''' /bin/bash -c "tap_name=\\$(echo \\$(ip link show |awk '{ if(match(\\$0,\\"tap\\")) { print substr(\\$0,4,6) }}') | awk '{print \\$1}') && tmux new -s \\"capture_before_pcap\\" -d \\"for i in {1..10} ;do tcpdump -i \\$tap_name -s 0 -U -w /pcap/before.pcap; echo $i; echo 'restart'; sleep 10s ;done\\""'''
        elif(benchmark_interface == 'br0'):
            command = '''docker exec -it '''+benchmark_container_name + \
                ''' /bin/bash -c "tap_name=br0 && tmux new -s \\"capture_before_pcap\\" -d \\"for i in {1..10} ;do tcpdump -i \\$tap_name -s 0 -U -w /pcap/before.pcap; echo $i; echo 'restart'; sleep 10s ;done\\""'''
        elif(benchmark_interface == 'eth0'):
            command = '''docker exec -it '''+benchmark_container_name + \
                ''' /bin/bash -c "tap_name=eth0 && tmux new -s \\"capture_before_pcap\\" -d \\"for i in {1..10} ;do tcpdump -i \\$tap_name -s 0 -U -w /pcap/before.pcap; echo $i; echo 'restart'; sleep 10s ;done\\""'''
        
        proc = subprocess.run(command, shell=True)
        
        time.sleep(2)

        
        updated_seed = update_seed.update_seed(
            seed_content, '0.0.0.0', docker_forward_port)
        print('[+] updated_seed: \n' + updated_seed)
        
        time.sleep(3)

        
        command = 'docker exec -it '+benchmark_container_name + \
            ' /bin/bash -c "tmux send-keys -t capture_before_pcap C-c && tmux kill-session -t capture_before_pcap"'
        proc = subprocess.run(command, shell=True)




        
        print('[+] Starting the fuzzing packet capture process...')
        
        
        if('tap' in benchmark_interface):
            command = '''docker exec -it '''+benchmark_container_name + \
                ''' /bin/bash -c "tap_name=\\$(echo \\$(ip link show |awk '{ if(match(\\$0,\\"tap\\")) { print substr(\\$0,4,6) }}') | awk '{print \\$1}') && tmux new -s \\"capture_fuzz_pcap\\" -d \\"for i in {1..10} ;do tcpdump -i \\$tap_name -s 0 -U -w /pcap/fuzz.pcap; echo $i; echo 'restart'; sleep 10s ;done\\""'''
        elif(benchmark_interface == 'br0'):
            command = '''docker exec -it '''+benchmark_container_name + \
                ''' /bin/bash -c "tap_name=br0 && tmux new -s \\"capture_fuzz_pcap\\" -d \\"for i in {1..10} ;do tcpdump -i \\$tap_name -s 0 -U -w /pcap/fuzz.pcap; echo $i; echo 'restart'; sleep 10s ;done\\""'''
        elif(benchmark_interface == 'eth0'):
            command = '''docker exec -it '''+benchmark_container_name + \
                ''' /bin/bash -c "tap_name=eth0 && tmux new -s \\"capture_fuzz_pcap\\" -d \\"for i in {1..10} ;do tcpdump -i \\$tap_name -s 0 -U -w /pcap/fuzz.pcap; echo $i; echo 'restart'; sleep 10s ;done\\""'''
        print(command)
        proc = subprocess.run(command, shell=True)
       
        time.sleep(2)


        
        print('[+] Building the fuzzing container...')
        
        updated_seed_dir = os.path.join(fuzzer_path, 'updated_seed')
        if not os.path.exists(updated_seed_dir):
            os.mkdir(updated_seed_dir)
        update_seed_file_name = 'updated_'+benchmark_container_name+'_'+seed_name + '.seed'
        update_seed_file = os.path.join(
            updated_seed_dir, update_seed_file_name)
        with open(update_seed_file, 'w') as f1:
            f1.write(updated_seed)

        
        command = '''docker inspect -f '{{range.NetworkSettings.Networks}}{{.IPAddress}}{{end}}' ''' + \
            benchmark_container_name
        
        result = subprocess.run(
            command, stdout=subprocess.PIPE, text=True, shell=True)
        

        benchmark_container_ip = result.stdout.replace('\n', '')
        benchmark_container_port = 80

        
        
        if fuzzer_name == 'mslfuzzer':
            share_dir = '/mslfuzzer/logs'
            fuzz_log_dir = benchmark_container_name
            fuzz_log_name = benchmark_container_name+'_'+seed_name+'.log'

            env_content = ''
            with open(fuzzer_env_path, 'w') as f1:
                env_content += 'FUZZ_IP='+benchmark_container_ip+'\n'
                env_content += 'FUZZ_PORT='+str(benchmark_container_port)+'\n'
                env_content += 'FUZZ_SEED=' + \
                    os.path.join('updated_seed', update_seed_file_name)+'\n'
                env_content += 'LOG_DIR='+fuzz_log_dir+'\n'
                env_content += 'LOG_FILE='+fuzz_log_name+'\n'
                if(replay_login_message_file!=''):
                    env_content += 'PRE_LOGIN_FILE=/'+replay_login_message_file+'\n'
                f1.write(env_content)
        elif fuzzer_name == 'mutiny':
            share_dir = '/mutiny/logs'
            fuzz_protocol = 'tcp'

            fuzzer_template_path = os.path.join(fuzzer_path,'fuzzer_template.fuzzer')
            update_fuzzer_template_file_name = 'updated_'+benchmark_container_name + '.fuzzer'
            update_fuzzer_template_file_path = os.path.join(updated_seed_dir,update_fuzzer_template_file_name)

            byte_str_updated_seed = str(updated_seed.encode())

            with open(fuzzer_template_path, 'r') as f1:
                fuzzer_template_content = f1.read()
                fuzzer_template_content = fuzzer_template_content.replace('proto tcp','proto '+fuzz_protocol)
                fuzzer_template_content = fuzzer_template_content.replace('port 80','port '+str(benchmark_container_port))
                fuzzer_template_content = fuzzer_template_content.replace("outbound fuzz 'GET'","outbound fuzz "+byte_str_updated_seed[1:])
            with open(update_fuzzer_template_file_path,'w') as f1:
                f1.write(fuzzer_template_content)


            env_content = ''
            with open(fuzzer_env_path, 'w') as f1:
                env_content += 'FUZZ_IP='+benchmark_container_ip+'\n'
                env_content += 'FUZZ_PORT='+str(benchmark_container_port)+'\n'
                env_content += 'FUZZER_FILE='+os.path.join('updated_seed',update_fuzzer_template_file_name)+'\n'
                if(replay_login_message_file!=''):
                    env_content += 'PRE_LOGIN_FILE=/'+replay_login_message_file+'\n'
                f1.write(env_content)

        elif fuzzer_name == 'boofuzz_default' or fuzzer_name == 'boofuzz_byte' or fuzzer_name == 'boofuzz_reversal':
            share_dir = '/pdfuzzergen/templates_created'
            fuzz_protocol = 'tcp'
            if(fuzzer_name == 'boofuzz_default'):
                fuzz_policy = 'boo_default'
            elif(fuzzer_name == 'boofuzz_byte'):
                fuzz_policy = 'boo_byte'
            elif(fuzzer_name == 'boofuzz_reversal'):
                fuzz_policy = 'boo_reversal'
            else:
                print('Fuzz policy not found')
                exit(-1)
                fuzz_policy = 'pdfuzzergen'

            env_content = ''
            with open(fuzzer_env_path, 'w') as f1:
                env_content += 'FUZZ_IP='+benchmark_container_ip+'\n'
                env_content += 'FUZZ_PORT='+str(benchmark_container_port)+'\n'
                env_content += 'FUZZ_POLICY='+fuzz_policy+'\n'
                env_content += 'SEED_FILE='+os.path.join('updated_seed',update_seed_file_name)+'\n'
                if(replay_login_message_file!=''):
                    env_content += 'PRE_LOGIN_FILE=/'+replay_login_message_file+'\n'
                f1.write(env_content)
        elif fuzzer_name == 'snipuzz':
            share_dir = '/snipuzz/logs'
            env_content = ''
            with open(fuzzer_env_path, 'w') as f1:
                env_content += 'FUZZ_IP='+benchmark_container_ip+'\n'
                env_content += 'FUZZ_PORT='+str(benchmark_container_port)+'\n'
                env_content += 'FUZZ_SEED=' + \
                    os.path.join('updated_seed', update_seed_file_name)+'\n'
                if(replay_login_message_file!=''):
                    env_content += 'PRE_LOGIN_FILE=/'+replay_login_message_file+'\n'
                f1.write(env_content)
        elif fuzzer_name == 'fuzzotron':
            share_dir = '/fuzzotron/crashes'
            fuzz_log_dir = benchmark_container_name
            fuzz_log_name = benchmark_container_name+'_'+seed_name+'.log'

            env_content = ''
            with open(fuzzer_env_path, 'w') as f1:
                env_content += 'FUZZ_IP='+benchmark_container_ip+'\n'
                env_content += 'FUZZ_PORT='+str(benchmark_container_port)+'\n'
                env_content += 'FUZZ_SEED=' + \
                    os.path.join('updated_seed', update_seed_file_name)+'\n'
                if(replay_login_message_file!=''):
                    env_content += 'PRE_LOGIN_FILE=/'+replay_login_message_file+'\n'
                f1.write(env_content)
        elif fuzzer_name == 'tReqs':
            share_dir = '/t-reqs/code/logs'
            fuzz_protocol = 'tcp'


            fuzzer_template_path = os.path.join(fuzzer_path,'template_config')
            update_fuzzer_template_file_name = 'updated_'+benchmark_container_name + '_config'
            update_fuzzer_template_file_path = os.path.join(updated_seed_dir,update_fuzzer_template_file_name)

            byte_str_updated_seed = str(updated_seed.encode())

            if('\r\n' in updated_seed):
                space_string = '\r\n'
            else:
                space_string = '\n'
            
            updated_seed = updated_seed.replace(space_string,'\r\n')
            print(updated_seed)
            space_string = '\r\n'
            
            print(updated_seed.encode())

            with open(fuzzer_template_path, 'r') as f1:
                fuzzer_template_content = f1.read()

                fuzzer_template_content = fuzzer_template_content.replace('replace_urls','http://'+benchmark_container_ip+':'+str(benchmark_container_port)+'/')

                fuzzer_template_content = fuzzer_template_content.replace('replace_hosts',benchmark_container_ip)

                fuzzer_template_content = fuzzer_template_content.replace('replace_uri',updated_seed[updated_seed.find(' ')+1:updated_seed.find('HTTP/')-1])

            
                fuzzer_template_content = fuzzer_template_content.replace('replace_base',str(updated_seed[updated_seed.find(space_string)+2:updated_seed.find(space_string*2)].encode())[2:-1])


                fuzzer_template_content = fuzzer_template_content.replace('replace_rest',str(updated_seed[updated_seed.find(space_string*2):].encode())[2:-1])
                
            with open(update_fuzzer_template_file_path,'w') as f1:
                f1.write(fuzzer_template_content)


            env_content = ''
            with open(fuzzer_env_path, 'w') as f1:
                env_content += 'FUZZ_IP='+benchmark_container_ip+'\n'
                env_content += 'FUZZ_PORT='+str(benchmark_container_port)+'\n'
                env_content += 'FUZZER_FILE='+update_fuzzer_template_file_name+'\n'
                if(replay_login_message_file!=''):
                    env_content += 'PRE_LOGIN_FILE=/'+replay_login_message_file+'\n'
                f1.write(env_content)


        build_image(fuzzer_dockerfile_path,
                    fuzzer_image_name, fuzzer_context_path)

        pool = Pool()
        if(moniter_http_flag == 1):
            res = pool.apply_async(container_server_monitor,
                            (benchmark_container_name, docker_forward_port, updated_seed,moniter_http_flag,))
        else:
            res = pool.apply_async(container_server_monitor,
                            (benchmark_container_name, docker_forward_port, updated_seed,))
        pool.close()


        delete_container(fuzzer_container_name)

        
        build_container(fuzzer_container_name, fuzzer_env_path, share_dir,replay_login_message_file_path)


        print('[+] Monitoring fuzzing...')
        FUZZER_SLEEP_TIME = 20
        MAX_WAIT_COUNT = 180

        exit_flag = 0

        benchmark_down_flag = 0
        fuzzer_end_flag = 0
        
   
        result_dir = os.path.join(
            result_base_dir, benchmark_name+'_'+fuzzer_name+'_'+seed_name)
        
        if not os.path.exists(result_dir):
            os.mkdir(result_dir)
        subfolders = [ f.name for f in os.scandir(result_dir) if f.is_dir() ]
        if(len(subfolders)==0):
            dir_id = str(0)
        else:
            for i in range(200):
                if(str(i) not in subfolders):
                    dir_id = str(i)
                    break
        result_dir = os.path.join(result_dir,dir_id)
        if not os.path.exists(result_dir):
            os.makedirs(result_dir)

        for count_num in range(MAX_WAIT_COUNT+1):
            
            command = 'docker ps -a --filter "status=exited" --filter "name=' + \
                fuzzer_container_name+'" | awk "NR==2"'
            result = subprocess.run(
                command, stdout=subprocess.PIPE, text=True, shell=True)
            
            result = result.stdout
            
            if (fuzzer_container_name in result):
                exit_flag = 1
                fuzzer_end_flag = 1
                print('[+] Fuzzer container down!')
            if(fuzzer_end_flag==1):
                
                time.sleep(180)
            else:
                
                command = 'docker stats --no-stream ' + fuzzer_container_name
                result = subprocess.run(
                    command, stdout=subprocess.PIPE, text=True, shell=True)
                
                result = result.stdout.split('\n')[1]
                print(result)
                cpu_memory_info_log_name = os.path.join(
                result_dir, fuzzer_container_name+'_cpu_memory.log')
                with open(cpu_memory_info_log_name,'a') as f1:
                    f1.write('\n'+result)
            
            fail_log_name = os.path.join(
                'logs', benchmark_container_name+'_fail.log')

            
            if(remote_port == 1900 or remote_port == 49152):
                break
            else:
                
                if (os.path.exists(fail_log_name)):
                    exit_flag = 1
                    benchmark_down_flag = 1
                    print('[+] Benchmark Server down!')

            
            if (exit_flag == 1 or count_num==MAX_WAIT_COUNT):
                
                print('[+] Ending the fuzzing process...')

                
                command = 'docker exec -it '+benchmark_container_name + \
                    ' /bin/bash -c "tmux send-keys -t capture_fuzz_pcap C-c && tmux kill-session -t capture_fuzz_pcap"'
                proc = subprocess.run(command, shell=True)


                
                delete_container(fuzzer_container_name)

               
                benchmark_volume_name = 'vol_'+benchmark_container_name
                delete_volume(benchmark_volume_name)
                src_pcap_dir = '/var/lib/docker/volumes/'+benchmark_volume_name+'/_data/'
                dst_pcap_dir = os.path.join(result_dir,'pcap')
                shutil.copytree(src_pcap_dir, dst_pcap_dir)
                
                fuzzer_volume_name = 'vol_'+fuzzer_container_name
                src_log_dir = '/var/lib/docker/volumes/'+fuzzer_volume_name+'/_data/'
                dst_log_dir = os.path.join(result_dir,'log')
                shutil.copytree(src_log_dir, dst_log_dir)

                time.sleep(120)

                re_monitor_flag = re_benchmark_monitor(docker_forward_port,test_seed)


                delete_container(benchmark_container_name)
                delete_volume(fuzzer_volume_name)

                
                result_log_path = os.path.join(result_dir,'fuzz_result.log')
                with open(result_log_path,'w') as f1:
                    if(benchmark_down_flag == 1 and re_monitor_flag == 0 ):
                        f1.write('Benchmark Server down!')
                    elif(benchmark_down_flag == 1 and re_monitor_flag == 1 ):
                        f1.write('Benchmark Server Suffer DoS!')
                    elif(fuzzer_end_flag):
                        f1.write('Fuzzer end!')
                    else:
                        f1.write('Fuzzing time is over!')
                break
            else:

                time.sleep(FUZZER_SLEEP_TIME)

def main():
    fuzzer_name = 'fuzzotron'
    fuzzer_path = '../fuzzer/fuzzotron'
    benchmark_name = 'CVE-2020-XXXX'
    benchmark_path = '../benchmarks/CVE-2020-XXXX'
    seed_name = 'CVE-2020-XXXX'
    fuzz_job(fuzzer_name,fuzzer_path,benchmark_name,benchmark_path,seed_name)

if __name__ == '__main__':
    main()