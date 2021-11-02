# encoding='utf-8'
from data_check import http_check

try:
    import os, sys, pytest, allure, time, re, time
except Exception as err:
    print('导入CPython内置函数库失败!错误信息如下:')
    print(err)
    sys.exit(0)  # 避免程序继续运行造成的异常崩溃,友好退出程序

base_path = os.path.dirname(os.path.abspath(__file__))  # 获取当前项目文件夹
base_path = base_path.replace('\\', '/')
sys.path.insert(0, base_path)  # 将当前目录添加到系统环境变量,方便下面导入版本配置等文件
print(base_path)
try:
    from iso_tcp_large_file import index
    from iso_tcp_large_file import message
    from common import fun
    import common.ssh as c_ssh
except Exception as err:
    print(
        '导入基础函数库失败!请检查相关文件是否存在.\n文件位于: ' + str(base_path) + '/common/ 目录下.\n分别为:pcap.py  rabbitmq.py  ssh.py\n错误信息如下:')
    print(err)
    sys.exit(0)  # 避免程序继续运行造成的异常崩溃,友好退出程序
else:
    del sys.path[0]  # 及时删除导入的环境变量,避免重复导入造成的异常错误
# import index
# del sys.path[0]
# dir_dir_path=os.path.abspath(os.path.join(os.getcwd()))
# sys.path.append(os.getcwd())

from common import baseinfo
from common import clr_env
from common.rabbitmq import *

datatime = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(time.time()))

FrontDomain = baseinfo.BG8010FrontDomain
BackDomain = baseinfo.BG8010BackDomain
proxy_ip = baseinfo.BG8010FrontOpeIp
rbmExc = baseinfo.rbmExc
BG8010ServerPwd = baseinfo.BG8010ServerPwd
ssh_proxy_port = baseinfo.ssh_proxy_port


class Test_iso_tcp_large_file():
    #
    # def setup_method(self):
    #     clr_env.data_check_setup_met(dut='FrontDut')
    #     clr_env.data_check_setup_met(dut='BackDut')
    #
    # def teardown_method(self):
    #     clr_env.iso_setup_class(dut='FrontDut')
    #     clr_env.iso_setup_class(dut='BackDut')

    def setup_class(self):
        # 获取参数
        fun.ssh_FrontDut.connect()
        fun.ssh_BackDut.connect()
        fun.ssh_BG8010Client.connect()
        fun.ssh_BG8010Server.connect()
        self.case1_step1 = index.case1_step1
        self.case1_step11 = index.case1_step11
        self.case2_step1 = index.case2_step1
        self.case2_step11 = index.case2_step11
        self.case3_step1 = index.case3_step1
        self.case3_step11 = index.case3_step11
        self.downfile_url = index.downfile_url
        self.downlocalPath = index.downlocalPath

        clr_env.iso_setup_class(dut='FrontDut')
        clr_env.iso_setup_class(dut='BackDut')

    """
    上传下载10G大文件会超时导致失败，1G和100M也是这样
    """
    # @pytest.mark.skip(reseason="skip")
    @allure.feature('验证隔离下的tcp策略（http）下载一个10M大小的文件')
    def test_iso_tcp_large_file_a1(self):

        # 下发配置
        fun.send(rbmExc, message.addtcp_front['AddCustomAppPolicy'], FrontDomain, base_path)
        fun.send(rbmExc, message.addtcp_back['AddCustomAppPolicy'], BackDomain, base_path)
        fun.wait_data('ps -ef |grep nginx', 'FrontDut', 'nginx: worker process')
        front_res = fun.nginx_worker('ps -ef |grep nginx', 'FrontDut', 'nginx: worker process', name='前置机nginx进程')
        assert front_res == 1
        fun.wait_data('ps -ef |grep nginx', 'BackDut', 'nginx: worker process')
        back_res = fun.nginx_worker('ps -ef |grep nginx', 'BackDut', 'nginx: worker process', name='后置机nginx进程')
        assert back_res == 1
        # 检查配置下发是否成功
        for key in self.case1_step1:
            re = fun.wait_data(self.case1_step1[key][0], 'FrontDut', self.case1_step1[key][1], '配置', 100)
            print(re)
            assert self.case1_step1[key][1] in re

        for key in self.case1_step11:
            re = fun.wait_data(self.case1_step11[key][0], 'FrontDut', self.case1_step11[key][1], '配置', 100)
            print(re)
            assert self.case1_step11[key][1] in re

        # 发送get请求，验证隔离下的http策略下载一个10M大小的文件
        print('下载的服务器地址为{}'.format(self.downfile_url))
        result = http_check.http_download(self.downfile_url, self.downlocalPath)
        assert result == 1

        # 检查下载目录下是否有文件生成，若有，则检查文件大小是否正常
        # 判断文件大小是否是10M
        print('self.downlocalPath: ', self.downlocalPath)
        file_size = os.path.getsize(self.downlocalPath)
        print('file_size1: ', file_size)
        file_size = file_size / float(1024 * 1024)  # 将单位转化为M
        print('file_size2: ', file_size)
        assert 9.0 <= file_size <= 11.0

        # 移除策略，清空环境
        fun.send(rbmExc, message.deltcp_front['DelCustomAppPolicy'], FrontDomain, base_path)
        fun.send(rbmExc, message.deltcp_back['DelCustomAppPolicy'], BackDomain, base_path)
        fun.wait_data('ps -ef |grep nginx', 'FrontDut', 'nginx: worker process')
        fdel_res = fun.nginx_worker('ps -ef |grep nginx', 'FrontDut', 'nginx: worker process', name='前置机nginx进程')
        assert fdel_res == 1
        fun.wait_data('ps -ef |grep nginx', 'BackDut', 'nginx: worker process')
        bdel_res = fun.nginx_worker('ps -ef |grep nginx', 'BackDut', 'nginx: worker process', name='后置机nginx进程')
        assert bdel_res == 1
        # 检查策略移除是否成功
        for key in self.case1_step1:
            re = fun.wait_data(self.case1_step1[key][0], 'FrontDut', self.case1_step1[key][1], '配置', 100, flag='不存在')
            print(re)
            assert self.case1_step1[key][1] not in re

    # @pytest.mark.skip(reseason="skip")
    @allure.feature('验证隔离下的tcp策略（ssh、scp）下载文件')
    def test_iso_tcp_large_file_a2(self):

        # 下发配置
        fun.send(rbmExc, message.addtcp_ssh_front['AddCustomAppPolicy'], FrontDomain, base_path)
        fun.send(rbmExc, message.addtcp_ssh_back['AddCustomAppPolicy'], BackDomain, base_path)
        fun.wait_data('ps -ef |grep nginx', 'FrontDut', 'nginx: worker process')
        front_res = fun.nginx_worker('ps -ef |grep nginx', 'FrontDut', 'nginx: worker process', name='前置机nginx进程')
        assert front_res == 1
        fun.wait_data('ps -ef |grep nginx', 'BackDut', 'nginx: worker process')
        back_res = fun.nginx_worker('ps -ef |grep nginx', 'BackDut', 'nginx: worker process', name='后置机nginx进程')
        assert back_res == 1
        # 检查配置下发是否成功
        for key in self.case2_step1:
            re = fun.wait_data(self.case2_step1[key][0], 'FrontDut', self.case2_step1[key][1], '配置', 100)
            print(re)
            assert self.case2_step1[key][1] in re

        for key in self.case2_step11:
            re = fun.wait_data(self.case2_step11[key][0], 'FrontDut', self.case2_step11[key][1], '配置', 100)
            print(re)
            assert self.case2_step11[key][1] in re

        # 在server的/opt/pkt/路径下创建一个10M大小的文件10M.txt
        fun.cmd('cd /opt/pkt && dd if=/dev/zero of=10M.txt bs=1M count=10', 'BG8010Server')
        time.sleep(10)

        # 检查服务端文件是否创建成功
        touch_file = fun.search('/opt/pkt', 'txt', 'BG8010Server')
        print('检查服务端/opt/pkt/目录下所有以txt结尾的文件列表为：{}'.format(touch_file))
        assert '10M.txt' in touch_file

        # 验证隔离下的tcp策略（ssh、scp）从客户端发送scp命令下载
        scp_cmd = f'sshpass -p {BG8010ServerPwd} scp -P {ssh_proxy_port} root@{proxy_ip}:/opt/pkt/10M.txt /opt/pkt/'
        print('scp下载的命令为：{}'.format(scp_cmd))
        fun.cmd(scp_cmd, 'BG8010Client')
        time.sleep(30)

        # 检查文件是否下载成功到客户端
        touch_file = fun.search('/opt/pkt', 'txt', 'BG8010Client')
        print('检查客户端/opt/pkt/目录下所有以txt结尾的文件列表为：{}'.format(touch_file))
        assert '10M.txt' in touch_file

        # 下载完成后，还原环境，清掉客户端下载的文件
        fun.cmd('rm -f /opt/pkt/10M.txt ', 'BG8010Client')
        check_file = fun.search('/opt/pkt', 'txt', 'BG8010Client')
        print('还原环境，10M.txt文件应该不在列表内，列表为{}'.format(check_file))

        # 移除策略，清空环境
        fun.send(rbmExc, message.deltcp_ssh_front['DelCustomAppPolicy'], FrontDomain, base_path)
        fun.send(rbmExc, message.deltcp_ssh_back['DelCustomAppPolicy'], BackDomain, base_path)
        fun.wait_data('ps -ef |grep nginx', 'FrontDut', 'nginx: worker process')
        fdel_res = fun.nginx_worker('ps -ef |grep nginx', 'FrontDut', 'nginx: worker process', name='前置机nginx进程')
        assert fdel_res == 1
        fun.wait_data('ps -ef |grep nginx', 'BackDut', 'nginx: worker process')
        bdel_res = fun.nginx_worker('ps -ef |grep nginx', 'BackDut', 'nginx: worker process', name='后置机nginx进程')
        assert bdel_res == 1
        # 检查策略移除是否成功
        for key in self.case2_step1:
            re = fun.wait_data(self.case2_step1[key][0], 'FrontDut', self.case2_step1[key][1], '配置', 100, flag='不存在')
            print(re)
            assert self.case2_step1[key][1] not in re

    # @pytest.mark.skip(reseason="skip")
    @allure.feature('验证隔离下的tcp策略（ssh、scp）上传文件')
    def test_iso_tcp_large_file_a3(self):

        # 下发配置
        fun.send(rbmExc, message.addtcp_ssh_front['AddCustomAppPolicy'], FrontDomain, base_path)
        fun.send(rbmExc, message.addtcp_ssh_back['AddCustomAppPolicy'], BackDomain, base_path)
        fun.wait_data('ps -ef |grep nginx', 'FrontDut', 'nginx: worker process')
        front_res = fun.nginx_worker('ps -ef |grep nginx', 'FrontDut', 'nginx: worker process', name='前置机nginx进程')
        assert front_res == 1
        fun.wait_data('ps -ef |grep nginx', 'BackDut', 'nginx: worker process')
        back_res = fun.nginx_worker('ps -ef |grep nginx', 'BackDut', 'nginx: worker process', name='后置机nginx进程')
        assert back_res == 1
        # 检查配置下发是否成功
        for key in self.case3_step1:
            re = fun.wait_data(self.case3_step1[key][0], 'FrontDut', self.case3_step1[key][1], '配置', 100)
            print(re)
            assert self.case3_step1[key][1] in re

        for key in self.case3_step11:
            re = fun.wait_data(self.case3_step11[key][0], 'FrontDut', self.case3_step11[key][1], '配置', 100)
            print(re)
            assert self.case3_step11[key][1] in re

        # 在客户端的/opt/pkt/路径下创建一个10M大小的文件10M.pdf
        fun.cmd('cd /opt/pkt && dd if=/dev/zero of=10M.pdf bs=1M count=1024', 'BG8010Client')
        time.sleep(10)

        # 检查客户端文件是否创建成功
        touch_file = fun.search('/opt/pkt', 'pdf', 'BG8010Client')
        print('检查客户端/opt/pkt/目录下所有以pdf结尾的文件列表为：{}'.format(touch_file))
        assert '10M.pdf' in touch_file

        # 验证隔离下的tcp策略（ssh、scp）从客户端发送scp命令上传
        scp_cmd = f'sshpass -p {BG8010ServerPwd} scp -P {ssh_proxy_port} /opt/pkt/10M.pdf root@{proxy_ip}:/opt/pkt/'
        print('scp上传的命令为：{}'.format(scp_cmd))
        fun.cmd(scp_cmd, 'BG8010Client')
        time.sleep(30)

        # 检查文件是否上传成功到服务端
        touch_file = fun.search('/opt/pkt', 'pdf', 'BG8010Server')
        print('检查服务端/opt/pkt/目录下所有以pdf结尾的文件列表为：{}'.format(touch_file))
        assert '10M.pdf' in touch_file

        # 下载完成后，还原环境，清掉上传到服务端的文件
        fun.cmd('rm -f /opt/pkt/10M.pdf ', 'BG8010Server')
        check_file = fun.search('/opt/pkt', 'pdf', 'BG8010Server')
        print('还原环境，10M.pdf文件应该不在列表内，列表为{}'.format(check_file))

        # 移除策略，清空环境
        fun.send(rbmExc, message.deltcp_ssh_front['DelCustomAppPolicy'], FrontDomain, base_path)
        fun.send(rbmExc, message.deltcp_ssh_back['DelCustomAppPolicy'], BackDomain, base_path)
        fun.wait_data('ps -ef |grep nginx', 'FrontDut', 'nginx: worker process')
        fdel_res = fun.nginx_worker('ps -ef |grep nginx', 'FrontDut', 'nginx: worker process', name='前置机nginx进程')
        assert fdel_res == 1
        fun.wait_data('ps -ef |grep nginx', 'BackDut', 'nginx: worker process')
        bdel_res = fun.nginx_worker('ps -ef |grep nginx', 'BackDut', 'nginx: worker process', name='后置机nginx进程')
        assert bdel_res == 1
        # 检查策略移除是否成功
        for key in self.case3_step1:
            re = fun.wait_data(self.case3_step1[key][0], 'FrontDut', self.case3_step1[key][1], '配置', 100, flag='不存在')
            print(re)
            assert self.case3_step1[key][1] not in re

    # def teardown_class(self):
    #     # 回收环境
    #     clr_env.iso_teardown_met('tcp_http', base_path)
    #     clr_env.iso_teardown_met('ssh', base_path)
    #     clr_env.iso_setup_class(dut='FrontDut')
    #     clr_env.iso_setup_class(dut='BackDut')
    #
    #     fun.rbm_close()
    #     fun.ssh_close('FrontDut')
    #     fun.ssh_close('BackDut')
