# encoding='utf-8'
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
    from iso_ftp_large_file import index
    from iso_ftp_large_file import message
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
from data_check import con_ftp

datatime = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(time.time()))

FrontDomain = baseinfo.BG8010FrontDomain
BackDomain = baseinfo.BG8010BackDomain
proxy_ip = baseinfo.BG8010FrontOpeIp
rbmExc = baseinfo.rbmExc
http_content = baseinfo.http_content
BG8010ServerPwd = baseinfo.BG8010ServerPwd
ssh_proxy_port = baseinfo.ssh_proxy_port


class Test_iso_ftp_large_file():

    def setup_method(self):
        clr_env.data_check_setup_met(dut='FrontDut')
        clr_env.data_check_setup_met(dut='BackDut')

    def teardown_method(self):
        clr_env.iso_setup_class(dut='FrontDut')
        clr_env.iso_setup_class(dut='BackDut')

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
        self.ftp_proxy_port = index.ftp_proxy_port
        self.ftp_user = index.ftp_user
        self.ftp_pass = index.ftp_pass
        self.case2_downremotePath = index.case2_downremotePath
        self.case2_downlocalPath = index.case2_downlocalPath
        self.upremotePath = index.upremotePath
        self.uplocalPath = index.uplocalPath

        clr_env.iso_setup_class(dut='FrontDut')
        clr_env.iso_setup_class(dut='BackDut')

    # @pytest.mark.skip(reseason="skip")
    @allure.feature('验证隔离下的ftp传输策略下载一个10G大小的文件')
    def test_iso_ftp_large_file_a1(self):

        # 下发配置
        fun.send(rbmExc, message.addftp_front['AddCustomAppPolicy'], FrontDomain, base_path)
        fun.send(rbmExc, message.addftp_back['AddCustomAppPolicy'], BackDomain, base_path)
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

        # 登录ftp服务器，下载一个10G大小的文件
        fp = con_ftp.connect_ftp(proxy_ip, self.ftp_proxy_port, self.ftp_user, self.ftp_pass)
        print('欢迎语是：{}'.format(fp.getwelcome()))
        print('self.case2_downremotePath, self.case2_downlocalPath', self.case2_downremotePath,
              self.case2_downlocalPath)
        result = con_ftp.downFile(fp, self.case2_downremotePath, self.case2_downlocalPath)
        print('ftp走隔离下载一个10G大小的文件结果为:{}'.format(result))
        assert result == 1

        # 移除策略，清空环境
        fun.send(rbmExc, message.delftp_front['DelCustomAppPolicy'], FrontDomain, base_path)
        fun.send(rbmExc, message.delftp_back['DelCustomAppPolicy'], BackDomain, base_path)
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

    '''
    ftp走隔离上传10G文件失败，上传到9.77G就失败了
    '''

    # @pytest.mark.skip(reseason="skip")
    @allure.feature('验证隔离下的ftp传输策略上传一个10G大小的文件')
    def test_iso_ftp_large_file_a2(self):

        # 下发配置
        fun.send(rbmExc, message.addftp_front['AddCustomAppPolicy'], FrontDomain, base_path)
        fun.send(rbmExc, message.addftp_back['AddCustomAppPolicy'], BackDomain, base_path)
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

        # 登录ftp服务器，上传一个10G大小的文件
        fp = con_ftp.connect_ftp(proxy_ip, self.ftp_proxy_port, self.ftp_user, self.ftp_pass)
        print('欢迎语是：{}'.format(fp.getwelcome()))
        result = con_ftp.uploadFile(fp, self.upremotePath, self.uplocalPath)
        print('ftp走隔离上传一个10G大小的文件结果为:{}'.format(self.uplocalPath, result))
        assert result == 1

        # 移除策略，清空环境
        fun.send(rbmExc, message.delftp_front['DelCustomAppPolicy'], FrontDomain, base_path)
        fun.send(rbmExc, message.delftp_back['DelCustomAppPolicy'], BackDomain, base_path)
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

    def teardown_class(self):
        # 回收环境
        clr_env.iso_teardown_met('ftp', base_path)
        clr_env.iso_setup_class(dut='FrontDut')
        clr_env.iso_setup_class(dut='BackDut')

        fun.rbm_close()
        fun.ssh_close('FrontDut')
        fun.ssh_close('BackDut')
