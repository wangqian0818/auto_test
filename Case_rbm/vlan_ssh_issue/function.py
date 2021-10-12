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
    from vlan_ssh_issue import index
    from vlan_ssh_issue import message
    from common import fun
    import common.ssh_wq as c_ssh
except Exception as err:
    print('导入基础函数库失败!请检查相关文件是否存在.\n文件位于: ' + str(base_path) + '/common/ 目录下.\n分别为:pcap.py  rabbitmq.py  ssh.py\n错误信息如下:')
    print(err)
    sys.exit(0)  # 避免程序继续运行造成的异常崩溃,友好退出程序
else:
    del sys.path[0]  # 及时删除导入的环境变量,避免重复导入造成的异常错误
# import index
# del sys.path[0]
# dir_dir_path=os.path.abspath(os.path.join(os.getcwd()))
# sys.path.append(os.getcwd())

# del sys.path[0]
# del sys.path[0]
from common import baseinfo
from common import clr_env
from common.rabbitmq import *
from data_check import http_check

datatime = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(time.time()))


class Test_vlan_ssh_issue():

    def setup_class(self):
        # 获取参数
        fun.ssh_gw.connect()
        self.clr_env = clr_env
        self.case1_step1 = index.case1_step1
        self.case1_step2 = index.case1_step2
        self.vlan_clear = index.vlan_clear
        self.case2_step1 = index.case2_step1
        self.case3_step1 = index.case3_step1


        clr_env.clear_env()

    def setup_method(self):
        clr_env.clear_met_acl()

    def teardown_method(self):
        clr_env.clear_met_acl()


    # @pytest.mark.skip(reseason="skip")
    @allure.feature('  从命令行配置vlan 对一个接口配置多个vlan')
    def test_vlan_ssh_issue_a1(self):

        # 对一个接口配置多个正确的vlan并检查配置是否成功
        for key in self.case1_step1:
            fun.cmd(self.case1_step1[key][0], 'gw')
            re = fun.cmd(self.case1_step1[key][1], 'gw')
            assert self.case1_step1[key][2] in re
        #对一个接口配置错误的vlan并检查命令是否报错
        for key in self.case1_step2:
            re = fun.cmd(self.case1_step2[key][0], 'gw')
            assert self.case1_step2[key][1] in re

        # 清空vlan配置
        for key in self.vlan_clear:
            fun.cmd(self.vlan_clear[key][0], 'gw')
            re = fun.cmd(self.vlan_clear[key][1], 'gw')
            assert self.vlan_clear[key][2] in re

    # @pytest.mark.skip(reseason="skip")
    @allure.feature(' 从命令行配置vlan 对多个接口配置一个vlan')
    def test_vlan_ssh_issue_a2(self):

        # 对多个接口配置一个正确的vlan并检查配置是否成功
        for key in self.case2_step1:
            fun.cmd(self.case2_step1[key][0], 'gw')
            re = fun.cmd(self.case2_step1[key][1], 'gw')
            assert self.case2_step1[key][2] in re

        # 清空vlan配置
        for key in self.vlan_clear:
            fun.cmd(self.vlan_clear[key][0], 'gw')
            re = fun.cmd(self.vlan_clear[key][1], 'gw')
            assert self.vlan_clear[key][2] in re

    # @pytest.mark.skip(reseason="skip")
    @allure.feature(' 从命令行配置vlan 对多个接口配置多个vlan')
    def test_vlan_ssh_issue_a3(self):

        # 对多个接口配置一个正确的vlan并检查配置是否成功
        for key in self.case3_step1:
            fun.cmd(self.case3_step1[key][0], 'gw')
            re = fun.cmd(self.case3_step1[key][1], 'gw')
            assert self.case3_step1[key][2] in re

        # 清空vlan配置
        for key in self.vlan_clear:
            fun.cmd(self.vlan_clear[key][0], 'gw')
            re = fun.cmd(self.vlan_clear[key][1], 'gw')
            assert self.vlan_clear[key][2] in re

    def teardown_class(self):
        # 回收环境
        clr_env.clear_env()

        fun.ssh_close('gw')
