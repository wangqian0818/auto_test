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
    from vlan_gw_issue import index
    from vlan_gw_issue import message
    from common import fun
    import common.ssh_wq as c_ssh
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

# del sys.path[0]
# del sys.path[0]
from common import baseinfo
from common import clr_env
from common.rabbitmq import *
from data_check import http_check

datatime = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(time.time()))

rbmDomain = baseinfo.rbmDomain
rbmExc = baseinfo.rbmExc

class Test_vlan_gw_issue():

    def setup_class(self):
        # 获取参数
        fun.ssh_gw.connect()
        self.clr_env = clr_env
        self.case1_step1 = index.case1_step1
        self.case1_step2 = index.case1_step2
        self.case1_step3 = index.case1_step3
        self.case2_step1 = index.case2_step1
        self.case2_step2 = index.case2_step2
        self.case3_step1 = index.case3_step1
        self.case3_step2 = index.case3_step2
        self.vlan_clear = index.vlan_clear


        clr_env.clear_env()

    def setup_method(self):
        clr_env.clear_met_acl()

    def teardown_method(self):
        clr_env.clear_met_acl()


    # @pytest.mark.skip(reseason="skip")
    @allure.feature(' 从管控配置vlan 对一个接口配置多个vlan')
    def test_vlan_gw_issue_a1(self):

        # 对一个接口配置多个正确的vlan
        fun.send(rbmExc, message.setvlan_right['SetVlan'], rbmDomain, base_path)
        # 检查配置下发是否成功
        for key in self.case1_step1:
            re = fun.wait_data(self.case1_step1[key][0], 'gw', self.case1_step1[key][1], 'vlan', 100)
            assert self.case1_step1[key][1] in re

        # 对一个接口配置多个错误的vlan
        fun.send(rbmExc, message.setvlan_error['SetVlan'], rbmDomain, base_path)
        # 检查配置下发是否成功
        for key in self.case1_step2:
            re = fun.wait_data(self.case1_step2[key][0], 'gw', self.case1_step2[key][1], 'vlan', 100,flag='不存在')
            assert self.case1_step2[key][1] not in re

        # 对一个接口配置多个vlan,部分正确，部分错误
        fun.send(rbmExc, message.setvlan_part['SetVlan'], rbmDomain, base_path)
        # 检查配置下发是否成功
        for key in self.case1_step3:
            re = fun.wait_data(self.case1_step3[key][0], 'gw', self.case1_step3[key][1], 'vlan', 100,flag='不存在')
            assert self.case1_step3[key][1] not in re

        #清空环境，还原配置
        fun.send(rbmExc, message.delvlan['SetVlan'], rbmDomain, base_path)
        # 检查配置下发是否成功
        for key in self.vlan_clear:
            re = fun.cmd(self.vlan_clear[key][0], 'gw')
            assert self.vlan_clear[key][1] in re


    # @pytest.mark.skip(reseason="skip")
    @allure.feature(' 从管控配置vlan 对多个接口配置一个vlan')
    def test_vlan_gw_issue_a2(self):

        # 对多个接口配置一个正确的vlan
        fun.send(rbmExc, message.setNetVlan_right['SetVlan'], rbmDomain, base_path)
        # 检查配置下发是否成功
        for key in self.case2_step1:
            re = fun.wait_data(self.case2_step1[key][0], 'gw', self.case2_step1[key][1], 'vlan', 100)
            assert self.case2_step1[key][1] in re

        # 对多个接口配置一个错误的vlan
        fun.send(rbmExc, message.setNetVlan_error['SetVlan'], rbmDomain, base_path)
        # 检查配置下发是否成功
        for key in self.case2_step2:
            re = fun.wait_data(self.case2_step2[key][0], 'gw', self.case2_step2[key][1], 'vlan', 100,flag='不存在')
            assert self.case2_step2[key][1] not in re

        # 清空环境，还原配置
        fun.send(rbmExc, message.delvlan['SetVlan'], rbmDomain, base_path)
        # 检查配置下发是否成功
        for key in self.vlan_clear:
            re = fun.cmd(self.vlan_clear[key][0], 'gw')
            assert self.vlan_clear[key][1] in re

    # @pytest.mark.skip(reseason="skip")
    @allure.feature(' 从管控配置vlan 对多个接口配置多个vlan')
    def test_vlan_gw_issue_a3(self):

        # 对多个接口配置一个正确的vlan
        fun.send(rbmExc, message.setMoreNetVlan_right['SetVlan'], rbmDomain, base_path)
        # 检查配置下发是否成功
        for key in self.case3_step1:
            re = fun.wait_data(self.case3_step1[key][0], 'gw', self.case3_step1[key][1], 'vlan', 100)
            assert self.case3_step1[key][1] in re

        # 对多个接口配置一个错误的vlan
        fun.send(rbmExc, message.setMoreNetVlan_error['SetVlan'], rbmDomain, base_path)
        # 检查配置下发是否成功
        for key in self.case3_step2:
            re = fun.wait_data(self.case3_step2[key][0], 'gw', self.case3_step2[key][1], 'vlan', 100,flag='不存在')
            assert self.case3_step2[key][1] not in re

        # 清空环境，还原配置
        fun.send(rbmExc, message.delvlan['SetVlan'], rbmDomain, base_path)
        # 检查配置下发是否成功
        for key in self.vlan_clear:
            re = fun.cmd(self.vlan_clear[key][0], 'gw')
            assert self.vlan_clear[key][1] in re

    def teardown_class(self):
        # 回收环境
        clr_env.clear_env()
        fun.send(rbmExc, message.delvlan['SetVlan'], rbmDomain, base_path)

        fun.rbm_close()
        fun.ssh_close('gw')
