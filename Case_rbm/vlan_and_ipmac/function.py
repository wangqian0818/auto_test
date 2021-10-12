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
    from vlan_and_ipmac import index
    from vlan_and_ipmac import message
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
vlanAOpeIp = baseinfo.vlanAOpeIp
vlanBOpeIp = baseinfo.vlanBOpeIp
gwInternetIp = baseinfo.gwInternetIp
vlanAOpeMac = baseinfo.vlanAOpeMac
vlanBOpeMac = baseinfo.vlanBOpeMac
vlanA = str(baseinfo.vlanA)
err_vlanA = str(baseinfo.vlanA-1)
vlanB = str(baseinfo.vlanB)

class Test_vlan_and_ipmac():

    def setup_class(self):
        # 获取参数
        fun.ssh_gw.connect()
        self.clr_env = clr_env
        self.case1_step1 = index.case1_step1
        self.case1_step2 = index.case1_step2
        self.case1_step11 = index.case1_step11


        clr_env.clear_env()

    def setup_method(self):
        clr_env.clear_met_acl()

    def teardown_method(self):
        clr_env.clear_met_acl()


    # @pytest.mark.skip(reseason="skip")
    @allure.feature('验证supervlan与静态ipmac表的组合测试')
    def test_vlan_and_ipmac_a1(self):

        # 开启switch开关并检查是否开启成功
        for key in self.case1_step1:
            fun.cmd(self.case1_step1[key][0], 'gw')
            re = fun.cmd(self.case1_step1[key][1], 'gw')
            assert self.case1_step1[key][2] in re
        # 下发vlan配置
        fun.send(rbmExc, message.setvlan['SetVlan'], rbmDomain, base_path)
        # 检查配置下发是否成功
        for key in self.case1_step2:
            re = fun.wait_data(self.case1_step2[key][0], 'gw', self.case1_step2[key][1], 'vlan', 100)
            assert self.case1_step2[key][1] in re

        # 测试从设备端ping vlanA设备正常
        resA_cmd = 'ping '+ vlanAOpeIp + ' -c 4'
        print('从设备端ping vlanA设备的命令是：{}'.format(resA_cmd))
        resA = fun.cmd(resA_cmd,'gw')
        assert '0% packet loss' in resA

        #清空ipmac表，静态配置一条正确的ipmac表项，再次发送ping报文，查看通信是否正常
        mac_list = fun.cmd('ipmac -g','gw')
        print('ipmac表项内容为：{}'.format(mac_list))
        fun.cmd('ipmac -c','gw')
        mac_null = fun.cmd('ipmac -g', 'gw')
        print('清空mac表后的ipmac表项内容为：{}'.format(mac_null))
        ipmac_cmd = f'ipmac -a -i {vlanAOpeIp} -m {vlanAOpeMac} -v {vlanA}'
        print('静态配置一条正确的ipmac表的命令为：{}'.format(ipmac_cmd))
        fun.cmd(ipmac_cmd,'gw')
        # 测试从设备端ping vlanA设备正常
        resA_cmd = 'ping ' + vlanAOpeIp + ' -c 4'
        print('从设备端ping vlanA设备的命令是：{}'.format(resA_cmd))
        resA = fun.cmd(resA_cmd, 'gw')
        assert '0% packet loss' in resA

        # 清空ipmac表，静态配置一条错误的ipmac表项(mac错误)，再次发送ping报文，查看通信是否正常
        fun.cmd('ipmac -c', 'gw')
        errmac_cmd = f'ipmac -a -i {vlanAOpeIp} -m dd:dd:dd:dd:dd:dd -v {vlanA}'
        print('静态配置一条错误的ipmac表的命令为：{}'.format(errmac_cmd))
        fun.cmd(errmac_cmd, 'gw')
        # 测试从设备端ping vlanA设备正常
        resA_cmd = 'ping ' + vlanAOpeIp + ' -c 4'
        print('从设备端ping vlanA设备的命令是：{}'.format(resA_cmd))
        resA = fun.cmd(resA_cmd, 'gw')
        assert '100% packet loss' in resA

        # 清空ipmac表，静态配置一条错误的ipmac表项(vlan错误)，再次发送ping报文，查看通信是否正常
        fun.cmd('ipmac -c', 'gw')
        errvlan_cmd = f'ipmac -a -i {vlanAOpeIp} -m dd:dd:dd:dd:dd:dd -v {err_vlanA}'
        print('静态配置一条错误的ipmac表(vlan错误)的命令为：{}'.format(errvlan_cmd))
        fun.cmd(errvlan_cmd, 'gw')
        # 测试从设备端ping vlanA设备正常
        resA_cmd = 'ping ' + vlanAOpeIp + ' -c 4'
        print('从设备端ping vlanA设备的命令是：{}'.format(resA_cmd))
        resA = fun.cmd(resA_cmd, 'gw')
        assert '100% packet loss' in resA

        # 还原环境，清空ipmac表，移除vlan的配置，且关闭vlan的开关
        fun.cmd('ipmac -c', 'gw')
        # 关闭switch开关并检查是否关闭成功
        for key in self.case1_step11:
            fun.cmd(self.case1_step11[key][0], 'gw')
            re = fun.cmd(self.case1_step11[key][1], 'gw')
            assert self.case1_step11[key][2] in re
        # 清空vlan配置
        fun.send(rbmExc, message.delvlan['SetVlan'], rbmDomain, base_path)
        # 检查配置下发是否成功
        for key in self.case1_step2:
            re = fun.wait_data(self.case1_step2[key][0], 'gw', self.case1_step2[key][1], 'vlan', 100,flag='不存在')
            assert self.case1_step2[key][1] not in re


    def teardown_class(self):
        # 回收环境
        clr_env.clear_env()
        fun.cmd('ipmac -c', 'gw')
        fun.send(rbmExc, message.delvlan['SetVlan'], rbmDomain, base_path)

        fun.rbm_close()
        fun.ssh_close('gw')
