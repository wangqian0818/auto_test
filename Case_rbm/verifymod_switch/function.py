'''
脚本一：
用例名称：验证认证服务的开启功能\验证认证服务的关闭功能
编写人员：马丹丹
编写日期：2021/7/13
测试目的：验证认证服务的开启功能\验证认证服务的关闭功能
测试步骤：
1.开启认证服务，通过命令ps -ef | grep verifymod、netstat -ultpn查询服务进程及服务端口是否存在
2.关闭认证服务，通过命令ps -ef | grep verifymod、netstat -ultpn查询服务进程及服务端口是否存在
预期结果：
1.认证服务开启成功，服务进程有/usr/local/ipauth/verifymod /etc/jsac/Initialize.conf、服务端口有443说明服务开启成功
2.认证服务关闭成功，查询不到服务进程/usr/local/ipauth/verifymod /etc/jsac/Initialize.conf、且认证服务端口443也不存在

脚本二：
用例名称：验证认证服务的重启功能
编写人员：马丹丹
编写日期：2021/7/13
测试目的：验证认证服务的重启功能
测试步骤：
1.开启认证服务，通过命令ps -ef | grep verifymod、netstat -ultpn查询服务进程及服务端口是否存在
2.重启认证服务，通过命令ps -ef | grep verifymod、netstat -ultpn查询服务进程是否存在及服务端口是否改变
3.关闭认证服务，通过命令ps -ef | grep verifymod、netstat -ultpn查询服务进程及服务端口是否存在
预期结果：
1.认证服务开启成功，服务进程有/usr/local/ipauth/verifymod /etc/jsac/Initialize.conf、服务端口有443说明服务开启成功
2.认证服务重启成功，服务进程有/usr/local/ipauth/verifymod /etc/jsac/Initialize.conf、服务端口有5566说明服务开启成功
3.认证服务关闭成功，查询不到服务进程/usr/local/ipauth/verifymod /etc/jsac/Initialize.conf、且认证服务端口5566也不存在
'''
#encoding='utf-8'
try:
	import os,sys,pytest,allure,time,re,time
except Exception as err:
	print('导入CPython内置函数库失败!错误信息如下:')
	print(err)
	sys.exit(0)#避免程序继续运行造成的异常崩溃,友好退出程序

base_path=os.path.dirname(os.path.abspath(__file__))#获取当前项目文件夹
base_path=base_path.replace('\\','/')
sys.path.insert(0,base_path)#将当前目录添加到系统环境变量,方便下面导入版本配置等文件
print(base_path)
try:
	from verifymod_switch import index
	from verifymod_switch import message
	from common import fun
	# import common.ssh as c_ssh
except Exception as err:
	print(
		'导入基础函数库失败!请检查相关文件是否存在.\n文件位于: ' + str(base_path) + '/common/ 目录下.\n分别为:pcap.py  rabbitmq.py  ssh.py\n错误信息如下:')
	print(err)
	sys.exit(0)  # 避免程序继续运行造成的异常崩溃,友好退出程序
else:
	del sys.path[0]  # 及时删除导入的环境变量,避免重复导入造成的异常错误
# import index
# del sys.path[0]
#dir_dir_path=os.path.abspath(os.path.join(os.getcwd()))
#sys.path.append(os.getcwd())

from common import clr_env
from common import baseinfo
from common.rabbitmq import *
from data_check import http_check


datatime = time.strftime('%Y-%m-%d %H:%M:%S',time.localtime(time.time()))

domain_rmb=baseinfo.rbmDomain
rbmExc = baseinfo.rbmExc

class Test_verifymod_switch():

    def setup_method(self):
        clr_env.clear_env('gw')
        clr_env.clear_met_acl('gw')

    def teardown_method(self):
        clr_env.clear_env('gw')
        clr_env.clear_met_acl('gw')
        clr_env.verifymod_teardown_met(base_path)

    def setup_class(self):
        # 获取参数
        fun.ssh_gw.connect()
        # fun.ssh_c.connect()
        self.case1_step1 = index.case1_step1
        self.case1_step2 = index.case1_step2
        self.case2_step1 = index.case2_step1

    # @pytest.mark.skip(reseason="skip")
    @allure.feature('验证认证服务的开启功能\验证认证服务的关闭功能')
    def test_verifymod_switch_start_stop(self):

        # 开启认证服务
        print('1.开启认证服务，通过命令ps -ef | grep verifymod、netstat -ultpn查询服务进程有/usr/local/ipauth/verifymod /etc/jsac/Initialize.conf、服务端口有443说明服务开启成功')
        fun.send(rbmExc, message.verifymod_switch_start['ManageAuthServer'], domain_rmb, base_path)
        # 检查配置下发是否成功
        for key in self.case1_step1:
            re1 = fun.wait_data(self.case1_step1[key][0], 'gw', self.case1_step1[key][1], '检查认证服务进程', 100)
            assert self.case1_step1[key][1] in re1
        for key in self.case1_step2:
            re2 = fun.wait_data(self.case1_step2[key][0], 'gw', self.case1_step2[key][1], '检查认证监听端口', 100)
            assert self.case1_step2[key][1] in re2

        # 关闭认证服务
        print('2.关闭认证服务，通过命令ps -ef | grep verifymod、netstat -ultpn查询不到服务进程/usr/local/ipauth/verifymod /etc/jsac/Initialize.conf、且认证服务端口443也不存在')
        fun.send(rbmExc, message.verifymod_switch_stop['ManageAuthServer'], domain_rmb, base_path)
        # 检查配置下发是否成功
        for key in self.case1_step1:
            re1 = fun.wait_data(self.case1_step1[key][0], 'gw', self.case1_step1[key][1], '检查认证服务进程', 100, flag='不存在')
            assert self.case1_step1[key][1] not in re1
        for key in self.case1_step2:
            re2 = fun.wait_data(self.case1_step2[key][0], 'gw', self.case1_step2[key][1], '检查认证监听端口', 100, flag='不存在')
            assert self.case1_step2[key][1] not in re2




    #@pytest.mark.skip(reseason="skip")
    @allure.feature('验证认证服务的重启功能')
    def test_verifymod_switch_restart(self):

        # 开启认证服务
        print('1.开启认证服务，通过命令ps -ef | grep verifymod、netstat -ultpn查询服务进程有/usr/local/ipauth/verifymod /etc/jsac/Initialize.conf、服务端口有443说明服务开启成功')
        fun.send(rbmExc, message.verifymod_switch_start['ManageAuthServer'], domain_rmb, base_path)
        # 检查配置下发是否成功
        for key in self.case1_step1:
            re1 = fun.wait_data(self.case1_step1[key][0], 'gw', self.case1_step1[key][1], '检查认证服务进程', 100)
            assert self.case1_step1[key][1] in re1
        for key in self.case1_step2:
            re2 = fun.wait_data(self.case1_step2[key][0], 'gw', self.case1_step2[key][1], '检查认证监听端口', 100)
            assert self.case1_step2[key][1] in re2


        print('2.重启认证服务，通过命令ps -ef | grep verifymod、netstat -ultpn查询服务进程有/usr/local/ipauth/verifymod /etc/jsac/Initialize.conf、服务端口有5566说明服务重启成功')
        fun.send(rbmExc, message.verifymod_switch_restart['ManageAuthServer'], domain_rmb, base_path)
        for key in self.case1_step1:
            re1 = fun.wait_data(self.case1_step1[key][0], 'gw', self.case1_step1[key][1], '检查认证服务进程', 100)
            assert self.case1_step1[key][1] in re1
        for key in self.case2_step1:
            re2 = fun.wait_data(self.case2_step1[key][0], 'gw', self.case2_step1[key][1], '检查认证监听端口', 100)
            assert self.case2_step1[key][1] in re2


        # 关闭认证服务
        print('3.关闭认证服务，通过命令ps -ef | grep verifymod、netstat -ultpn查询不到服务进程/usr/local/ipauth/verifymod /etc/jsac/Initialize.conf、且认证服务端口5566也不存在')
        fun.send(rbmExc, message.verifymod_switch_stop['ManageAuthServer'], domain_rmb, base_path)
        # 检查配置下发是否成功
        for key in self.case1_step1:
            re1 = fun.wait_data(self.case1_step1[key][0], 'gw', self.case1_step1[key][1], '检查认证服务进程', 100, flag='不存在')
            assert self.case1_step1[key][1] not in re1
        for key in self.case2_step1:
            re2 = fun.wait_data(self.case2_step1[key][0], 'gw', self.case2_step1[key][1], '检查认证监听端口', 100, flag='不存在')
            assert self.case2_step1[key][1] not in re2




    def teardown_class(self):
        # 回收环境
        fun.rbm_close()
        # fun.ssh_close('c')
        # fun.ssh_close('s')
        fun.ssh_close('gw')
