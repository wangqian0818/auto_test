'''
脚本一：
用例名称：验证根证书下发功能\验证根证书移除功能
编写人员：马丹丹
编写日期：2021/7/13
测试目的：验证根证书下发功能\验证根证书移除功能
测试步骤：
1.开启认证服务，通过命令ps -ef | grep verifymod、netstat -ultpn查询服务进程及服务端口是否存在
2.下发根证书文件到设备上
3.移除根证书文件
4.关闭认证服务，通过命令ps -ef | grep verifymod、netstat -ultpn查询服务进程及服务端口是否存在
预期结果：
1.认证服务开启成功，服务进程有/usr/local/ipauth/verifymod /etc/jsac/Initialize.conf、服务端口有443说明服务开启成功
2.根证书下发成功，ls /usr/local/ipauth/file/CAdb/可以查看到证书md5值c970dfa3234ed84ccac2e819a1276026
3.根证书移除成功，ls /usr/local/ipauth/file/CAdb/无法查到证书md5值c970dfa3234ed84ccac2e819a1276026
4.认证服务关闭成功，查询不到服务进程/usr/local/ipauth/verifymod /etc/jsac/Initialize.conf、且认证服务端口443也不存在

脚本二：
用例名称：验证下发多个根证书功能
编写人员：马丹丹
编写日期：2021/7/13
测试目的：验证下发多个根证书功能
测试步骤：
1.开启认证服务，通过命令ps -ef | grep verifymod、netstat -ultpn查询服务进程及服务端口是否存在
2.下发根证书1文件到设备上
3.下发根证书2文件到设备上
4.下发根证书3文件到设备上
5.移除根证书1文件
6.移除根证书2文件
7.移除根证书3文件
8.关闭认证服务，通过命令ps -ef | grep verifymod、netstat -ultpn查询服务进程及服务端口是否存在
预期结果：
1.认证服务开启成功，服务进程有/usr/local/ipauth/verifymod /etc/jsac/Initialize.conf、服务端口有443说明服务开启成功
2.根证书1下发成功，ls /usr/local/ipauth/file/CAdb/可以查看到证书md5值c970dfa3234ed84ccac2e819a1276026
3.根证书2下发成功，ls /usr/local/ipauth/file/CAdb/可以查看到证书md5值b1cca5dae1537b565f9781e6c47e9e90
4.根证书3下发成功，ls /usr/local/ipauth/file/CAdb/可以查看到证书md5值356702019c53f58e3e2e6b6697a2299c
5.根证书1移除成功，ls /usr/local/ipauth/file/CAdb/无法查到证书md5值c970dfa3234ed84ccac2e819a1276026
6.根证书2移除成功，ls /usr/local/ipauth/file/CAdb/无法查到证书md5值b1cca5dae1537b565f9781e6c47e9e90
7.根证书3移除成功，ls /usr/local/ipauth/file/CAdb/无法查到证书md5值356702019c53f58e3e2e6b6697a2299c
8.认证服务关闭成功，查询不到服务进程/usr/local/ipauth/verifymod /etc/jsac/Initialize.conf、且认证服务端口443也不存在


脚本三：
用例名称：验证多个根证书认证功能
编写人员：马丹丹
编写日期：2021/7/20
测试目的：验证多个根证书认证功能
测试步骤：
1.开启认证服务，通过命令ps -ef | grep verifymod、netstat -ultpn查询服务进程及服务端口是否存在
2.下发根证书1文件到设备上
3.下发根证书2文件到设备上
4.使用客户端证书1、证书2向认证服务器发起认证请求，请求命令分别是curl --cert /opt/test2certandkey.pem:123456 https://www.testCA.cn:443、curl --cert /opt/test3certandkey.pem:123456 https://www.testCA.cn:443
5.用命令tail -1 /var/log/jsac.verifymod.log查询网关设备认证日志文件 及用命令ipauth-jsac --auth --show查询认证ip表
6.下发命令，清空认证ip
7.移除根证书1文件
8.移除根证书2文件
9.关闭认证服务，通过命令ps -ef | grep verifymod、netstat -ultpn查询服务进程及服务端口是否存在
预期结果：
1.认证服务开启成功，服务进程有/usr/local/ipauth/verifymod /etc/jsac/Initialize.conf、服务端口有443说明服务开启成功
2.根证书1下发成功，ls /usr/local/ipauth/file/CAdb/可以查看到证书md5值c970dfa3234ed84ccac2e819a1276026
3.根证书2下发成功，ls /usr/local/ipauth/file/CAdb/可以查看到证书md5值b1cca5dae1537b565f9781e6c47e9e90
4.认证请求返回结果verify success说明请求发送成功
5.日志查询到"jsacaudit 源ip success"，认证ip表查询到源ip说明认证成功
6.使用命令ipauth-jsac --auth --show查询不到认证源ip说明ip清除成功
7.根证书1移除成功，ls /usr/local/ipauth/file/CAdb/无法查到证书md5值c970dfa3234ed84ccac2e819a1276026
8.根证书2移除成功，ls /usr/local/ipauth/file/CAdb/无法查到证书md5值b1cca5dae1537b565f9781e6c47e9e90
9.认证服务关闭成功，查询不到服务进程/usr/local/ipauth/verifymod /etc/jsac/Initialize.conf、且认证服务端口443也不存在
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
	from verifymod_authcert import index
	from verifymod_authcert import message
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
        fun.send(rbmExc, message.verifymod_DropAuthIp['DropAuthIp'], domain_rmb, base_path)
        fun.send(rbmExc, message.verifymod_DelAuthCert['DelAuthCert'], domain_rmb, base_path)
        fun.send(rbmExc, message.verifymod_Del_test2_AuthCert['DelAuthCert'], domain_rmb, base_path)
        fun.send(rbmExc, message.verifymod_Del_test3_AuthCert['DelAuthCert'], domain_rmb, base_path)
        clr_env.verifymod_teardown_met(base_path)

    def setup_class(self):
        # 获取参数
        fun.ssh_gw.connect()
        fun.ssh_c.connect()
        self.case1_step1 = index.case1_step1
        self.case1_step2 = index.case1_step2
        self.case1_step3 = index.case1_step3
        self.case2_step1 = index.case2_step1
        self.case2_step2 = index.case2_step2
        self.case3_step1 = index.case3_step1
        self.case3_step2 = index.case3_step2
        self.case3_step3 = index.case3_step3

    # @pytest.mark.skip(reseason="skip")
    @allure.feature('验证根证书下发功能\验证根证书移除功能')
    def test_verifymod_add_authcert(self):

        # 开启认证服务
        print('1.开启认证服务，通过命令ps -ef | grep verifymod、netstat -ultpn查询服务进程有/usr/local/ipauth/verifymod /etc/jsac/Initialize.conf、服务有监听443端口说明服务开启成功')
        fun.send(rbmExc, message.verifymod_switch_start['ManageAuthServer'], domain_rmb, base_path)
        # 检查配置下发是否成功
        for key in self.case1_step1:
            re1 = fun.wait_data(self.case1_step1[key][0], 'gw', self.case1_step1[key][1], '检查认证服务进程', 100)
            assert self.case1_step1[key][1] in re1
        for key in self.case1_step2:
            re2 = fun.wait_data(self.case1_step2[key][0], 'gw', self.case1_step2[key][1], '检查认证监听端口', 100)
            assert self.case1_step2[key][1] in re2


        print('2.下发根证书文件到设备上，ls /usr/local/ipauth/file/CAdb/可以查看到根证书md5值c970dfa3234ed84ccac2e819a1276026')
        fun.send(rbmExc, message.verifymod_AddAuthCert['AddAuthCert'], domain_rmb, base_path)
        # 检查配置下发是否成功
        for key in self.case1_step3:
            print(self.case1_step3[key][0])
            re1 = fun.wait_data(self.case1_step3[key][0], 'gw', self.case1_step3[key][1], '检查根证书', 100)
            assert self.case1_step3[key][1] in re1

        print('3.移除根证书文件，根证书移除成功，ls /usr/local/ipauth/file/CAdb/无法查到证书md5值c970dfa3234ed84ccac2e819a1276026')
        fun.send(rbmExc, message.verifymod_DelAuthCert['DelAuthCert'], domain_rmb, base_path)
        # 检查配置下发是否成功
        for key in self.case1_step3:
            re1 = fun.wait_data(self.case1_step3[key][0], 'gw', self.case1_step3[key][1], '移除根证书', 100 , flag='不存在')
            assert self.case1_step3[key][1] not in re1

        # 关闭认证服务
        print('4.关闭认证服务，通过命令ps -ef | grep verifymod、netstat -ultpn查询不到服务进程/usr/local/ipauth/verifymod /etc/jsac/Initialize.conf、且认证服务端口443也不存在')
        fun.send(rbmExc, message.verifymod_switch_stop['ManageAuthServer'], domain_rmb, base_path)
        # 检查配置下发是否成功
        for key in self.case1_step1:
            re1 = fun.wait_data(self.case1_step1[key][0], 'gw', self.case1_step1[key][1], '检查认证服务进程', 100, flag='不存在')
            assert self.case1_step1[key][1] not in re1
        for key in self.case1_step2:
            re2 = fun.wait_data(self.case1_step2[key][0], 'gw', self.case1_step2[key][1], '检查认证监听端口', 100, flag='不存在')
            assert self.case1_step2[key][1] not in re2





    # @pytest.mark.skip(reseason="skip")
    @allure.feature('验证下发多个根证书功能')
    def test_verifymod_add_many_authcert(self):

        # 开启认证服务
        print('1.开启认证服务，通过命令ps -ef | grep verifymod、netstat -ultpn查询服务进程有/usr/local/ipauth/verifymod /etc/jsac/Initialize.conf、服务有监听443端口说明服务开启成功')
        fun.send(rbmExc, message.verifymod_switch_start['ManageAuthServer'], domain_rmb, base_path)
        # 检查配置下发是否成功
        for key in self.case1_step1:
            re1 = fun.wait_data(self.case1_step1[key][0], 'gw', self.case1_step1[key][1], '检查认证服务进程', 100)
            assert self.case1_step1[key][1] in re1
        for key in self.case1_step2:
            re2 = fun.wait_data(self.case1_step2[key][0], 'gw', self.case1_step2[key][1], '检查认证监听端口', 100)
            assert self.case1_step2[key][1] in re2

        print('2.下发根证书1文件到设备上，根证书1下发成功，ls /usr/local/ipauth/file/CAdb/可以查看到证书md5值c970dfa3234ed84ccac2e819a1276026')
        fun.send(rbmExc, message.verifymod_AddAuthCert['AddAuthCert'], domain_rmb, base_path)
        # 检查配置下发是否成功
        for key in self.case1_step3:
            print(self.case1_step3[key][0])
            re1 = fun.wait_data(self.case1_step3[key][0], 'gw', self.case1_step3[key][1], '检查根证书1', 100)
            assert self.case1_step3[key][1] in re1

        print('3.下发根证书2文件到设备上，根证书2下发成功，ls /usr/local/ipauth/file/CAdb/可以查看到证书md5值b1cca5dae1537b565f9781e6c47e9e90')
        fun.send(rbmExc, message.verifymod_Add_test2_AuthCert['AddAuthCert'], domain_rmb, base_path)
        # 检查配置下发是否成功
        for key in self.case2_step1:
            print(self.case2_step1[key][0])
            re1 = fun.wait_data(self.case2_step1[key][0], 'gw', self.case2_step1[key][1], '检查根证书2', 100)
            assert self.case2_step1[key][1] in re1

        print('4.下发根证书3文件到设备上，根证书3下发成功，ls /usr/local/ipauth/file/CAdb/可以查看到证书md5值356702019c53f58e3e2e6b6697a2299c')
        fun.send(rbmExc, message.verifymod_Add_test3_AuthCert['AddAuthCert'], domain_rmb, base_path)
        # 检查配置下发是否成功
        for key in self.case2_step2:
            print(self.case2_step2[key][0])
            re1 = fun.wait_data(self.case2_step2[key][0], 'gw', self.case2_step2[key][1], '检查根证书3', 100)
            assert self.case2_step2[key][1] in re1

        print('5.根证书1移除成功，ls /usr/local/ipauth/file/CAdb/无法查到证书md5值c970dfa3234ed84ccac2e819a1276026')
        fun.send(rbmExc, message.verifymod_DelAuthCert['DelAuthCert'], domain_rmb, base_path)
        # 检查配置下发是否成功
        for key in self.case1_step3:
            re1 = fun.wait_data(self.case1_step3[key][0], 'gw', self.case1_step3[key][1], '移除根证书1', 100, flag='不存在')
            assert self.case1_step3[key][1] not in re1

        print('6.根证书2移除成功，ls /usr/local/ipauth/file/CAdb/无法查到证书md5值b1cca5dae1537b565f9781e6c47e9e90')
        fun.send(rbmExc, message.verifymod_Del_test2_AuthCert['DelAuthCert'], domain_rmb, base_path)
        # 检查配置下发是否成功
        for key in self.case2_step1:
            re1 = fun.wait_data(self.case2_step1[key][0], 'gw', self.case2_step1[key][1], '移除根证书2', 100, flag='不存在')
            assert self.case2_step1[key][1] not in re1

        print('7.根证书3移除成功，ls /usr/local/ipauth/file/CAdb/无法查到证书md5值356702019c53f58e3e2e6b6697a2299c')
        fun.send(rbmExc, message.verifymod_Del_test3_AuthCert['DelAuthCert'], domain_rmb, base_path)
        # 检查配置下发是否成功
        for key in self.case2_step2:
            re1 = fun.wait_data(self.case2_step2[key][0], 'gw', self.case2_step2[key][1], '移除根证书3', 100, flag='不存在')
            assert self.case2_step2[key][1] not in re1

        # 关闭认证服务
        print('8.关闭认证服务，认证服务关闭成功，查询不到服务进程/usr/local/ipauth/verifymod /etc/jsac/Initialize.conf、且认证服务端口443也不存在')
        fun.send(rbmExc, message.verifymod_switch_stop['ManageAuthServer'], domain_rmb, base_path)
        # 检查配置下发是否成功
        for key in self.case1_step1:
            re1 = fun.wait_data(self.case1_step1[key][0], 'gw', self.case1_step1[key][1], '检查认证服务进程', 100, flag='不存在')
            assert self.case1_step1[key][1] not in re1
        for key in self.case1_step2:
            re2 = fun.wait_data(self.case1_step2[key][0], 'gw', self.case1_step2[key][1], '检查认证监听端口', 100, flag='不存在')
            assert self.case1_step2[key][1] not in re2




     # @pytest.mark.skip(reseason="skip")
    @allure.feature('验证多个根证书认证功能')
    def test_verifymod_many_authcert_function(self):
        # 开启认证服务
        print('1.开启认证服务，通过命令ps -ef | grep verifymod、netstat -ultpn查询服务进程有/usr/local/ipauth/verifymod /etc/jsac/Initialize.conf、服务有监听443端口说明服务开启成功')
        fun.send(rbmExc, message.verifymod_switch_start['ManageAuthServer'], domain_rmb, base_path)
        # 检查配置下发是否成功
        for key in self.case1_step1:
            re1 = fun.wait_data(self.case1_step1[key][0], 'gw', self.case1_step1[key][1], '检查认证服务进程', 100)
            assert self.case1_step1[key][1] in re1
        for key in self.case1_step2:
            re2 = fun.wait_data(self.case1_step2[key][0], 'gw', self.case1_step2[key][1], '检查认证监听端口', 100)
            assert self.case1_step2[key][1] in re2

        print('2.下发根证书1文件到设备上，根证书1下发成功，ls /usr/local/ipauth/file/CAdb/可以查看到证书md5值c970dfa3234ed84ccac2e819a1276026')
        fun.send(rbmExc, message.verifymod_AddAuthCert['AddAuthCert'], domain_rmb, base_path)
        # 检查配置下发是否成功
        for key in self.case1_step3:
            print(self.case1_step3[key][0])
            re1 = fun.wait_data(self.case1_step3[key][0], 'gw', self.case1_step3[key][1], '检查根证书1', 100)
            assert self.case1_step3[key][1] in re1

        print('3.下发根证书2文件到设备上，根证书1下发成功，ls /usr/local/ipauth/file/CAdb/可以查看到证书md5值b1cca5dae1537b565f9781e6c47e9e90')
        fun.send(rbmExc, message.verifymod_Add_test2_AuthCert['AddAuthCert'], domain_rmb, base_path)
        # 检查配置下发是否成功
        for key in self.case2_step1:
            print(self.case2_step1[key][0])
            re1 = fun.wait_data(self.case2_step1[key][0], 'gw', self.case2_step1[key][1], '检查根证书2', 100)
            assert self.case2_step1[key][1] in re1

        print('4.使用客户端证书1、证书2向认证服务器发起认证请求，请求命令分别是curl --cert /opt/test2certandkey.pem:123456 https://www.testCA.cn:443、curl --cert /opt/test3certandkey.pem:123456 https://www.testCA.cn:443，认证请求返回结果verify success说明请求发送成功')
        print('发送证书一认证url：',self.case3_step1["step1"][0])
        print('发送证书二认证url：',self.case3_step1["step2"][0])
        for key in self.case3_step1:
            re1 = fun.cmd(self.case3_step1[key][0],'c')
            print(re1)
            assert self.case3_step1[key][1] in re1

        print('5.检查网关设备认证日志文件/var/log/jsac.verifymod.log 及用命令ipauth-jsac --auth --show查询认证ip，日志查询到"jsacaudit 源ip success"，认证ip有源ip说明认证成功')
        fun.wait_data(self.case3_step2["step1"][0], 'gw', self.case3_step2["step1"][1], '检查认证日志', 100)
        for key in self.case3_step2:
            re1 = fun.cmd(self.case3_step2[key][0], 'gw')
            assert self.case3_step2[key][1] in re1
        fun.wait_data(self.case3_step3["step1"][0], 'gw', self.case3_step3["step1"][1], '检查认证ip', 100)
        for key in self.case3_step3:
            re1 = fun.cmd(self.case3_step3[key][0], 'gw')
            assert self.case3_step3[key][1] in re1

        print('6.清空认证ip，使用命令ipauth-jsac --auth --show查询不到认证源ip说明ip清除成功')
        fun.send(rbmExc, message.verifymod_DropAuthIp['DropAuthIp'], domain_rmb, base_path)
        fun.wait_data(self.case3_step3["step1"][0], 'gw', self.case3_step3["step1"][1], '检查认证ip', 100, flag='不存在')
        for key in self.case3_step3:
            re1 = fun.cmd(self.case3_step3[key][0], 'gw')
            assert self.case3_step3[key][1] not in re1

        print('7.根证书1移除成功，ls /usr/local/ipauth/file/CAdb/无法查到证书md5值c970dfa3234ed84ccac2e819a1276026')
        fun.send(rbmExc, message.verifymod_DelAuthCert['DelAuthCert'], domain_rmb, base_path)
        # 检查配置下发是否成功
        for key in self.case1_step3:
            re1 = fun.wait_data(self.case1_step3[key][0], 'gw', self.case1_step3[key][1], '移除根证书1', 100, flag='不存在')
            assert self.case1_step3[key][1] not in re1

        print('8.根证书2移除成功，ls /usr/local/ipauth/file/CAdb/无法查到证书md5值b1cca5dae1537b565f9781e6c47e9e90')
        fun.send(rbmExc, message.verifymod_Del_test2_AuthCert['DelAuthCert'], domain_rmb, base_path)
        # 检查配置下发是否成功
        for key in self.case2_step1:
            re1 = fun.wait_data(self.case2_step1[key][0], 'gw', self.case2_step1[key][1], '移除根证书2', 100, flag='不存在')
            assert self.case2_step1[key][1] not in re1

      # 关闭认证服务
        print('9.认证服务关闭成功，查询不到服务进程/usr/local/ipauth/verifymod /etc/jsac/Initialize.conf、且认证服务端口443也不存在')
        fun.send(rbmExc, message.verifymod_switch_stop['ManageAuthServer'], domain_rmb, base_path)
        # 检查配置下发是否成功
        for key in self.case1_step1:
            re1 = fun.wait_data(self.case1_step1[key][0], 'gw', self.case1_step1[key][1], '检查认证服务进程', 100, flag='不存在')
            assert self.case1_step1[key][1] not in re1
        for key in self.case1_step2:
            re2 = fun.wait_data(self.case1_step2[key][0], 'gw', self.case1_step2[key][1], '检查认证监听端口', 100, flag='不存在')
            assert self.case1_step2[key][1] not in re2


    def teardown_class(self):
        # 回收环境
        fun.rbm_close()
        fun.ssh_close('c')
        # fun.ssh_close('s')
        fun.ssh_close('gw')
