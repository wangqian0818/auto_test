'''

脚本一：
用例名称：验证ACL标记策略下的认证服务功能
编写人员：马丹丹
编写日期：2021/7/19
测试目的：验证ACL标记策略下的认证服务功能
测试步骤：
1.开启认证服务，通过命令ps -ef | grep verifymod、netstat -ultpn查询服务进程及服务端口是否存在
2.下发根证书文件到设备上
3.使用命令export cardid=0&&defconf --action drop开启靠近客户端卡的默认开关
4.下发acl放行策略到靠近客户端的网卡上
5.客户端向认证服务器发起认证请求，请求命令curl --cert /opt/test2certandkey.pem:123456 https://www.testCA.cn:443
6.使用命令tail -1 /var/log/jsac.verifymod.log查询网关设备认证日志 及用命令ipauth-jsac --auth --show查询认证ip表
7.使用命令export cardid=0&&defconf --action forward关闭靠近客户端卡的默认开关
8.移除acl策略
9.使用命令ipauth-jsac --clear将记录的认证ip清除掉
10.移除根证书文件
11.关闭认证服务，通过命令ps -ef | grep verifymod、netstat -ultpn查询服务进程及服务端口是否存在
预期结果：
1.认证服务开启成功，服务进程有/usr/local/ipauth/verifymod /etc/jsac/Initialize.conf、服务有监听443端口说明服务开启成功
2.根证书下发成功，ls /usr/local/ipauth/file/CAdb/可以查看到证书md5值c970dfa3234ed84ccac2e819a1276026
3.使用export cardid=0&&defconf --show命令查看有action: drop说明正常
4.使用export cardid=0&&tupleacl --get命令查看有目的端口为443的acl策略说明正常,策略详情如下：
id       sip             sp    dip             dp    l4p act in  prior ttl   qos0          qos1          qmode qbucket match strip tag drop mode doi   level type value
1        192.168.30.28   0     192.168.30.47   443   6   0   0   1     0     0             0             0     0       0     0     0   0    0    0     0     0    0x0,0x0,0x0,0x0
5.认证请求返回结果verify success说明请求发送成功
6.查询日志有"jsacaudit 源ip success"，查询认证ip表有源ip说明认证成功
7.使用export cardid=0&&defconf --show命令查看有action: forward说明正常
8.使用export cardid=0&&tupleacl --get命令查看无目的端口为443的acl策略说明策略移除成功
9.使用命令ipauth-jsac --auth --show查询不到认证源ip说明ip清除成功
10.根证书移除成功，ls /usr/local/ipauth/file/CAdb/无法查到证书md5值c970dfa3234ed84ccac2e819a1276026
11.认证服务关闭成功，服务进程usr/local/ipauth/verifymod /etc/jsac/Initialize.conf、端口443不存在



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
	from verifymod_acl import index
	from verifymod_acl import message
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

class Test_verifymod_acl():

    def setup_method(self):
        print('说明：CA测试涉及到的三个证书如下\n'
              '1.根证书/usr/local/ipauth/file/CAdb/cacert.pem md5值为c970dfa3234ed84ccac2e819a1276026有效期为2020/6/30 到 2023/6/30，若证书失效需替换\n'
              '2.认证服务设备端证书/usr/local/ipauth/file/ordinaryUser/app.crt有效期为2021/7/14 到 2023/7/14,若证书失效需替换\n'
              '3.客户端证书test2certandkey.pem有效期为2021/7/14 到 2023/7/14，,若证书失效需替换\n')
        clr_env.clear_env('gw')
        clr_env.clear_met_acl('gw')

    def teardown_method(self):
        clr_env.clear_env('gw')
        clr_env.clear_met_acl('gw')
        fun.cmd(self.case1_step4["step2"][1], 'gw')
        fun.cmd(self.case1_step8["step1"][1], 'gw')
        fun.send(rbmExc, message.acl_del['DelAclPolicy'], domain_rmb, base_path)
        fun.send(rbmExc, message.verifymod_DelAuthCert['DelAuthCert'], domain_rmb, base_path)
        clr_env.verifymod_teardown_met(base_path)



    def setup_class(self):
        # 获取参数
        fun.ssh_gw.connect()
        fun.ssh_c.connect()
        self.case1_step1 = index.case1_step1
        self.case1_step2 = index.case1_step2
        self.case1_step3 = index.case1_step3
        self.case1_step4 = index.case1_step4
        self.case1_step5 = index.case1_step5
        self.case1_step6 = index.case1_step6
        self.case1_step7 = index.case1_step7
        self.case1_step8 = index.case1_step8


    # @pytest.mark.skip(reseason="skip")
    @allure.feature(' 验证ACL标记策略下的认证服务功能')
    def test_verifymod_acl(self):

        # 开启认证服务
        print('1.开启认证服务，通过命令ps -ef | grep verifymod、netstat -ultpn查询服务进程及服务端口是否存在，服务进程有/usr/local/ipauth/verifymod /etc/jsac/Initialize.conf、服务有监听443端口说明服务开启成功')
        fun.send(rbmExc, message.verifymod_switch_start['ManageAuthServer'], domain_rmb, base_path)
        # 检查配置下发是否成功
        for key in self.case1_step1:
            re1 = fun.wait_data(self.case1_step1[key][0], 'gw', self.case1_step1[key][1], '检查认证服务进程', 100)
            assert self.case1_step1[key][1] in re1
        for key in self.case1_step2:
            re2 = fun.wait_data(self.case1_step2[key][0], 'gw', self.case1_step2[key][1], '检查认证监听端口', 100)
            assert self.case1_step2[key][1] in re2

        print('2.下发根证书文件到设备上，使用命令ls /usr/local/ipauth/file/CAdb/可以查看到证书md5值c970dfa3234ed84ccac2e819a1276026')
        fun.send(rbmExc, message.verifymod_AddAuthCert['AddAuthCert'], domain_rmb, base_path)
        # 检查配置下发是否成功
        for key in self.case1_step3:
            print(self.case1_step3[key][0])
            re1 = fun.wait_data(self.case1_step3[key][0], 'gw', self.case1_step3[key][1], '检查根证书', 100)
            assert self.case1_step3[key][1] in re1

        print('3.使用命令export cardid=0&&defconf --action drop开启靠近客户端卡的默认开关，使用export cardid=0&&defconf --show命令查看有action: drop说明正常')
        fun.cmd(self.case1_step4["step1"][0],'gw')
        re1 = fun.cmd(self.case1_step4["step1"][1],'gw')
        print(re1)
        assert self.case1_step4["step1"][2] in re1

        print('4.下发acl放行策略到靠近客户端的网卡上，使用export cardid=0&&tupleacl --get命令查看有目的端口为443的acl策略说明正常')
        fun.send(rbmExc, message.acl_add['AddAclPolicy'], domain_rmb, base_path)
        for key in self.case1_step5:
            re1 = fun.cmd(self.case1_step5[key][0],'gw')
            print(re1)
            assert self.case1_step5[key][1] in re1

        print('5.客户端向认证服务器发起认证请求，认证请求返回结果verify success说明正常')
        print('发送认证url：', self.case1_step6["step1"][0])
        for key in self.case1_step6:
            re1 = fun.cmd(self.case1_step6[key][0], 'c')
            print(re1)
            assert self.case1_step6[key][1]  in re1

        print('6.使用命令tail -1 /var/log/jsac.verifymod.log查询网关设备认证日志 及用命令ipauth-jsac --auth --show查询认证ip，查询日志有"jsacaudit 源ip success"，查询认证ip表有源ip说明认证成功')
        fun.wait_data(self.case1_step7["step1"][0], 'gw', self.case1_step7["step1"][1], '检查认证日志', 100)
        for key in self.case1_step7:
            re1 = fun.cmd(self.case1_step7[key][0], 'gw')
            assert self.case1_step7[key][1] in re1
        fun.wait_data(self.case1_step8["step1"][0], 'gw', self.case1_step8["step1"][2], '检查认证ip', 100)
        for key in self.case1_step8:
            re1 = fun.cmd(self.case1_step8[key][0], 'gw')
            assert self.case1_step8[key][2] in re1

        print('7.使用命令export cardid=0&&defconf --action forward关闭靠近客户端卡的默认开关，使用export cardid=0&&defconf --show命令查看有action: forward说明正常')
        fun.cmd(self.case1_step4["step2"][0],'gw')
        re1 = fun.cmd(self.case1_step4["step2"][1],'gw')
        print(re1)
        assert self.case1_step4["step2"][2] in re1

        print('8.移除acl策略，使用export cardid=0&&tupleacl --get命令查看无目的端口为443的acl策略说明策略移除成功')
        fun.send(rbmExc, message.acl_del['DelAclPolicy'], domain_rmb, base_path)
        for key in self.case1_step5:
            re1 = fun.cmd(self.case1_step5[key][0],'gw')
            print(re1)
            assert self.case1_step5[key][1] not in re1

        print('9.使用命令ipauth-jsac --clear将记录的认证ip清除掉，使用命令ipauth-jsac --auth --show查询不到认证源ip说明ip清除成功')
        fun.wait_data(self.case1_step8["step1"][1], 'gw', self.case1_step8["step1"][3], '检查认证ip', 100)
        for key in self.case1_step8:
            re1 = fun.cmd(self.case1_step8[key][0], 'gw')
            print(re1)
            assert self.case1_step8[key][2] not in re1

        print('10.移除根证书文件，根证书移除成功，ls /usr/local/ipauth/file/CAdb/无法查到证书md5值c970dfa3234ed84ccac2e819a1276026')
        fun.send(rbmExc, message.verifymod_DelAuthCert['DelAuthCert'], domain_rmb, base_path)
        # 检查配置下发是否成功
        for key in self.case1_step3:
            re1 = fun.wait_data(self.case1_step3[key][0], 'gw', self.case1_step3[key][1], '移除根证书', 100, flag='不存在')
            assert self.case1_step3[key][1] not in re1

        # 关闭认证服务
        print('11.关闭认证服务，通过命令ps -ef | grep verifymod、netstat -ultpn查询不到服务进程/usr/local/ipauth/verifymod /etc/jsac/Initialize.conf、且认证服务端口443也不存在')
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
