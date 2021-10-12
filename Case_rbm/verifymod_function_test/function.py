'''

脚本一：
用例名称：验证正常情况下的认证服务功能
编写人员：马丹丹
编写日期：2021/7/15
测试目的：验证正常情况下的认证服务功能
测试步骤：
1.开启认证服务，通过命令ps -ef | grep verifymod、netstat -ultpn查询服务进程及服务端口是否存在
2.下发根证书文件到设备上
3.客户端向认证服务器发起认证请求,请求命令curl --cert /opt/test2certandkey.pem:123456 https://www.testCA.cn:443
4.用命令tail -1 /var/log/jsac.verifymod.log查询网关设备认证日志文件 及用命令ipauth-jsac --auth --show查询认证ip表
5.使用命令ipauth-jsac --clear将记录的认证ip清除掉
6.移除根证书文件
7.关闭认证服务，通过命令ps -ef | grep verifymod、netstat -ultpn查询服务进程及服务端口是否存在
预期结果：
1.认证服务开启成功，服务进程有/usr/local/ipauth/verifymod /etc/jsac/Initialize.conf、服务有监听443端口说明服务开启成功
2.根证书下发成功，ls /usr/local/ipauth/file/CAdb/可以查看到证书md5值c970dfa3234ed84ccac2e819a1276026
3.认证请求返回结果verify success说明请求发送成功
4.日志查询到"jsacaudit 源ip success"，认证ip表查询到源ip说明认证成功
5.使用命令ipauth-jsac --auth --show查询不到认证源ip说明ip清除成功
6.根证书移除成功，ls /usr/local/ipauth/file/CAdb/无法查到证书md5值c970dfa3234ed84ccac2e819a1276026
7.认证服务关闭成功，查询不到服务进程/usr/local/ipauth/verifymod /etc/jsac/Initialize.conf、且认证服务端口443也不存在


脚本二：
用例名称：验证异常情况下的认证服务功能
编写人员：马丹丹
编写日期：2021/7/15
测试目的：验证异常情况下的认证服务功能
测试步骤：
1.开启认证服务，通过命令ps -ef | grep verifymod、netstat -ultpn查询服务进程及服务端口是否存在
2.下发根证书文件到设备上
3.客户端向认证服务器发起异常认证请求1,其中使用错误的客户端证书，请求命令curl --cert /opt/gwdifferentCA.pem:123456 https://www.testCA.cn:443
4.用命令tail -1 /var/log/jsac.verifymod.log查询网关设备认证日志文件 及用命令ipauth-jsac --auth --show查询认证ip表
5.客户端向认证服务器发起异常认证请求2,其中使用错误证书密码，请求命令curl --cert /opt/test2certandkey.pem:666666 https://www.testCA.cn:443
6.用命令tail -1 /var/log/jsac.verifymod.log查询网关设备认证日志文件 及用命令ipauth-jsac --auth --show查询认证ip表
7.客户端向认证服务器发起异常认证请求3,其中使用错误认证服务域名，请求命令curl --cert /opt/test2certandkey.pem:666666 https://www.test.cn:443
8.用命令tail -1 /var/log/jsac.verifymod.log查询网关设备认证日志文件 及用命令ipauth-jsac --auth --show查询认证ip表
9.移除根证书文件
10.关闭认证服务，通过命令ps -ef | grep verifymod、netstat -ultpn查询服务进程及服务端口是否存在
预期结果：
1.认证服务开启成功，服务进程有/usr/local/ipauth/verifymod /etc/jsac/Initialize.conf、服务有监听443端口说明服务开启成功
2.根证书下发成功，ls /usr/local/ipauth/file/CAdb/可以查看到证书md5值c970dfa3234ed84ccac2e819a1276026
3.异常认证请求1发送成功，认证请求返回结果无verify success说明正常
4.日志查询到"jsacaudit 源ip failed"，说明认证失败。使用命令ipauth-jsac --auth --show查询认证ip，查不到认证ip说明正常
5.异常认证请求2发送成功，认证请求返回结果无verify success说明正常
6.日志查询到"jsacaudit 源ip failed"，说明认证失败。使用命令ipauth-jsac --auth --show查询认证ip，查不到认证ip说明正常
7.异常认证请求3发送成功，认证请求返回结果无verify success说明正常
8.日志查询到"jsacaudit 源ip failed"，说明认证失败。使用命令ipauth-jsac --auth --show查询认证ip，查不到认证ip说明正常
9.根证书移除成功，ls /usr/local/ipauth/file/CAdb/无法查到证书md5值c970dfa3234ed84ccac2e819a1276026
10.认证服务关闭成功，查询不到服务进程/usr/local/ipauth/verifymod /etc/jsac/Initialize.conf、且认证服务端口443也不存在


脚本三：
用例名称：验证开启认证开关对正常业务的影响
编写人员：马丹丹
编写日期：2021/7/15
测试目的：验证开启认证开关对正常业务的影响
测试步骤：
1.开启认证服务，通过命令ps -ef | grep verifymod、netstat -ultpn查询服务进程及服务端口是否存在
2.下发根证书文件到设备上
3.使用命令export cardid=0&&switch-jsac --set --switch on --module 13开启靠近客户端卡上的认证开关
4.客户端向认证服务器发起认证请求，请求命令curl --cert /opt/test2certandkey.pem:123456 https://www.testCA.cn:443
5.用命令tail -1 /var/log/jsac.verifymod.log查询网关设备认证日志文件 及用命令ipauth-jsac --auth --show查询认证ip表
6.客户端向服务端发起http请求验证联通性，请求命令curl http://{dip}:80 >/opt/verifymod_curl.txt
7.使用命令ipauth-jsac --clear将记录的认证ip清除掉
8.再次从客户端向服务端发起http请求验证联通性,请求命令curl http://{dip}:80 >/opt/verifymod_curl.txt
9.使用命令export cardid=0&&switch-jsac --set --switch off --module 13关闭靠近客户端卡上的认证开关
10.移除根证书文件
11.关闭认证服务，通过命令ps -ef | grep verifymod、netstat -ultpn查询服务进程及服务端口是否存在
12.使用命令rm -f /opt/verifymod*.txt，在客户端删除第6步http请求结果的文件/opt/verifymod*.txt
预期结果：
1.认证服务开启成功，服务进程有/usr/local/ipauth/verifymod /etc/jsac/Initialize.conf、服务有监听443端口说明服务开启成功
2.根证书下发成功，ls /usr/local/ipauth/file/CAdb/可以查看到证书md5值c970dfa3234ed84ccac2e819a1276026
3.使用命令export cardid=0&&switch-jsac --get检查有“13   IP_AUTH_MODULE     1    in     on”说明认证开关开启成功
4.认证请求返回结果verify success说明请求发送成功
5.日志查询到"jsacaudit 源ip success"，认证ip表查询到源ip说明认证成功
6.服务端nginx服务返回结果为Welcome to nginx!说明http联通性正常
7.使用命令ipauth-jsac --auth --show查询不到认证ip说明ip清除成功
8.服务端nginx服务没有返回结果Welcome to nginx!说明http联通失败
9.使用命令export cardid=0&&switch-jsac --get检查有“13   IP_AUTH_MODULE     1    in     off”说明认证开关关闭成功
10.根证书移除成功，ls /usr/local/ipauth/file/CAdb/无法查到证书md5值c970dfa3234ed84ccac2e819a1276026
11.认证服务关闭成功，查询不到服务进程/usr/local/ipauth/verifymod /etc/jsac/Initialize.conf、且认证服务端口443也不存在
12.使用命令ls /opt/ |grep txt在客户端查询不到文件/opt/verifymod*.txt说明删除成功


脚本四：
用例名称：验证移除根证书后，认证请求功能
编写人员：马丹丹
编写日期：2021/7/15
测试目的：验证开启认证开关对正常业务的影响
测试步骤：
1.开启认证服务，通过命令ps -ef | grep verifymod、netstat -ultpn查询服务进程及服务端口是否存在
2.下发根证书文件到设备上
3.客户端向认证服务器发起认证请求，请求命令curl --cert /opt/test2certandkey.pem:123456 https://www.testCA.cn:443
4.用命令tail -1 /var/log/jsac.verifymod.log查询网关设备认证日志文件 及用命令ipauth-jsac --auth --show查询认证ip表
5.使用命令ipauth-jsac --clear将记录的认证ip清除掉
6.移除根证书文件
7.再次从客户端向认证服务器发起认证请求，请求命令curl --cert /opt/test2certandkey.pem:123456 https://www.testCA.cn:443
8.用命令tail -1 /var/log/jsac.verifymod.log查询网关设备认证日志文件 及用命令ipauth-jsac --auth --show查询认证ip表
9.关闭认证服务，通过命令ps -ef | grep verifymod、netstat -ultpn查询服务进程及服务端口是否存在
预期结果：
1.认证服务开启成功，服务进程有/usr/local/ipauth/verifymod /etc/jsac/Initialize.conf、服务有监听443端口说明服务开启成功
2.根证书下发成功，ls /usr/local/ipauth/file/CAdb/可以查看到证书md5值c970dfa3234ed84ccac2e819a1276026
3.认证请求返回结果verify success说明请求发送成功
4.日志查询到"jsacaudit 源ip success"，认证ip表查询到源ip说明认证成功
5.使用命令ipauth-jsac --auth --show查询不到认证ip说明ip清除成功
6.根证书移除成功，ls /usr/local/ipauth/file/CAdb/无法查到证书md5值c970dfa3234ed84ccac2e819a1276026
7.认证请求返回结果无verify success说明请求发送正常
8.日志查询到"jsacaudit 源ip fail"，认证ip表查询不到源ip说明正常
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
	from verifymod_function_test import index
	from verifymod_function_test import message
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

class Test_verifymod_function():

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
        fun.cmd(self.case3_step3["step1"][0], 'gw')
        fun.cmd(self.case1_step6["step1"][1], 'gw')
        fun.send(rbmExc, message.verifymod_DelAuthCert['DelAuthCert'], domain_rmb, base_path)
        clr_env.verifymod_teardown_met(base_path)

        fun.cmd("rm -f /opt/verifymod*.txt", 'c')
        re1 = fun.cmd("ls /opt/ |grep txt", 'c')
        assert self.case3_step2["step2"][0] not in re1

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
        self.case2_step1 = index.case2_step1
        self.case2_step2 = index.case2_step2
        self.case2_step3 = index.case2_step3
        self.case2_step4 = index.case2_step4
        self.case3_step1 = index.case3_step1
        self.case3_step2 = index.case3_step2
        self.case3_step3 = index.case3_step3

    # @pytest.mark.skip(reseason="skip")
    @allure.feature('验证正常情况下的认证服务功能')
    def test_verifymod_normal_function(self):

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

        print('3.客户端向认证服务器发起认证请求，请求命令curl --cert /opt/test2certandkey.pem:123456 https://www.testCA.cn:443，认证请求返回结果verify success说明请求发送成功')
        print('发送认证url：',self.case1_step4["step1"][0])
        for key in self.case1_step4:
            re1 = fun.cmd(self.case1_step4[key][0],'c')
            print(re1)
            assert self.case1_step4[key][1] in re1

        print('4.用命令tail -1 /var/log/jsac.verifymod.log查询网关设备认证日志文件 及用命令ipauth-jsac --auth --show查询认证ip表，日志查询到"jsacaudit 源ip success"，认证ip表查询到源ip说明认证成功')
        fun.wait_data(self.case1_step5["step1"][0],'gw', self.case1_step5["step1"][1], '检查认证日志', 100)
        for key in self.case1_step5:
            re1 = fun.cmd(self.case1_step5[key][0],'gw')
            assert self.case1_step5[key][1] in re1
        fun.wait_data(self.case1_step6["step1"][0], 'gw', self.case1_step6["step1"][2], '检查认证ip', 100)
        for key in self.case1_step6:
            re1 = fun.cmd(self.case1_step6[key][0], 'gw')
            assert self.case1_step6[key][2] in re1


        print('5.使用命令ipauth-jsac --clear将记录的认证ip清除掉，使用命令ipauth-jsac --auth --show查询不到认证源ip说明ip清除成功')
        fun.wait_data(self.case1_step6["step1"][1], 'gw', self.case1_step6["step1"][3], '检查认证ip', 100)
        for key in self.case1_step6:
            re1 = fun.cmd(self.case1_step6[key][0], 'gw')
            print(re1)
            assert self.case1_step6[key][2] not in re1


        print('6.移除根证书文件，根证书移除成功，ls /usr/local/ipauth/file/CAdb/无法查到证书md5值c970dfa3234ed84ccac2e819a1276026')
        fun.send(rbmExc, message.verifymod_DelAuthCert['DelAuthCert'], domain_rmb, base_path)
        # 检查配置下发是否成功
        for key in self.case1_step3:
            re1 = fun.wait_data(self.case1_step3[key][0], 'gw', self.case1_step3[key][1], '移除根证书', 100 , flag='不存在')
            assert self.case1_step3[key][1] not in re1

        # 关闭认证服务
        print('7.关闭认证服务，通过命令ps -ef | grep verifymod、netstat -ultpn查询不到服务进程/usr/local/ipauth/verifymod /etc/jsac/Initialize.conf、且认证服务端口443也不存在')
        fun.send(rbmExc, message.verifymod_switch_stop['ManageAuthServer'], domain_rmb, base_path)
        # 检查配置下发是否成功
        for key in self.case1_step1:
            re1 = fun.wait_data(self.case1_step1[key][0], 'gw', self.case1_step1[key][1], '检查认证服务进程', 100, flag='不存在')
            assert self.case1_step1[key][1] not in re1
        for key in self.case1_step2:
            re2 = fun.wait_data(self.case1_step2[key][0], 'gw', self.case1_step2[key][1], '检查认证监听端口', 100, flag='不存在')
            assert self.case1_step2[key][1] not in re2





    # @pytest.mark.skip(reseason="skip")
    @allure.feature('验证异常情况下的认证服务功能')
    def test_verifymod_abnormal_function(self):

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

        print('3.客户端向认证服务器发起异常认证请求1,其中使用错误的客户端证书，请求命令curl --cert /opt/gwdifferentCA.pem:123456 https://www.testCA.cn:443,认证请求返回结果无verify success说明正常')
        print('发送认证url：', self.case2_step1["step1"][0])
        re1 = fun.cmd(self.case2_step1["step1"][0], 'c')
        assert self.case2_step1["step1"][1] not in re1


        print('4.用命令tail -1 /var/log/jsac.verifymod.log查询网关设备认证日志文件 及用命令ipauth-jsac --auth --show查询认证ip表，日志查询到"jsacaudit 源ip fail"，认证ip表查询不到源ip说明正常')
        fun.wait_data(self.case2_step4["step1"][0], 'gw', self.case2_step4["step1"][1], '检查认证日志', 100)
        for key in self.case2_step4:
            re1 = fun.cmd(self.case2_step4[key][0], 'gw')
            assert self.case2_step4[key][1] in re1
        fun.wait_data(self.case1_step6["step1"][0], 'gw', self.case1_step6["step1"][2], '检查认证ip', 100 ,flag='不存在')
        for key in self.case1_step6:
            re1 = fun.cmd(self.case1_step6[key][0], 'gw')
            assert self.case1_step6[key][2] not in re1

        print('5.客户端向认证服务器发起异常认证请求2,其中使用错误的证书密码，请求命令curl --cert /opt/test2certandkey.pem:666666 https://www.testCA.cn:443,认证请求返回结果无verify success说明正常')
        print('发送认证url：', self.case2_step2["step1"][0])
        re1 = fun.cmd(self.case2_step2["step1"][0], 'c')
        assert self.case2_step2["step1"][1] not in re1

        print('6.用命令tail -1 /var/log/jsac.verifymod.log查询网关设备认证日志文件 及用命令ipauth-jsac --auth --show查询认证ip表，日志查询到"jsacaudit 源ip fail"，认证ip表查询不到源ip说明正常')
        fun.wait_data(self.case2_step4["step1"][0], 'gw', self.case2_step4["step1"][1], '检查认证日志', 100)
        for key in self.case2_step4:
            re1 = fun.cmd(self.case2_step4[key][0], 'gw')
            assert self.case2_step4[key][1] in re1
        fun.wait_data(self.case1_step6["step1"][0], 'gw', self.case1_step6["step1"][2], '检查认证ip', 100, flag='不存在')
        for key in self.case1_step6:
            re1 = fun.cmd(self.case1_step6[key][0], 'gw')
            assert self.case1_step6[key][2] not in re1

        print("7.客户端向认证服务器发起异常认证请求3,其中使用错误的认证服务域名，请求命令curl --cert /opt/test2certandkey.pem:666666 https://www.test.cn:443,认证请求返回结果无verify success说明正常")
        print('发送认证url：', self.case2_step3["step1"][0])
        re1 = fun.cmd(self.case2_step3["step1"][0], 'c')
        assert self.case2_step3["step1"][1] not in re1

        print('8.用命令tail -1 /var/log/jsac.verifymod.log查询网关设备认证日志文件 及用命令ipauth-jsac --auth --show查询认证ip表，日志查询到"jsacaudit 源ip fail"，认证ip表查询不到源ip说明正常')
        fun.wait_data(self.case2_step4["step1"][0], 'gw', self.case2_step4["step1"][1], '检查认证日志', 100)
        for key in self.case2_step4:
            re1 = fun.cmd(self.case2_step4[key][0], 'gw')
            assert self.case2_step4[key][1] in re1
        fun.wait_data(self.case1_step6["step1"][0], 'gw', self.case1_step6["step1"][2], '检查认证ip', 100, flag='不存在')
        for key in self.case1_step6:
            re1 = fun.cmd(self.case1_step6[key][0], 'gw')
            assert self.case1_step6[key][2] not in re1


        print('9.移除根证书文件，根证书移除成功，ls /usr/local/ipauth/file/CAdb/无法查到证书md5值c970dfa3234ed84ccac2e819a1276026')
        fun.send(rbmExc, message.verifymod_DelAuthCert['DelAuthCert'], domain_rmb, base_path)
        # 检查配置下发是否成功
        for key in self.case1_step3:
            re1 = fun.wait_data(self.case1_step3[key][0], 'gw', self.case1_step3[key][1], '移除根证书', 100, flag='不存在')
            assert self.case1_step3[key][1] not in re1

        # 关闭认证服务
        print('10.关闭认证服务，通过命令ps -ef | grep verifymod、netstat -ultpn查询不到服务进程/usr/local/ipauth/verifymod /etc/jsac/Initialize.conf、且认证服务端口443也不存在')
        fun.send(rbmExc, message.verifymod_switch_stop['ManageAuthServer'], domain_rmb, base_path)
        # 检查配置下发是否成功
        for key in self.case1_step1:
            re1 = fun.wait_data(self.case1_step1[key][0], 'gw', self.case1_step1[key][1], '检查认证服务进程', 100, flag='不存在')
            assert self.case1_step1[key][1] not in re1
        for key in self.case1_step2:
            re2 = fun.wait_data(self.case1_step2[key][0], 'gw', self.case1_step2[key][1], '检查认证监听端口', 100, flag='不存在')
            assert self.case1_step2[key][1] not in re2







    # @pytest.mark.skip(reseason="skip")
    @allure.feature('验证开启认证开关对正常业务的影响')
    def test_verifymod_switch(self):

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

        print('3.使用命令export cardid=0&&switch-jsac --set --switch on --module 13开启靠近客户端卡上的认证开关，使用命令export cardid=0&&switch-jsac --get检查有“13   IP_AUTH_MODULE     1    in     on”说明认证开关开启成功')
        for key in self.case3_step1:
            fun.cmd(self.case3_step1[key][0], 'gw')
            re1 = fun.cmd(self.case3_step1[key][1], 'gw')
            print(re1)
            assert self.case3_step1[key][2] in re1

        print('4.客户端向认证服务器发起认证请求，请求命令curl --cert /opt/test2certandkey.pem:123456 https://www.testCA.cn:443，认证请求返回结果verify success说明请求发送成功')
        print('发送认证url：', self.case1_step4["step1"][0])
        for key in self.case1_step4:
            re1 = fun.cmd(self.case1_step4[key][0], 'c')
            print(re1)
            assert self.case1_step4[key][1] in re1

        print('5.用命令tail -1 /var/log/jsac.verifymod.log查询网关设备认证日志文件 及用命令ipauth-jsac --auth --show查询认证ip表，日志查询到"jsacaudit 源ip success"，认证ip表查询到源ip说明认证成功')
        fun.wait_data(self.case1_step5["step1"][0], 'gw', self.case1_step5["step1"][1], '检查认证日志', 100)
        for key in self.case1_step5:
            re1 = fun.cmd(self.case1_step5[key][0], 'gw')
            assert self.case1_step5[key][1] in re1
        fun.wait_data(self.case1_step6["step1"][0], 'gw', self.case1_step6["step1"][2], '检查认证ip', 100)
        for key in self.case1_step6:
            re1 = fun.cmd(self.case1_step6[key][0], 'gw')
            assert self.case1_step6[key][2] in re1

        print('6.客户端向服务端发起http请求验证联通性，请求命令curl http://{dip}:80 >/opt/verifymod_curl.txt，服务端nginx服务返回结果为Welcome to nginx!说明http联通性正常')
        print('发送http请求',self.case3_step2["step1"][0])
        fun.cmd(self.case3_step2["step1"][0], 'c')
        re = fun.wait_data(self.case3_step2["step"][1], 'c', self.case3_step2["curl"][2], '检查http请求', 100)
        assert self.case3_step2["step"][2] in re
        print('正常http请求发送成功')

        print('7.使用命令ipauth-jsac --clear将记录的认证ip清除掉，使用命令ipauth-jsac --auth --show查询不到认证ip说明ip清除成功')
        fun.wait_data(self.case1_step6["step1"][1], 'gw', self.case1_step6["step1"][3], '检查认证ip', 100)
        for key in self.case1_step6:
            re1 = fun.cmd(self.case1_step6[key][0], 'gw')
            print(re1)
            assert self.case1_step6[key][2] not in re1

        print('8.再次从客户端向服务端发起http请求验证联通性,请求命令curl http://{dip}:80 >/opt/verifymod_curl.txt，服务端nginx服务没有返回结果Welcome to nginx!说明http联通失败')
        print('发送http请求', self.case3_step2["step1"][0])
        fun.cmd(self.case3_step2["step1"][0], 'c')
        re = fun.wait_data(self.case3_step2["step"][1], 'c', self.case3_step2["curl"][2], '检查http请求', 100 ,flag='不存在')
        assert self.case3_step2["step"][2] not in re
        print('http请求发送失败')

        print('9.使用命令export cardid=0&&switch-jsac --set --switch off --module 13关闭靠近客户端卡上的认证开关，使用命令export cardid=0&&switch-jsac --get检查有“13   IP_AUTH_MODULE     1    in     off”说明认证开关关闭成功')
        for key in self.case3_step3:
            print(self.case3_step3[key][0])
            re1 = fun.cmd(self.case3_step3[key][0], 'gw')
            assert self.case3_step3[key][1] in re1


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

        # 删除/opt/cipso_curl.txt文件
        print('12.使用命令rm -f /opt/verifymod*.txt，在客户端删除第6步http请求结果的文件/opt/verifymod*.txt，使用命令ls /opt/ |grep txt在客户端查询不到文件/opt/verifymod*.txt说明删除成功')
        fun.cmd("rm -f /opt/verifymod*.txt", 'c')
        re1 = fun.cmd("ls /opt/ |grep txt", 'c')
        print('客户端txt文件查询结果是:', re1)
        assert self.case3_step2["step2"][0] not in re1




    # @pytest.mark.skip(reseason="skip")
    @allure.feature('验证移除根证书后，认证请求功能')
    def test_verifymod_DelAuthCert_function(self):
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

        print('3.客户端向认证服务器发起认证请求，请求命令curl --cert /opt/test2certandkey.pem:123456 https://www.testCA.cn:443，认证请求返回结果verify success说明请求发送成功')
        print('发送认证url：', self.case1_step4["step1"][0])
        for key in self.case1_step4:
            re1 = fun.cmd(self.case1_step4[key][0], 'c')
            print(re1)
            assert self.case1_step4[key][1] in re1

        print('4.用命令tail -1 /var/log/jsac.verifymod.log查询网关设备认证日志文件 及用命令ipauth-jsac --auth --show查询认证ip表，日志查询到"jsacaudit 源ip success"，认证ip表查询到源ip说明认证成功')
        fun.wait_data(self.case1_step5["step1"][0], 'gw', self.case1_step5["step1"][1], '检查认证日志', 100)
        for key in self.case1_step5:
            re1 = fun.cmd(self.case1_step5[key][0], 'gw')
            assert self.case1_step5[key][1] in re1
        fun.wait_data(self.case1_step6["step1"][0], 'gw', self.case1_step6["step1"][2], '检查认证ip', 100)
        for key in self.case1_step6:
            re1 = fun.cmd(self.case1_step6[key][0], 'gw')
            assert self.case1_step6[key][2] in re1

        print('5.使用命令ipauth-jsac --clear将记录的认证ip清除掉，使用命令ipauth-jsac --auth --show查询不到认证ip说明ip清除成功')
        fun.send(rbmExc, message.verifymod_DropAuthIp['DropAuthIp'], domain_rmb, base_path)
        fun.wait_data(self.case1_step6["step1"][0], 'gw', self.case1_step6["step1"][2], '检查认证ip', 100, flag='不存在')
        for key in self.case1_step6:
            re1 = fun.cmd(self.case1_step6[key][0], 'gw')
            assert self.case1_step6[key][2] not in re1

        print('6.移除根证书文件，根证书移除成功，ls /usr/local/ipauth/file/CAdb/无法查到证书md5值c970dfa3234ed84ccac2e819a1276026')
        fun.send(rbmExc, message.verifymod_DelAuthCert['DelAuthCert'], domain_rmb, base_path)
        # 检查配置下发是否成功
        for key in self.case1_step3:
            re1 = fun.wait_data(self.case1_step3[key][0], 'gw', self.case1_step3[key][1], '移除根证书', 100, flag='不存在')
            assert self.case1_step3[key][1] not in re1

        print('7.再次从客户端向认证服务器发起认证请求，请求命令curl --cert /opt/test2certandkey.pem:123456 https://www.testCA.cn:443，认证请求返回结果无verify success说明请求发送正常')
        print('发送认证url：', self.case1_step4["step1"][0])
        for key in self.case1_step4:
            re1 = fun.cmd(self.case1_step4[key][0], 'c')
            print(re1)
            assert self.case1_step4[key][1] not in re1

        print('8.用命令tail -1 /var/log/jsac.verifymod.log查询网关设备认证日志文件 及用命令ipauth-jsac --auth --show查询认证ip表，日志查询到"jsacaudit 源ip fail"，认证ip无源ip说明正常')
        fun.wait_data(self.case2_step4["step1"][0], 'gw', self.case2_step4["step1"][1], '检查认证日志', 100)
        for key in self.case2_step4:
            re1 = fun.cmd(self.case2_step4[key][0], 'gw')
            assert self.case2_step4[key][1] in re1
        fun.wait_data(self.case1_step6["step1"][0], 'gw', self.case1_step6["step1"][2], '检查认证ip', 100 ,flag='不存在')
        for key in self.case1_step6:
            re1 = fun.cmd(self.case1_step6[key][0], 'gw')
            assert self.case1_step6[key][2] not in re1

        # 关闭认证服务
        print('9.关闭认证服务，通过命令ps -ef | grep verifymod、netstat -ultpn查询不到服务进程/usr/local/ipauth/verifymod /etc/jsac/Initialize.conf、且认证服务端口443也不存在')
        fun.send(rbmExc, message.verifymod_switch_stop['ManageAuthServer'], domain_rmb, base_path)
        # 检查配置下发是否成功
        for key in self.case1_step1:
            re1 = fun.wait_data(self.case1_step1[key][0], 'gw', self.case1_step1[key][1], '检查认证服务进程', 100,flag='不存在')
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
