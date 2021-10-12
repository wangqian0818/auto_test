'''
脚本一：
用例名称：验证管理口标记与网关设备业务口之间对于标记的处理能力
编写人员：马丹丹
编写日期：2021/7/12
测试目的：验证管理口标记与网关设备业务口之间对于标记的处理能力
测试步骤：
1.客户端下发管理口标记策略，命令iptables -I POSTROUTING -t mangle -p tcp -j CIPSO --doi 16 --level 12 --cat 0xe7,0x90,0xf1,0x36 -d {pcap_dip} --dport 80
2.客户端下发管理口标记策略，命令iptables -I PREROUTING -t mangle -p tcp  -s {pcap_dip} --sport {dport} -j CIPSO --rm
3.在网关设备靠近客户端的网卡上下发acl策略，命令tupleacl --add --sip {pcap_sip} --dip {pcap_dip} --dp 80 --l4p 6 --action forward --netlbl strip --drop on --mode BLP --doi 16 --level 16 --type 1 --value 0xe7,0x90,0xf1,0x36
4.在客户端使用curl命令发送http请求验证联通性，命令curl http://{pcap_dip}:80 >/opt/cipso_gw_tcp.txt
5.客户端移除管理口标记策略，命令iptables -D POSTROUTING -t mangle -p tcp -j CIPSO --doi 16 --level 12 --cat 0xe7,0x90,0xf1,0x36 -d {pcap_dip} --dport 80
命令iptables -D PREROUTING -t mangle -p tcp  -s {pcap_dip} --sport {dport} -j CIPSO --rm
6.网关设备移除acl标记策略，使用命令export cardid=0&&tupleacl --clear
7.rm -f /opt/cipso*.txt在客户端删除第4步http请求结果的文件
预期结果：
1.客户端管理口打标策略下发成功，可以使用iptables -t mangle -nL命令查看策略包含0xe7,0x90,0xf1,0x36
2.客户端管理口去标策略下发成功，可以使用iptables -t mangle -nL命令查看策略包含rm
3.网关设备acl去标策略下发成功，可以使用export cardid=0&&tupleacl --get命令查看策略包含目的ip{pcap_dip}
4.http请求成功，服务端nginx服务返回结果为Welcome to nginx!即为正常
5.客户端移除策略成功，可以使用iptables -t mangle -nL命令查看策略不包含目的ip{pcap_dip}
6.网关设备移除策略成功，可以使用tupleacl --get命令查看策略不包含目的ip{pcap_dip}
7.ls /opt/ |grep txt命令查询不到cipso_gw_tcp.txt说明文件删除成功
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
	from cipso_gw import index
	from cipso_gw import message
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
#sys.path.append(os.getcwd())sys.path.append(os.getcwd())

from common import clr_env
from common import baseinfo
from common.rabbitmq import *


# pcap_sip = baseinfo.clientOpeIp
pcap_dip = baseinfo.serverOpeIp
domain_rmb=baseinfo.rbmDomain
Exc_rmb=baseinfo.rbmExc
port_attack=index.attack_port


class Test_gw():

	def setup_method(self):
		clr_env.clear_env('gw')
		clr_env.clear_met_acl('gw')


	def teardown_method(self):

		clr_env.clear_env('gw')
		clr_env.clear_met_acl('gw')

		fun.cmd(self.case1_step4["step1"][0], 'gw')
		fun.cmd(self.case_step["step1"][0], 'c')
		fun.cmd("rm -f /opt/*txt*", 'c')
		re1 = fun.cmd("ls /opt/ |grep txt", 'c')
		print('客户端txt文件查询结果是:', re1)
		assert self.case_step1["step1"][0] not in re1

	def setup_class(self):
		#获取参数
		fun.ssh_gw.connect()
		fun.ssh_c.connect()
		# fun.ssh_s.connect()
		# fun.rbm.connect()
		self.case_step = index.case_step
		self.case_step1 = index.case_step1
		self.case1_step1 = index.case1_step1
		self.case1_step2 = index.case1_step2
		self.case1_step3 = index.case1_step3
		self.case1_step4 = index.case1_step4
		self.cipso_tcp = index.cipso_tcp


	# @pytest.mark.skip(reseason="skip")
	@allure.feature('验证管理口标记与网关设备业务口之间对于标记的处理能力')
	def test_gw(self):

		# 下发配置并检查结果
		print('1.客户端下发管理口标记策略，命令iptables -I POSTROUTING -t mangle -p tcp -j CIPSO --doi 16 --level 12 --cat 0xe7,0x90,0xf1,0x36 -d {pcap_dip} --dport 80，使用iptables -t mangle -nL命令查看策略包含0xe7,0x90,0xf1,0x36')
		fun.cmd(self.case1_step1["step1"][0],'c')
		for key in self.case1_step1:
			re0 = fun.cmd(self.case1_step1["step1"][1], 'c')
			print(re0)
			assert self.case1_step1["step1"][2] in re0

		print('2.客户端下发管理口标记策略，命令iptables -I PREROUTING -t mangle -p tcp  -s {pcap_dip} --sport 80 -j CIPSO --rm，使用iptables -t mangle -nL命令查看策略包含rm')
		fun.cmd(self.case1_step1["step2"][0], 'c')
		for key in self.case1_step1:
			re0 = fun.cmd(self.case1_step1["step2"][1], 'c')
			print(re0)
			assert self.case1_step1["step2"][2] in re0


		print('3.在网关设备靠近客户端的网卡上下发acl策略，命令tupleacl --add --sip {pcap_sip} --dip {pcap_dip} --dp 80 --l4p 6 --action forward --netlbl strip --drop on --mode BLP --doi 16 --level 16 --type 1 --value 0xe7,0x90,0xf1,0x36\n'
			  '，export cardid=0&&tupleacl --get命令查看策略包含目的ip')
		fun.cmd(self.case1_step2["step1"][0],'gw')
		for key in self.case1_step2:
			re0 = fun.cmd(self.case1_step2[key][1], 'gw')
			print(re0)
			assert self.case1_step2[key][2] in re0


		# 客户端发送http请求
		print('4.在客户端使用curl命令发送http请求，命令curl http://{pcap_dip}:80 >/opt/cipso_gw_tcp.txt，服务端nginx服务返回结果为Welcome to nginx!即为正常')
		print(self.cipso_tcp["curl"][0])
		fun.cmd(self.cipso_tcp["curl"][0],'c')
		re = fun.wait_data(self.cipso_tcp["curl"][1], 'c', self.cipso_tcp["curl"][2], '检查http请求', 100)
		assert self.cipso_tcp["curl"][2] in re
		print('正常http请求发送成功')

		# 移除策略
		print('5.客户端移除管理口标记策略，命令iptables -D POSTROUTING -t mangle -p tcp -j CIPSO --doi 16 --level 12 --cat 0xe7,0x90,0xf1,0x36 -d {pcap_dip} --dport 80,\n'
			  '命令iptables -D PREROUTING -t mangle -p tcp  -s {pcap_dip} --sport {dport} -j CIPSO --rm可以使用iptables -t mangle -nL命令查看策略不包含目的ip')
		fun.cmd(self.case1_step3["step1"][0],'c')
		fun.cmd(self.case1_step3["step2"][0], 'c')
		for key in self.case1_step3:
			re0 = fun.cmd(self.case1_step3["step2"][1],'c')
			print(re0)
			assert self.case1_step3["step2"][2] not in re0

		print('6.网关设备使用命令export cardid=0&&tupleacl --clear移除acl标记策略，网关设备移除策略成功，可以使用tupleacl --get命令查看策略不包含目的ip')
		fun.cmd(self.case1_step4["step1"][0],'gw')
		for key in self.case1_step4:
			re0 = fun.cmd(self.case1_step4[key][1], 'gw')
			print(re0)
			assert self.case1_step4[key][2] not in re0

		print('7.rm -f /opt/cipso*.txt在客户端删除第4步http请求结果的文件,ls /opt/ |grep txt命令查询不到cipso_gw_tcp.txt说明文件删除成功')
		#删除/opt/cipso_curl.txt文件
		fun.cmd("rm -f /opt/cipso*.txt", 'c')
		re1 = fun.cmd("ls /opt/ |grep txt", 'c')
		print('客户端txt文件查询结果是:', re1)
		assert self.cipso_tcp["txt"][0] not in re1



	def teardown_class(self):
		#回收环境
		# fun.rbm_close()
		fun.ssh_close('c')
		# fun.ssh_close('s')
		fun.ssh_close('gw')