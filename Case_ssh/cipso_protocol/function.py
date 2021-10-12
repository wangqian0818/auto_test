'''
脚本一：
用例名称：验证管理口标记对tcp协议报文的处理能力(cat字段包含64位后)
编写人员：马丹丹
编写日期：2021/7/13
测试目的：验证管理口标记对tcp协议报文的处理能力(cat字段包含64位后)
测试步骤：
1.客户端下发管理口标记策略，命令iptables -I POSTROUTING -t mangle -p tcp -j CIPSO --doi 16 --level 12 --cat 0x15,0xc5,0x79,0x81 -d {cipso_dip} --dport 80
2.服务端下发管理口标记策略，命令iptables -I PREROUTING -t mangle -p tcp -m cipso --doi 16 --level 20 --blp --inc  --cat 0x15,0xc5,0x79,0x81 -s {cipso_sip} --dport 80 -j CIPSO --rm
3.在客户端使用curl命令发送http请求验证联通性，命令curl http://{cipso_dip}:80 >/opt/cipso_tcp.txt
4.客户端移除管理口标记策略，命令iptables -D POSTROUTING -t mangle -p tcp -j CIPSO --doi 16 --level 12 --cat 0x15,0xc5,0x79,0x81 -d {cipso_dip} --dport 80
5.服务端移除管理口标记策略，命令iptables -D PREROUTING -t mangle -p tcp -m cipso --doi 16 --level 20 --blp --inc  --cat 0x15,0xc5,0x79,0x81 -s {cipso_sip} --dport 80 -j CIPSO --rm
6.rm -f /opt/cipso*.txt在客户端删除第3步http请求结果的文件
预期结果：
1.客户端管理口标记策略下发成功，可以使用iptables -t mangle -nL命令查看策略包含tcp
2.服务端管理口标记策略下发成功，可以使用iptables -t mangle -nL命令查看策略包含tcp
3.http请求成功，服务端nginx服务返回结果为Welcome to nginx!即为正常
4.客户端移除策略成功，可以使用iptables -t mangle -nL命令查看策略不包含tcp
5.服务端移除策略成功，可以使用iptables -t mangle -nL命令查看策略不包含tcp
6.ls /opt/ |grep txt客户端查询不包含cipso_tcp.txt说明文件删除成功

脚本二：
用例名称：验证管理口标记对icmp协议报文的处理能力(cat字段包含64位后)
编写人员：马丹丹
编写日期：2021/7/13
测试目的：验证管理口标记对icmp协议报文的处理能力(cat字段包含64位后)
测试步骤：
1.客户端下发管理口标记策略，命令iptables -I POSTROUTING -t mangle -p icmp -j CIPSO --doi 16 --level 12 --cat 0x15,0xc5,0x79,0x81 -d {cipso_dip}
2.服务端下发管理口标记策略，命令iptables -I PREROUTING -t mangle -p icmp -m cipso --doi 16 --level 20 --blp --inc  --cat 0x15,0xc5,0x79,0x81 -s {cipso_sip} -j CIPSO --rm
3.在客户端使用ping命令发送icmp请求验证联通性，命令ping -c 2 {cipso_dip} > /opt/cipso_icmp.txt
4.客户端移除管理口标记策略，命令iptables -D POSTROUTING -t mangle -p icmp -j CIPSO --doi 16 --level 12 --cat 0x15,0xc5,0x79,0x81 -d {cipso_dip}
5.服务端移除管理口标记策略，命令iptables -D PREROUTING -t mangle -p icmp -m cipso --doi 16 --level 20 --blp --inc  --cat 0x15,0xc5,0x79,0x81 -s {cipso_sip} -j CIPSO --rm
6.rm -f /opt/cipso*.txt在客户端删除第3步icmp请求结果的文件
预期结果：
1.客户端管理口标记策略下发成功，可以使用iptables -t mangle -nL命令查看策略包含icmp
2.服务端管理口标记策略下发成功，可以使用iptables -t mangle -nL命令查看策略包含icmp
3.icmp请求成功，服务端nginx服务返回结果为64 bytes from 服务端ip: icmp_seq=1 ttl=64即为正常
4.客户端移除策略成功，可以使用iptables -t mangle -nL命令查看策略不包含icmp
5.服务端移除策略成功，可以使用iptables -t mangle -nL命令查看策略不包含icmp
6.ls /opt/ |grep txt客户端查询不包含cipso_icmp.txt说明文件删除成功

脚本三：
用例名称：验证管理口标记对icmp协议报文的处理能力(cat字段不包含64位后)
编写人员：马丹丹
编写日期：2021/7/13
测试目的：验证管理口标记对icmp协议报文的处理能力(cat字段不包含64位后)
测试步骤：
1.客户端下发管理口标记策略，命令iptables -I POSTROUTING -t mangle -p icmp -j CIPSO --doi 16 --level 12 --cat 0xa9,0x0,0x0,0x0 -d {cipso_dip}
2.服务端下发管理口标记策略，命令iptables -I PREROUTING -t mangle -p icmp -m cipso --doi 16 --level 20 --blp --inc  --cat 0xa9,0x0,0x0,0x0 -s {cipso_sip} -j CIPSO --rm
3.在客户端使用ping命令发送icmp请求验证联通性，命令ping -c 2 {cipso_dip} > /opt/cipso_icmp.txt
4.客户端移除管理口标记策略，命令iptables -D POSTROUTING -t mangle -p icmp -j CIPSO --doi 16 --level 12 --cat 0xa9,0x0,0x0,0x0 -d {cipso_dip}
5.服务端移除管理口标记策略，命令iptables -D PREROUTING -t mangle -p icmp -m cipso --doi 16 --level 20 --blp --inc  --cat 0xa9,0x0,0x0,0x0 -s {cipso_sip} -j CIPSO --rm
6.rm -f /opt/cipso*.txt在客户端删除第3步icmp请求结果的文件
预期结果：
1.客户端管理口标记策略下发成功，可以使用iptables -t mangle -nL命令查看策略包含icmp
2.服务端管理口标记策略下发成功，可以使用iptables -t mangle -nL命令查看策略包含icmp
3.icmp请求成功，服务端nginx服务返回结果为64 bytes from 服务端ip: icmp_seq=1 ttl=64即为正常
4.客户端移除策略成功，可以使用iptables -t mangle -nL命令查看策略不包含icmp
5.服务端移除策略成功，可以使用iptables -t mangle -nL命令查看策略不包含icmp
6.ls /opt/ |grep txt客户端查询不包含cipso_icmp.txt说明文件删除成功
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
	from cipso_protocol import index
	from cipso_protocol import message
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
# port_attack=index.attack_port


class Test_protocol():

	def setup_method(self):
		clr_env.clear_env('gw')
		clr_env.clear_met_acl('gw')


	def teardown_method(self):

		clr_env.clear_env('gw')
		clr_env.clear_met_acl('gw')

		fun.cmd(self.case_step["step1"][0], 'c')
		fun.cmd(self.case_step["step1"][0], 's')

		fun.cmd("rm -f /opt/cipso*.txt", 'c')
		re1 = fun.cmd("ls /opt/ |grep txt", 'c')
		print('客户端txt文件查询结果是:', re1)
		assert self.case_step1["step1"][0] not in re1
		assert self.case_step1["step1"][1] not in re1
		assert self.case_step1["step1"][2] not in re1

	def setup_class(self):
		#获取参数
		fun.ssh_gw.connect()
		fun.ssh_c.connect()
		fun.ssh_s.connect()
		# fun.rbm.connect()
		self.case_step = index.case_step
		self.case_step1 = index.case_step1
		self.case1_step1 = index.case1_step1
		self.case1_step2 = index.case1_step2
		self.case1_step3 = index.case1_step3
		self.case1_step4 = index.case1_step4
		self.case2_step1 = index.case2_step1
		self.case2_step2 = index.case2_step2
		self.case2_step3 = index.case2_step3
		self.case2_step4 = index.case2_step4
		self.case3_step1 = index.case3_step1
		self.case3_step2 = index.case3_step2
		self.case3_step3 = index.case3_step3
		self.case3_step4 = index.case3_step4
		self.cipso_tcp = index.cipso_tcp
		self.cipso_icmp = index.cipso_icmp

	# @pytest.mark.skip(reseason="skip")
	@allure.feature('验证管理口标记对tcp协议报文的处理能力(cat字段包含64位后)')
	def test_tcp_cat64(self):

		# 下发配置并检查结果
		print('1.客户端下发管理口标记策略，命令iptables -I POSTROUTING -t mangle -p tcp -j CIPSO --doi 16 --level 12 --cat 0x15,0xc5,0x79,0x81 -d {cipso_dip} --dport 80，使用iptables -t mangle -nL命令查看策略包含tcp')
		fun.cmd(self.case1_step1["step1"][0],'c')
		for key in self.case1_step1:
			re0 = fun.cmd(self.case1_step1[key][1], 'c')
			print(re0)
			assert self.case1_step1[key][2] in re0

		print('2.服务端下发管理口标记策略，命令iptables -I PREROUTING -t mangle -p tcp -m cipso --doi 16 --level 20 --blp --inc  --cat 0x15,0xc5,0x79,0x81 -s {cipso_sip} --dport 80 -j CIPSO --rm，使用iptables -t mangle -nL命令查看策略包含tcp')
		fun.cmd(self.case1_step2["step1"][0], 's')
		for key in self.case1_step2:
			re0 = fun.cmd(self.case1_step2[key][1], 's')
			print(re0)
			assert self.case1_step2[key][2] in re0

		# 客户端发送http请求
		print('3.在客户端使用curl命令发送http请求，命令curl http://{cipso_dip}:80 >/opt/cipso_tcp.txt，服务端nginx服务返回结果为Welcome to nginx!即为正常')
		print(self.cipso_tcp["curl"][0])
		fun.cmd(self.cipso_tcp["curl"][0],'c')
		re = fun.wait_data(self.cipso_tcp["curl"][1], 'c', self.cipso_tcp["curl"][2], '检查http请求', 100)
		assert self.cipso_tcp["curl"][2] in re
		print('正常http请求发送成功')

		# 移除策略
		print('4.客户端移除管理口标记策略，命令iptables -D POSTROUTING -t mangle -p tcp -j CIPSO --doi 16 --level 12 --cat 0x15,0xc5,0x79,0x81 -d {cipso_dip} --dport 80，使用iptables -t mangle -nL命令查看策略不包含tcp')
		fun.cmd(self.case1_step3["step1"][0],'c')
		for key in self.case1_step3:
			re0 = fun.cmd(self.case1_step3[key][1],'c')
			print(re0)
			assert self.case1_step3[key][2] not in re0

		print('5.服务端移除管理口标记策略，命令iptables -I PREROUTING -t mangle -p tcp -m cipso --doi 16 --level 20 --blp --inc  --cat 0x15,0xc5,0x79,0x81 -s {cipso_sip} --dport 80 -j CIPSO --rm，使用iptables -t mangle -nL命令查看策略不包含tcp')
		fun.cmd(self.case1_step4["step1"][0], 's')
		for key in self.case1_step4:
			re0 = fun.cmd(self.case1_step4[key][1], 's')
			print(re0)
			assert self.case1_step4[key][2] not in re0

		#删除/opt/cipso_curl.txt文件
		print('6.rm -f /opt/cipso*.txt在客户端删除第3步http请求结果的文件，ls /opt/ |grep txt客户端查询不包含cipso_tcp.txt说明文件删除成功')
		fun.cmd("rm -f /opt/cipso*.txt", 'c')
		re1 = fun.cmd("ls /opt/ |grep txt", 'c')
		print('客户端txt文件查询结果是:', re1)
		assert self.cipso_tcp["txt"][0] not in re1




	# @pytest.mark.skip(reseason="skip")
	@allure.feature(' 验证管理口标记对icmp协议报文的处理能力(cat字段包含64位后)')
	def test_cipso_icmp_cat64(self):

		# 下发配置并检查结果
		print('1.客户端下发管理口标记策略，命令iptables -I POSTROUTING -t mangle -p icmp -j CIPSO --doi 16 --level 12 --cat 0x15,0xc5,0x79,0x81 -d {cipso_dip}，使用iptables -t mangle -nL命令查看策略包含icmp')
		fun.cmd(self.case2_step1["step1"][0], 'c')
		for key in self.case2_step1:
			re0 = fun.cmd(self.case2_step1[key][1], 'c')
			print(re0)
			assert self.case2_step1[key][2] in re0

		print('2.服务端下发管理口标记策略，命令iptables -I PREROUTING -t mangle -p icmp -m cipso --doi 16 --level 20 --blp --inc  --cat 0x15,0xc5,0x79,0x81 -s {cipso_sip} -j CIPSO --rm，使用iptables -t mangle -nL命令查看策略包含icmp')
		fun.cmd(self.case2_step2["step1"][0], 's')
		for key in self.case2_step2:
			re0 = fun.cmd(self.case2_step2[key][1], 's')
			print(re0)
			assert self.case2_step2[key][2] in re0

		# 客户端发送请求
		print('3.在客户端使用ping命令发送icmp请求，命令ping -c 2 {cipso_dip} > /opt/cipso_icmp.txt，服务端nginx服务返回结果为64 bytes from 服务端ip: icmp_seq=1 ttl=64即为正常')
		print(self.cipso_icmp["ping"][0])
		fun.cmd(self.cipso_icmp["ping"][0], 'c')
		re = fun.wait_data(self.cipso_icmp["ping"][1], 'c', self.cipso_icmp["ping"][2], '检查icmp请求', 100)
		assert self.cipso_icmp["ping"][2] in re
		print('ICMP请求发送成功')

		# 移除策略
		print('4.客户端移除管理口标记策略，命令iptables -D POSTROUTING -t mangle -p icmp -j CIPSO --doi 16 --level 12 --cat 0x15,0xc5,0x79,0x81 -d {cipso_dip}，使用iptables -t mangle -nL命令查看策略不包含icmp')
		fun.cmd(self.case2_step3["step1"][0], 'c')
		for key in self.case2_step3:
			re0 = fun.cmd(self.case2_step3[key][1], 'c')
			print(re0)
			assert self.case2_step3[key][2] not in re0

		print('5.服务端移除管理口标记策略，命令iptables -D PREROUTING -t mangle -p icmp -m cipso --doi 16 --level 20 --blp --inc  --cat 0x15,0xc5,0x79,0x81 -s {cipso_sip} -j CIPSO --rm，使用iptables -t mangle -nL命令查看策略不包含icmp')
		fun.cmd(self.case2_step4["step1"][0], 's')
		for key in self.case2_step4:
			re0 = fun.cmd(self.case2_step4[key][1], 's')
			print(re0)
			assert self.case2_step4[key][2] not in re0

		# 删除/opt/cipso_curl.txt文件
		print('6.rm -f /opt/cipso*.txt在客户端删除第3步http请求结果的文件，ls /opt/ |grep txt客户端查询不包含cipso_icmp.txt说明文件删除成功')
		fun.cmd("rm -f /opt/cipso*.txt", 'c')
		re1 = fun.cmd("ls /opt/ |grep txt", 'c')
		print('客户端txt文件查询结果是:', re1)
		assert self.cipso_icmp["txt"][0] not in re1





	# @pytest.mark.skip(reseason="skip")
	@allure.feature(' 验证管理口标记对icmp协议报文的处理能力(cat字段不包含64位后)')
	def test_cipso_icmp(self):

		# 下发配置并检查结果
		print('1.客户端下发管理口标记策略，命令iptables -I POSTROUTING -t mangle -p icmp -j CIPSO --doi 16 --level 12 --cat 0xa9,0x0,0x0,0x0 -d {cipso_dip}，使用iptables -t mangle -nL命令查看策略包含icmp')
		fun.cmd(self.case3_step1["step1"][0], 'c')
		for key in self.case3_step1:
			re0 = fun.cmd(self.case3_step1[key][1], 'c')
			print(re0)
			assert self.case3_step1[key][2] in re0

		print('2.服务端下发管理口标记策略，命令iptables -I PREROUTING -t mangle -p icmp -m cipso --doi 16 --level 20 --blp --inc  --cat 0xa9,0x0,0x0,0x0 -s {cipso_sip} -j CIPSO --rm，使用iptables -t mangle -nL命令查看策略包含imcp')
		fun.cmd(self.case3_step2["step1"][0], 's')
		for key in self.case3_step2:
			re0 = fun.cmd(self.case3_step2[key][1], 's')
			print(re0)
			assert self.case3_step2[key][2] in re0

		# 客户端发送http请求
		print('3.在客户端使用ping命令发送icmp请求，命令ping -c 2 {cipso_dip} > /opt/cipso_icmp.txt，服务端nginx服务返回结果为64 bytes from 服务端ip: icmp_seq=1 ttl=64即为正常')
		print(self.cipso_icmp["ping"][0])
		fun.cmd(self.cipso_icmp["ping"][0], 'c')
		re = fun.wait_data(self.cipso_icmp["ping"][1], 'c', self.cipso_icmp["ping"][2], '检查icmp请求', 100)
		assert self.cipso_icmp["ping"][2] in re
		print('ICMP请求发送成功')

		# 移除策略
		print('4.客户端移除管理口标记策略，命令iptables -D POSTROUTING -t mangle -p icmp -j CIPSO --doi 16 --level 12 --cat 0xa9,0x0,0x0,0x0 -d {cipso_dip}，使用iptables -t mangle -nL命令查看策略不包含icmp')
		fun.cmd(self.case3_step3["step1"][0], 'c')
		for key in self.case3_step3:
			re0 = fun.cmd(self.case3_step3[key][1], 'c')
			print(re0)
			assert self.case3_step3[key][2] not in re0

		print('5.服务端移除管理口标记策略，命令iptables -D PREROUTING -t mangle -p icmp -m cipso --doi 16 --level 20 --blp --inc  --cat 0xa9,0x0,0x0,0x0 -s {cipso_sip} -j CIPSO --rm，使用iptables -t mangle -nL命令查看策略不包含imcp')
		fun.cmd(self.case3_step4["step1"][0], 's')
		for key in self.case3_step4:
			re0 = fun.cmd(self.case3_step4[key][1], 's')
			print(re0)
			assert self.case3_step4[key][2] not in re0

		# 删除/opt/cipso_curl.txt文件
		print('6.rm -f /opt/cipso*.txt在客户端删除第3步http请求结果的文件，ls /opt/ |grep txt客户端查询不包含cipso_icmp.txt说明文件删除成功')
		fun.cmd("rm -f /opt/cipso*.txt", 'c')
		re1 = fun.cmd("ls /opt/ |grep txt", 'c')
		print('客户端txt文件查询结果是:', re1)
		assert self.cipso_icmp["txt"][0] not in re1





	# @pytest.mark.skip(reseason="skip")
	# @allure.feature(' 验证管理口标记对udp协议报文的处理能力(cat字段包含64位后)')
	# def test_cipso_udp(self):
	#
	# 	# 下发配置并检查结果
	# 	print('1.客户端下发管理口标记策略，标记详情为udp协议的打标策略，可以使用iptables -t mangle -nL命令查看策略详情')
	# 	fun.cmd(self.case4_step1["step1"][0], 'c')
	# 	for key in self.case4_step1:
	# 		re0 = fun.cmd(self.case4_step1[key][1], 'c')
	# 		print(re0)
	# 		assert self.case4_step1[key][2] in re0
	#
	# 	print('2.服务端下发管理口标记策略，标记详情为udp协议的去标策略，可以使用iptables -t mangle -nL命令查看策略详情')
	# 	fun.cmd(self.case4_step2["step1"][0], 's')
	# 	for key in self.case4_step2:
	# 		re0 = fun.cmd(self.case4_step2[key][1], 's')
	# 		print(re0)
	# 		assert self.case4_step2[key][2] in re0
	#
	# 	# 客户端发送http请求
	# 	print('3.在服务端开启udp监听端口，可以使用netstat -ultpn检查端口监听情况')
	# 	print('服务端开启udp监听端口：',self.cipso_udp["udp-s"][1])
	# 	fun.cmd(self.cipso_udp["udp-s"][1], 's',thread=1)
	# 	for key in self.case4_step5:
	# 		re0 = fun.cmd(self.case4_step5[key][0],'s')
	# 		print(re0)
	# 		assert self.case4_step5[key][1] in re0
	#
	# 	print('客户端发送udp报文：',self.cipso_udp["udp-c"][0])
	# 	fun.cmd(self.cipso_udp["udp-c"][0], 'c')
	# 	re = fun.wait_data(self.cipso_udp["udp-c"][1], 'c', self.cipso_udp["udp-c"][2], '检查udp请求', 100)
	# 	assert self.cipso_udp["udp-c"][2] in re
	# 	print('正常udp请求发送成功')

	# fun.cmd(self.cipso_udp["udp-s"][2], 's')
	# re = fun.wait_data(self.cipso_udp["udp-s"][2], 'c', self.cipso_udp["udp-s"][3], '检查udp接收情况', 100)
	# assert self.cipso_udp["udp-s"][3] in re
	# print('udp接收成功')
	# fun.cmd('exit','s')
	#
	# # 移除策略
	# print('4.客户端移除管理口标记策略，可以使用iptables -t mangle -nL命令查看策略详情')
	# fun.cmd(self.case4_step3["step1"][0], 'c')
	# for key in self.case4_step3:
	# 	re0 = fun.cmd(self.case4_step3[key][1], 'c')
	# 	print(re0)
	# 	assert self.case4_step3[key][2] not in re0
	#
	# print('5.服务端移除管理口标记策略，可以使用iptables -t mangle -nL命令查看策略详情')
	# fun.cmd(self.case4_step4["step1"][0], 's')
	# for key in self.case4_step3:
	# 	re0 = fun.cmd(self.case4_step4[key][1], 's')
	# 	print(re0)
	# 	assert self.case4_step4[key][2] not in re0
	#
	# #删除/opt/cipso_curl.txt文件
	# print('6.在客户端删除第3步http请求结果的文件/opt/cipso*.txt')
	# fun.cmd("rm -f /opt/cipso*.txt", 'c')
	# re1 = fun.cmd("ls /opt/ |grep txt", 'c')
	# print('客户端txt文件查询结果是:', re1)
	# assert self.cipso_udp["txt"][0] not in re1





	def teardown_class(self):
		#回收环境
		# fun.rbm_close()
		fun.ssh_close('c')
		fun.ssh_close('s')
		fun.ssh_close('gw')