'''
脚本一：
用例名称：验证管理口标记BLP模型时的标记过滤功能
编写人员：马丹丹
编写日期：2021/7/8
测试目的：验证管理口标记BLP模型时的标记过滤功能
测试步骤：
1.客户端下发管理口标记策略，命令iptables -I POSTROUTING -t mangle -p tcp -j CIPSO --doi 16 --level 12 --cat 0x78a,0x6c,0x88e,0x601 -d {cipso_dip} --dport 80
2.服务端下发管理口标记策略，命令iptables -I PREROUTING -t mangle -p tcp -m cipso --doi 16 --level 20 --blp --inc  --cat 0x78a,0x6c,0x88e,0x601 -s {cipso_sip} --dport 80 -j CIPSO --rm
3.在客户端使用curl命令发送http请求验证联通性，命令curl http://{cipso_dip}:80 >/opt/cipso_blp_biba.txt
4.客户端移除管理口标记策略，命令iptables -D POSTROUTING -t mangle -p tcp -j CIPSO --doi 16 --level 12 --cat 0x78a,0x6c,0x88e,0x601 -d {cipso_dip} --dport 80
5.服务端移除管理口标记策略，命令iptables -D PREROUTING -t mangle -p tcp -m cipso --doi 16 --level 20 --blp --inc  --cat 0x78a,0x6c,0x88e,0x601 -s {cipso_sip} --dport 80 -j CIPSO --rm
6.客户端使用命令rm -f /opt/cipso*.txt删除第3步生成的文件
预期结果：
1.客户端管理口标记策略下发成功，可以使用iptables -t mangle -nL命令查看策略包含level 12
2.服务端管理口标记策略下发成功，可以使用iptables -t mangle -nL命令查看策略包含blp
3.http请求成功，服务端nginx服务返回结果为Welcome to nginx!即为正常
4.客户端移除策略成功，可以使用iptables -t mangle -nL命令查看策略不包含level 12
5.服务端移除策略成功，可以使用iptables -t mangle -nL命令查看策略不包含blp
6.客户端使用命令ls /opt/ |grep txt查询不到cipso_blp_biba.txt说明文件删除成功

脚本二：
用例名称：验证管理口标记BIBA模型时的标记过滤功能
编写人员：马丹丹
编写日期：2021/7/8
测试目的：验证管理口标记BIBA模型时的标记过滤功能
测试步骤：
1.客户端下发管理口标记策略，命令iptables -I POSTROUTING -t mangle -p tcp -j CIPSO --doi 16 --level 22 --cat 0x78a,0x6c,0x88e,0x601 -d {cipso_dip} --dport 80
2.服务端下发管理口标记策略，命令iptables -I PREROUTING -t mangle -p tcp -m cipso --doi 16 --level 10 --biba --inc  --cat 0x78a,0x6c,0x88e,0x601 -s {cipso_sip} --dport 80 -j CIPSO --rm
3.在客户端使用curl命令发送http请求验证联通性，命令curl http://{cipso_dip}:80 >/opt/cipso_blp_biba.txt
4.客户端移除管理口标记策略，命令iptables -D POSTROUTING -t mangle -p tcp -j CIPSO --doi 16 --level 22 --cat 0x78a,0x6c,0x88e,0x601 -d {cipso_dip} --dport 80
5.服务端移除管理口标记策略，命令iptables -D PREROUTING -t mangle -p tcp -m cipso --doi 16 --level 10 --biba --inc  --cat 0x78a,0x6c,0x88e,0x601 -s {cipso_sip} --dport 80 -j CIPSO --rm
6.客户端使用命令rm -f /opt/cipso*.txt删除第3步生成的文件
预期结果：
1.客户端管理口标记策略下发成功，可以使用iptables -t mangle -nL命令查看策略包含level 12
2.服务端管理口标记策略下发成功，可以使用iptables -t mangle -nL命令查看策略包含biba
3.http请求成功，服务端nginx服务返回结果为Welcome to nginx!即为正常
4.客户端移除策略成功，可以使用iptables -t mangle -nL命令查看策略不包含level 12
5.服务端移除策略成功，可以使用iptables -t mangle -nL命令查看策略不包含biba
6.客户端使用命令ls /opt/ |grep txt查询不到cipso_blp_biba.txt说明文件删除成功
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
	from cipso_blp_biba import index
	from cipso_blp_biba import message
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


class Test_cipso_blp_biba():

	def setup_method(self):
		clr_env.clear_env('gw')
		clr_env.clear_met_acl('gw')


	def teardown_method(self):

		clr_env.clear_env('gw')
		clr_env.clear_met_acl('gw')

		fun.cmd(self.case_step["step1"][0], 'c')
		fun.cmd(self.case_step["step1"][0], 's')


	def setup_class(self):
		#获取参数
		fun.ssh_gw.connect()
		fun.ssh_c.connect()
		fun.ssh_s.connect()
		# fun.rbm.connect()
		self.case_step = index.case_step
		self.case1_step1 = index.case1_step1
		self.case1_step2 = index.case1_step2
		self.case1_step3 = index.case1_step3
		self.case1_step4 = index.case1_step4
		self.case2_step1 = index.case2_step1
		self.case2_step2 = index.case2_step2
		self.case2_step3 = index.case2_step3
		self.case2_step4 = index.case2_step4
		self.cipso = index.cipso



	# @pytest.mark.skip(reseason="skip")
	@allure.feature(' 验证管理口标记BLP模型时的标记过滤功能')
	def test_cipso_blp(self):

		# 下发配置并检查结果
		print('1.客户端下发管理口标记策略，命令iptables -I POSTROUTING -t mangle -p tcp -j CIPSO --doi 16 --level 12 --cat 0x78a,0x6c,0x88e,0x601 -d {cipso_dip} --dport 80，使用iptables -t mangle -nL命令查看策略包含level 12')
		fun.cmd(self.case1_step1["step1"][0],'c')
		for key in self.case1_step1:
			re0 = fun.cmd(self.case1_step1[key][1], 'c')
			print(re0)
			assert self.case1_step1[key][2] in re0

		print('2.服务端下发管理口标记策略，命令iptables -I PREROUTING -t mangle -p tcp -m cipso --doi 16 --level 20 --blp --inc  --cat 0x78a,0x6c,0x88e,0x601 -s {cipso_sip} --dport 80 -j CIPSO --rm，可以使用iptables -t mangle -nL命令查看策略包含blp')
		fun.cmd(self.case1_step2["step1"][0], 's')
		for key in self.case1_step2:
			re0 = fun.cmd(self.case1_step2[key][1], 's')
			print(re0)
			assert self.case1_step2[key][2] in re0

		# 客户端发送http请求
		print('3.在客户端使用curl命令发送http请求，命令curl http://{cipso_dip}:80 >/opt/cipso_blp_biba.txt，服务端nginx服务返回结果为Welcome to nginx!即为正常')
		print(self.cipso["curl"][0])
		fun.cmd(self.cipso["curl"][0],'c')
		re = fun.wait_data(self.cipso["curl"][1], 'c', self.cipso["curl"][2], '检查http请求', 100)
		assert self.cipso["curl"][2] in re
		print('正常http请求发送成功')

		# 移除策略
		print('4.客户端移除管理口标记策略，命令iptables -D POSTROUTING -t mangle -p tcp -j CIPSO --doi 16 --level 12 --cat 0x78a,0x6c,0x88e,0x601 -d {cipso_dip} --dport 80，使用iptables -t mangle -nL命令查看策略不包含level 12')
		fun.cmd(self.case1_step3["step1"][0],'c')
		for key in self.case1_step3:
			re0 = fun.cmd(self.case1_step3[key][1],'c')
			print(re0)
			assert self.case1_step3[key][2] not in re0

		print('5.服务端移除管理口标记策略，命令iptables -D PREROUTING -t mangle -p tcp -m cipso --doi 16 --level 20 --blp --inc  --cat 0x78a,0x6c,0x88e,0x601 -s {cipso_sip} --dport 80 -j CIPSO --rm，使用iptables -t mangle -nL命令查看策略不包含blp')
		fun.cmd(self.case1_step4["step1"][0], 's')
		for key in self.case1_step3:
			re0 = fun.cmd(self.case1_step4[key][1], 's')
			print(re0)
			assert self.case1_step4[key][2] not in re0

		#删除/opt/cipso_curl.txt文件
		print('6.客户端使用命令rm -f /opt/cipso*.txt删除第3步生成的文件，使用命令ls /opt/ |grep txt查询不到cipso_blp_biba.txt说明文件删除成功')
		fun.cmd("rm -f /opt/cipso*.txt", 'c')
		re1 = fun.cmd("ls /opt/ |grep txt", 'c')
		print('客户端txt文件查询结果是:', re1)
		assert self.cipso["txt"][0] not in re1



	# @pytest.mark.skip(reseason="skip")
	@allure.feature(' 验证管理口标记BIBA模型时的标记过滤功能')
	def test_cipso_biba(self):

		# 下发配置并检查结果
		print('1.客户端下发管理口标记策略，命令iptables -I POSTROUTING -t mangle -p tcp -j CIPSO --doi 16 --level 22 --cat 0x78a,0x6c,0x88e,0x601 -d {cipso_dip} --dport 80，使用iptables -t mangle -nL命令查看策略包含level 12')
		fun.cmd(self.case2_step1["step1"][0], 'c')
		for key in self.case2_step1:
			re0 = fun.cmd(self.case2_step1[key][1], 'c')
			print(re0)
			assert self.case2_step1[key][2] in re0

		print('2.服务端下发管理口标记策略，命令iptables -I PREROUTING -t mangle -p tcp -m cipso --doi 16 --level 10 --biba --inc  --cat 0x78a,0x6c,0x88e,0x601 -s {cipso_sip} --dport 80 -j CIPSO --rm，使用iptables -t mangle -nL命令查看策略包含biba')
		fun.cmd(self.case2_step2["step1"][0], 's')
		for key in self.case2_step2:
			re0 = fun.cmd(self.case2_step2[key][1], 's')
			print(re0)
			assert self.case2_step2[key][2] in re0

		# 客户端发送http请求
		print('3.在客户端使用curl命令发送http请求，命令curl http://{cipso_dip}:80 >/opt/cipso_blp_biba.txt，服务端nginx服务返回结果为Welcome to nginx!即为正常')
		print(self.cipso["curl"][0])
		fun.cmd(self.cipso["curl"][0], 'c')
		re = fun.wait_data(self.cipso["curl"][1], 'c', self.cipso["curl"][2], '检查http请求', 100)
		assert self.cipso["curl"][2] in re
		print('正常http请求发送成功')

		# 移除策略
		print('4.客户端移除管理口标记策略，命令iptables -D POSTROUTING -t mangle -p tcp -j CIPSO --doi 16 --level 22 --cat 0x78a,0x6c,0x88e,0x601 -d {cipso_dip} --dport 80，使用iptables -t mangle -nL命令查看策略不包含level 12')
		fun.cmd(self.case2_step3["step1"][0], 'c')
		for key in self.case2_step3:
			re0 = fun.cmd(self.case2_step3[key][1], 'c')
			print(re0)
			assert self.case2_step3[key][2] not in re0

		print('5.服务端移除管理口标记策略，命令iptables -D PREROUTING -t mangle -p tcp -m cipso --doi 16 --level 10 --biba --inc  --cat 0x78a,0x6c,0x88e,0x601 -s {cipso_sip} --dport 80 -j CIPSO --rm，使用iptables -t mangle -nL命令查看策略不包含biba')
		fun.cmd(self.case2_step4["step1"][0], 's')
		for key in self.case2_step3:
			re0 = fun.cmd(self.case2_step4[key][1], 's')
			print(re0)
			assert self.case2_step4[key][2] not in re0

		#删除/opt/cipso_curl.txt文件
		print('6.客户端使用命令rm -f /opt/cipso*.txt删除第3步生成的文件，使用命令ls /opt/ |grep txt查询不到cipso_blp_biba.txt说明文件删除成功')
		fun.cmd("rm -f /opt/cipso*.txt", 'c')
		re1 = fun.cmd("ls /opt/ |grep txt", 'c')
		print('客户端txt文件查询结果是:', re1)
		assert self.cipso["txt"][0] not in re1





	def teardown_class(self):
		#回收环境
		# fun.rbm_close()
		fun.ssh_close('c')
		fun.ssh_close('s')
		fun.ssh_close('gw')