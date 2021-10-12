'''
脚本一
用例名称：边界保护系统开启DDoS防御，RST Flood攻击测试
编写人员：马丹丹
编写日期：2021/7/9
测试目的：验证边界保护系统开启DDoS防御，RST Flood攻击测试
测试步骤：
1.网关设备开启ddos防御开关、fwlog抗攻击日志上报开关，使用defconf --show查看结果
2.使用hping3工具发送RST Flood攻击命令hping3 -R 服务端ip -p 攻击端口 --faster -c 6000
3.在客户端使用curl命令发送http请求，验证联通性
4.检查/var/log/jsac.agentjsac.info.log日志中ReportDdosEvent上报结果
5.网关设备关闭ddos防御开关、fwlog抗攻击日志上报开关，使用defconf --show查看结果
预期结果：
1.检查到以下开关为开启状态说明开关开启成功：syn-cookie: on、filter noflow: on、check no option: on、firewall-log: on
2.hping3命令发送成功返回结果R set
3.http请求成功，服务端nginx服务返回结果为Welcome to nginx!即为正常
4.日志中检查到有RST Flood字段说明日志上报正确
5.检查到以下开关为关闭状态说明开关关闭成功：syn-cookie: off、filter noflow: off、check no option: off、firewall-log: off

脚本二
用例名称：边界保护系统开启DDoS防御，ACK Flood攻击测试
编写人员：马丹丹
编写日期：2021/7/9
测试目的：验证边界保护系统开启DDoS防御，ACK Flood攻击测试
测试步骤：
1.网关设备开启ddos防御开关、fwlog抗攻击日志上报开关，使用defconf --show查看结果
2.使用hping3工具发送ACK Flood攻击命令hping3 -A 服务端ip -p 攻击端口 --faster -c 6000
3.在客户端使用curl命令发送http请求，验证联通性
4.检查/var/log/jsac.agentjsac.info.log日志中ReportDdosEvent上报结果
5.网关设备关闭ddos防御开关、fwlog抗攻击日志上报开关，使用defconf --show查看结果
预期结果：
1.检查到以下开关为开启状态说明开关开启成功：syn-cookie: on、filter noflow: on、check no option: on、firewall-log: on
2.hping3命令发送成功返回结果A set
3.http请求成功，服务端nginx服务返回结果为Welcome to nginx!即为正常
4.日志中检查到有ACK Flood字段说明日志上报正确
5.检查到以下开关为关闭状态说明开关关闭成功：syn-cookie: off、filter noflow: off、check no option: off、firewall-log: off

用例名称：边界保护系统开启DDoS防御，SYN Flood攻击测试
编写人员：马丹丹
编写日期：2021/7/9
测试目的：验证边界保护系统开启DDoS防御，SYN Flood攻击测试
测试步骤：
1.网关设备开启ddos防御开关、fwlog抗攻击日志上报开关，使用defconf --show查看结果
2.使用hping3工具发送SYN Flood攻击命令hping3 -S 服务端ip -p 攻击端口 --faster -c 6000
3.在客户端使用curl命令发送http请求，验证联通性
4.检查/var/log/jsac.agentjsac.info.log日志中ReportDdosEvent上报结果
5.网关设备关闭ddos防御开关、fwlog抗攻击日志上报开关，使用defconf --show查看结果
预期结果：
1.检查到以下开关为开启状态说明开关开启成功：syn-cookie: on、filter noflow: on、check no option: on、firewall-log: on
2.hping3命令发送成功返回结果S set
3.http请求成功，服务端nginx服务返回结果为Welcome to nginx!即为正常
4.日志中检查到有Syn Flood字段说明日志上报正确
5.检查到以下开关为关闭状态说明开关关闭成功：syn-cookie: off、filter noflow: off、check no option: off、firewall-log: off
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
	from firewall_ddos_attack import index
	from firewall_ddos_attack import message
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


class Test_ddos_attack():

	def setup_method(self):
		clr_env.clear_env('gw')
		clr_env.clear_met_acl('gw')


	def teardown_method(self):

		clr_env.clear_env('gw')
		clr_env.clear_met_acl('gw')

		fun.cmd("rm -f /opt/*txt*", 'c')
		re1 = fun.cmd("ls /opt/ |grep txt", 'c')
		print('客户端txt文件查询结果是:', re1)
		assert self.case_step2["step1"][0] not in re1

	def setup_class(self):
		#获取参数
		fun.ssh_gw.connect()
		fun.ssh_c.connect()
		# fun.ssh_s.connect()
		# fun.rbm.connect()
		self.case_step = index.case_step
		self.case_step1 = index.case_step1
		self.case_step2 = index.case_step2
		self.case1_step1 = index.case1_step1
		self.case2_step1 = index.case2_step1
		self.case3_step1 = index.case3_step1
		self.ddos1_rst = index.ddos1_rst
		self.ddos2_ack = index.ddos2_ack
		self.ddos3_syn = index.ddos3_syn


	# @pytest.mark.skip(reseason="skip")
	@allure.feature('边界保护系统开启DDoS防御，RST Flood攻击测试')
	def test_ddos_rst_flood(self):

		# 下发配置并检查结果
		print("1.网关设备开启ddos防御开关、fwlog抗攻击日志上报开关，使用defconf --show查看开关开启")
		fun.cmd(self.ddos1_rst["fwlog"][0],'gw')
		fun.send(Exc_rmb,message.setddos_open['SetDdosEnable'], domain_rmb, base_path)
		for key in self.case_step:
			re0 = fun.cmd(self.case_step[key][0], 'gw')
			print(re0)
			assert self.case_step[key][1] in re0
			assert self.case_step[key][2] in re0
			assert self.case_step[key][3] in re0
			assert self.case_step[key][4] in re0

		# 客户端发送攻击命令
		print("2.使用hping3工具发送RST Flood攻击命令hping3 -R 目的ip -p 攻击端口 --faster -c 6000，返回结果R set")
		fun.cmd(self.ddos1_rst["hping3"][0], 'c')
		# print('/////////////////////////////////')
		re = fun.wait_data(self.ddos1_rst["hping3"][1], 'c', self.ddos1_rst["hping3"][2], '检查RST FLOOD攻击发送', 100)
		assert self.ddos1_rst["hping3"][2] in re
		print('hping3 RST Flood攻击命令下发成功')

		# 客户端发送http请求
		print("3.使用curl工具发送正常http请求，返回结果为Welcome to nginx!表示http请求成功")
		print(self.ddos1_rst["curl"][0])
		fun.cmd(self.ddos1_rst["curl"][0],'c')
		re = fun.wait_data(self.ddos1_rst["curl"][1], 'c', self.ddos1_rst["curl"][2], '检查http请求', 100 )
		assert self.ddos1_rst["curl"][2] in re
		print('正常http请求发送成功')

		# 检查抗攻击日志
		print("4.检查/var/log/jsac.agentjsac.info.log日志中ReportDdosEvent上报结果，检查到有RST Flood字段说明日志上报正确")
		fun.wait_data('grep -n ReportDdosEvent /var/log/jsac.agentjsac.info.log |tail -1', 'gw',self.case1_step1['step1'][0], '检查RST Flood', 300, flag='存在')
		for key in self.case1_step1:
			re = fun.cmd('grep -n ReportDdosEvent /var/log/jsac.agentjsac.info.log |tail -1', 'gw')
			print('re:', re)
			assert self.case1_step1[key][0] in re

		print("5.网关设备关闭ddos防御开关、fwlog抗攻击日志上报开关，使用defconf --show查看开关关闭")
		fun.cmd(self.ddos1_rst["fwlog"][1],'gw')
		fun.send(Exc_rmb,message.setddos_close['SetDdosEnable'], domain_rmb, base_path)
		for key in self.case_step1:
			re0 = fun.cmd(self.case_step1[key][0], 'gw')
			print(re0)
			assert self.case_step1[key][1] in re0
			assert self.case_step1[key][2] in re0
			assert self.case_step1[key][3] in re0
			assert self.case_step1[key][4] in re0

		#删除/opt/ddos_*.txt文件
		fun.cmd("rm -f /opt/*txt*", 'c')
		re1 = fun.cmd("ls /opt/ |grep txt", 'c')
		print('客户端txt文件查询结果是:', re1)
		assert self.ddos1_rst["txt"][0] not in re1
		assert self.ddos1_rst["txt"][1] not in re1




	# @pytest.mark.skip(reseason="skip")
	@allure.feature('边界保护系统开启DDoS防御，ACK Flood攻击测试')
	def test_ddos_ack_flood(self):

		# 下发配置并检查结果
		print("1.开启ddos防御开关、fwlog抗攻击日志上报开关，使用defconf --show查看开关开启")
		fun.cmd(self.ddos2_ack["fwlog"][0], 'gw')
		fun.send(Exc_rmb, message.setddos_open['SetDdosEnable'], domain_rmb, base_path)
		for key in self.case_step:
			re0 = fun.cmd(self.case_step[key][0], 'gw')
			print(re0)
			assert self.case_step[key][1] in re0
			assert self.case_step[key][2] in re0
			assert self.case_step[key][3] in re0
			assert self.case_step[key][4] in re0

		# 客户端发送攻击命令
		print("2.使用hping3工具发送ACK Flood攻击命令hping3 -A 目的ip -p 攻击端口 --faster -c 6000，返回结果A set")
		fun.cmd(self.ddos2_ack["hping3"][0], 'c')
		re = fun.wait_data(self.ddos2_ack["hping3"][1], 'c', self.ddos2_ack["hping3"][2], '检查ACK FLOOD攻击发送', 100)
		assert self.ddos2_ack["hping3"][2] in re
		print('hping3 ACK Flood攻击命令下发成功')

		# 客户端发送http请求
		print("3.使用curl工具发送正常http请求，返回结果为Welcome to nginx!表示http请求成功")
		print(self.ddos2_ack["curl"][0])
		fun.cmd(self.ddos2_ack["curl"][0],'c')
		re = fun.wait_data(self.ddos2_ack["curl"][1], 'c', self.ddos2_ack["curl"][2], '检查http请求', 100)
		assert self.ddos2_ack["curl"][2] in re
		print('正常http请求发送成功')

		# 检查抗攻击日志
		print("4.检查/var/log/jsac.agentjsac.info.log日志中ReportDdosEvent上报结果，检查到有ACK Flood字段说明日志上报正确")
		fun.wait_data('grep -n ReportDdosEvent /var/log/jsac.agentjsac.info.log |tail -1', 'gw', self.case2_step1['step1'][0], '检查ACK Flood', 300, flag='存在')
		for key in self.case2_step1:
			re = fun.cmd('grep -n ReportDdosEvent /var/log/jsac.agentjsac.info.log |tail -1', 'gw')
			print('re:', re)
			assert self.case2_step1[key][0] in re

		print("5.网关设备关闭ddos防御开关、fwlog抗攻击日志上报开关，使用defconf --show查看开关关闭")
		fun.cmd(self.ddos1_rst["fwlog"][1],'gw')
		fun.send(Exc_rmb,message.setddos_close['SetDdosEnable'], domain_rmb, base_path)
		for key in self.case_step1:
			re0 = fun.cmd(self.case_step1[key][0], 'gw')
			print(re0)
			assert self.case_step1[key][1] in re0
			assert self.case_step1[key][2] in re0
			assert self.case_step1[key][3] in re0
			assert self.case_step1[key][4] in re0

		#删除/opt/ddos_*.txt文件
		fun.cmd("rm -f /opt/*txt*", 'c')
		re1 = fun.cmd("ls /opt/ |grep txt", 'c')
		print('客户端txt文件查询结果是:', re1)
		assert self.ddos2_ack["txt"][0] not in re1
		assert self.ddos2_ack["txt"][1] not in re1




	# @pytest.mark.skip(reseason="skip")
	@allure.feature('边界保护系统开启DDoS防御，Syn Flood攻击测试')
	def test_ddos_syn_flood(self):

		# 下发配置并检查结果
		print("1.开启ddos防御开关、fwlog抗攻击日志上报开关，使用defconf --show查看开关开启")
		fun.cmd(self.ddos2_ack["fwlog"][0], 'gw')
		fun.send(Exc_rmb, message.setddos_open['SetDdosEnable'], domain_rmb, base_path)
		for key in self.case_step:
			re0 = fun.cmd(self.case_step[key][0], 'gw')
			print(re0)
			assert self.case_step[key][1] in re0
			assert self.case_step[key][2] in re0
			assert self.case_step[key][3] in re0
			assert self.case_step[key][4] in re0

		# 客户端发送攻击命令
		print("2.使用hping3工具发送SYN Flood攻击命令hping3 -S 目的ip -p 攻击端口 --faster -c 6000，返回结果S set")
		fun.cmd(self.ddos3_syn["hping3"][0], 'c')
		# fun.cmd(f"hping3 -i u1000 -SA -p {port_attack} {pcap_dip} --rand-source --tcp-timestamp", 'c')
		re = fun.wait_data(self.ddos3_syn["hping3"][1], 'c', self.ddos3_syn["hping3"][2], '检查ACK FLOOD攻击发送', 100)
		assert self.ddos3_syn["hping3"][2] in re
		print('hping3 Syn Flood攻击命令下发成功')

		# 客户端发送http请求
		print("3.使用curl工具发送正常http请求，返回结果为Welcome to nginx!表示http请求成功")
		print(self.ddos3_syn["curl"][0])
		fun.cmd(self.ddos3_syn["curl"][0],'c')
		re = fun.wait_data(self.ddos3_syn["curl"][1], 'c', self.ddos3_syn["curl"][2], '检查http请求', 100)
		assert self.ddos3_syn["curl"][2] in re
		print('正常http请求发送成功')

		# 检查抗攻击日志
		print("4.检查/var/log/jsac.agentjsac.info.log日志中ReportDdosEvent上报结果，检查到有Syn Flood字段说明日志上报正确")
		fun.wait_data('grep -n ReportDdosEvent /var/log/jsac.agentjsac.info.log |tail -1', 'gw',self.case3_step1['step1'][0], '检查Syn Flood', 300, flag='存在')
		for key in self.case3_step1:
			re = fun.cmd('grep -n ReportDdosEvent /var/log/jsac.agentjsac.info.log |tail -1', 'gw')
			print('re:', re)
			assert self.case3_step1[key][0] in re

		print("5.网关设备关闭ddos防御开关、fwlog抗攻击日志上报开关，使用defconf --show查看开关关闭")
		fun.cmd(self.ddos1_rst["fwlog"][1],'gw')
		fun.send(Exc_rmb,message.setddos_close['SetDdosEnable'], domain_rmb, base_path)
		for key in self.case_step1:
			re0 = fun.cmd(self.case_step1[key][0], 'gw')
			print(re0)
			assert self.case_step1[key][1] in re0
			assert self.case_step1[key][2] in re0
			assert self.case_step1[key][3] in re0
			assert self.case_step1[key][4] in re0

		# 删除/opt/ddos_*.txt文件
		fun.cmd("rm -f /opt/*txt*", 'c')
		re1 = fun.cmd("ls /opt/ |grep txt", 'c')
		print('客户端txt文件查询结果是:', re1)
		assert self.ddos3_syn["txt"][0] not in re1
		assert self.ddos3_syn["txt"][1] not in re1


	def teardown_class(self):
		#回收环境
		fun.rbm_close()
		fun.ssh_close('c')
		# fun.ssh_close('s')
		fun.ssh_close('gw')