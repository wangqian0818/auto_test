'''
脚本一
用例名称：验证边界保护系统对ICMP FLOOD攻击测试的防御
编写人员：马丹丹
编写日期：2021/7/9
测试目的：验证边界保护系统对ICMP FLOOD攻击测试的防御
测试步骤：
1.网关设备开启netflow流量上报开关、fwlog抗攻击日志上报开关,下发icmp协议的acl qos多桶限速策略，使用defconf --show、tupleacl --get查看结果
2.使用hping3工具发送ICMP Flood攻击命令hping3 -1 服务端ip -c 10000 --faster
3.检查/var/log/jsac.agentjsac.info.log日志中ReportDdosEvent上报结果
4.移除acl策略，使用tupleacl --get查看结果
5.网关设备关闭netflow流量上报开关、fwlog抗攻击日志上报开关，使用defconf --show查看结果
预期结果：
1.检查到以下开关为开启状态说明开关开启成功：firewall-log: on、flow report: on
2.hping3命令发送成功返回结果icmp mode set
3.检查到有ICMP Flood字段说明日志上报正确
4.使用tupleacl --get查看无策略
5.检查到以下开关为关闭状态说明开关关闭成功：flow report: off、firewall-log: off
脚本二
用例名称：验证边界保护系统对UDP FLOOD攻击测试的防御
编写人员：马丹丹
编写日期：2021/7/9
测试目的：验证边界保护系统对UDP FLOOD攻击测试的防御
测试步骤：
1.网关设备开启netflow流量上报开关、fwlog抗攻击日志上报开关,下发udp协议的acl qos多桶限速策略，使用defconf --show、tupleacl --get查看结果
2.使用hping3工具发送UDP Flood攻击命令hping3 -q -n --udp --keep -p 攻击端口 --flood 服务端ip -c 10000 --faster
3.检查/var/log/jsac.agentjsac.info.log日志中ReportDdosEvent上报结果
4.移除acl策略，使用tupleacl --get查看结果
5.网关设备关闭netflow流量上报开关、fwlog抗攻击日志上报开关，使用defconf --show查看结果
预期结果：
1.检查到以下开关为开启状态说明开关开启成功：firewall-log: on、flow report: on
2.hping3命令发送成功返回结果udp mode set
3.检查到有UDP Flood字段说明日志上报正确
4.使用tupleacl --get查看无策略
5.检查到以下开关为关闭状态说明开关关闭成功：flow report: off、firewall-log: off
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
	from firewall_flood_attack import index
	from firewall_flood_attack import message
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


class Test_flood_attack():

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
		self.case1_step2 = index.case1_step2
		self.case2_step1 = index.case2_step1
		self.case2_step2 = index.case2_step2
		self.flood1_icmp = index.flood1_icmp
		self.flood2_udp = index.flood2_udp



	# @pytest.mark.skip(reseason="skip")
	@allure.feature('验证边界保护系统对ICMP FLOOD攻击测试的防御')
	def test_imcp_flood(self):

		# 下发配置并检查结果
		print("1.网关设备开启netflow流量上报开关、fwlog抗攻击日志上报开关,下发icmp协议的acl qos多桶限速策略，使用defconf --show、tupleacl --get查看开关开启，acl策略存在")
		fun.cmd(self.flood1_icmp["fwlog"][0],'gw')
		fun.cmd(self.flood1_icmp["netflow"][0],'gw')
		for key in self.case_step:
			re0 = fun.cmd(self.case_step[key][0], 'gw')
			print(re0)
			assert self.case_step[key][1] in re0
			assert self.case_step[key][2] in re0

		fun.send(Exc_rmb,message.AddAclPolicy_ICMP['AddAclPolicy'], domain_rmb, base_path)
		for key in self.case1_step1:
			re0 = fun.cmd(self.case1_step1[key][0], 'gw')
			print(re0)
			assert self.case1_step1[key][1] in re0

		# 客户端发送攻击命令
		print("2.使用hping3工具发送ICMP Flood攻击命令hping3 -1 服务端ip -c 10000 --faster，返回结果icmp mode set")
		print('icmp flood命令为：', self.flood1_icmp["hping3"][0])
		fun.cmd(f"hping3 -1 {pcap_dip} -c 10000 --faster > /opt/icmp_flood.txt", 'c')
		re = fun.wait_data('cat /opt/icmp_flood.txt', 'c', self.flood1_icmp["txt"][0], '检查ICMP FLOOD攻击发送', 100)
		assert self.flood1_icmp["txt"][0] in re
		print('hping3 ICMP Flood攻击命令下发成功')

		# 检查抗攻击日志
		print("3.检查/var/log/jsac.agentjsac.info.log日志中ReportDdosEvent上报结果，检查到有ICMP Flood字段说明日志上报正确")
		fun.wait_data('grep -n ReportDdosEvent /var/log/jsac.agentjsac.info.log |tail -1', 'gw',self.case1_step2['step1'][0], '检查ICMP Flood', 300, flag='存在')
		for key in self.case1_step2:
			re = fun.cmd('grep -n ReportDdosEvent /var/log/jsac.agentjsac.info.log |tail -1', 'gw')
			print('re:', re)
			assert self.case1_step2[key][0] in re

		# 移除icmp策略
		print("4.移除acl策略，使用tupleacl --get查看结果,使用tupleacl --get查看无策略")
		fun.send(Exc_rmb, message.DelAclPolicy['DelAclPolicy'], domain_rmb, base_path)
		for key in self.case1_step1:
			re0 = fun.cmd(self.case1_step1[key][0], 'gw')
			print(re0)
			assert self.case1_step1[key][1] not in re0

		print("5.网关设备关闭netflow流量上报开关、fwlog抗攻击日志上报开关，使用defconf --show查看开关关闭")
		fun.cmd(self.flood1_icmp["fwlog"][1], 'gw')
		fun.cmd(self.flood1_icmp["netflow"][1], 'gw')
		for key in self.case_step1:
			re0 = fun.cmd(self.case_step1[key][0], 'gw')
			print(re0)
			assert self.case_step1[key][1] in re0
			assert self.case_step1[key][2] in re0

		#删除/opt/*flood.txt文件
		fun.cmd("rm -f /opt/*txt*", 'c')
		re1 = fun.cmd("ls /opt/ |grep txt", 'c')
		print('客户端txt文件查询结果是:', re1)
		assert self.flood1_icmp["txt"][1] not in re1



	# @pytest.mark.skip(reseason="skip")
	@allure.feature('验证边界保护系统对UDP FLOOD攻击测试的防御')
	def test_udp_flood(self):

		# 下发配置并检查结果
		print("1.网关设备开启netflow流量上报开关、fwlog抗攻击日志上报开关,下发udp协议的acl qos多桶限速策略，使用defconf --show、tupleacl --get查看开关开启，acl策略存在")
		fun.cmd(self.flood2_udp["fwlog"][0],'gw')
		fun.cmd(self.flood2_udp["netflow"][0],'gw')
		for key in self.case_step:
			re0 = fun.cmd(self.case_step[key][0], 'gw')
			print(re0)
			assert self.case_step[key][1] in re0
			assert self.case_step[key][2] in re0

		fun.send(Exc_rmb,message.AddAclPolicy_UDP['AddAclPolicy'], domain_rmb, base_path)
		for key in self.case2_step1:
			re0 = fun.cmd(self.case2_step1[key][0], 'gw')
			print(re0)
			assert self.case2_step1[key][1] in re0

		# 客户端发送攻击命令
		print("2.使用hping3工具发送UDP Flood攻击命令hping3 -q -n --udp --keep -p 攻击端口 --flood 服务端ip -c 10000 --faster，返回结果icmp mode set")
		print('udp flood命令为：',self.flood2_udp["hping3"][0])
		fun.cmd(f"hping3 -q -n --udp --keep -p {port_attack} --flood {pcap_dip} -c 10000 --faster > /opt/udp_flood.txt", 'c')
		re = fun.wait_data('cat /opt/udp_flood.txt', 'c', self.flood2_udp["txt"][0], '检查UDP FLOOD攻击发送', 100)
		assert self.flood2_udp["txt"][0] in re
		print('hping3 UDP Flood攻击命令下发成功')

		# 检查抗攻击日志
		print("3.检查/var/log/jsac.agentjsac.info.log日志中ReportDdosEvent上报结果，检查到有UDP Flood字段说明日志上报正确")
		fun.wait_data('grep -n ReportDdosEvent /var/log/jsac.agentjsac.info.log |tail -1', 'gw',self.case2_step2['step1'][0], '检查UDP Flood', 300, flag='存在')
		for key in self.case2_step2:
			re = fun.cmd('grep -n ReportDdosEvent /var/log/jsac.agentjsac.info.log |tail -1', 'gw')
			print('re:', re)
			assert self.case2_step2[key][0] in re

		# 移除udp策略
		print("4.移除acl策略，使用tupleacl --get查看结果,使用tupleacl --get查看无策略")
		fun.send(Exc_rmb, message.DelAclPolicy['DelAclPolicy'], domain_rmb, base_path)
		for key in self.case2_step1:
			re0 = fun.cmd(self.case2_step1[key][0], 'gw')
			print(re0)
			assert self.case2_step1[key][1] not in re0

		print("5.网关设备关闭netflow流量上报开关、fwlog抗攻击日志上报开关，使用defconf --show查看开关关闭")
		fun.cmd(self.flood2_udp["fwlog"][1],'gw')
		fun.cmd(self.flood2_udp["netflow"][1],'gw')
		for key in self.case_step1:
			re0 = fun.cmd(self.case_step1[key][0], 'gw')
			print(re0)
			assert self.case_step1[key][1] in re0
			assert self.case_step1[key][2] in re0

		#删除/opt/*flood.txt文件
		fun.cmd("rm -f /opt/*txt*", 'c')
		re1 = fun.cmd("ls /opt/ |grep txt", 'c')
		print('客户端txt文件查询结果是:', re1)
		assert self.flood2_udp["txt"][1] not in re1

	def teardown_class(self):
		#回收环境
		fun.rbm_close()
		fun.ssh_close('c')
		# fun.ssh_close('s')
		fun.ssh_close('gw')