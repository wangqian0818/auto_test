'''
脚本一：
用例名称：验证隔离下基于多种过滤方法过滤的邮件策略
编写人员：李皖秋
编写日期：2021.7.14
测试目的：验证隔离下基于多种过滤方法过滤的邮件策略
测试步骤：
1、下发邮件的隔离代理：代理ip为前置机安全卡的ip，port为8885（smtp）和8886（pop3），等待nginx的24个进程起来
2、下发地址白名单：liwanqiu66@163.com、m53667987@163.com；黑名单主题：test；黑名单文件名：test；附件扩展名黑名单：txt，等待nginx的24个进程起来
3、控制台发送邮件，邮件地址为非白名单地址：jusontest@163.com，查看发送结果
4、控制台发送邮件，邮件主题为黑名单主题：test，查看发送结果
5、控制台发送邮件，邮件附件文件名为黑名单文件名：test，查看发送结果
6、控制台发送邮件，邮件附件扩展名为黑名单扩展名：txt，查看发送结果
7、控制台发送邮件，邮件地址为白名单地址：liwanqiu66@163.com；非黑名单主题：我不是黑名单主题，测试多种类型（隔离的数据结构检查）；附件文件名为非黑名单：1；附件扩展名为非黑名单：xls，查看发送结果
8、接收邮件，接收邮件地址为白名单地址：m53667987@163.com，查看pop3协议收到的邮件内容是否为刚刚发送的
9、移除邮件的隔离策略，清空环境，等待nginx的24个进程起来
10、移除邮件策略，等待nginx的24个进程起来
预期结果：
1、cat /etc/jsac/customapp.stream应该包含代理ip和port，netstat -anp |grep tcp应该可以查看到监听ip和端口
2、cat /etc/jsac/filter.json文件应该包含：allow-from、deny-topic、deny-basename、deny-suffix和地址白名单：liwanqiu66@163.com、m53667987@163.com；黑名单主题：test；黑名单文件名：test；附件扩展名黑名单：txt
3、发送失败
4、发送失败
5、发送失败
6、发送失败
7、发送成功
8、接收邮件内容为非黑名单扩展名发送的
9、cat /etc/jsac/customapp.stream应该不包含代理ip和port
10、cat /etc/jsac/filter.json文件应该不包含：mail协议
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
	from iso_mail_check_alltype import index
	from iso_mail_check_alltype import message
	from common import fun
	import common.ssh as c_ssh
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
from data_check import send_smtp
from data_check import recv_pop3

datatime = time.strftime('%Y-%m-%d %H:%M:%S',time.localtime(time.time()))
FrontDomain = baseinfo.BG8010FrontDomain
BackDomain = baseinfo.BG8010BackDomain
proxy_ip = baseinfo.BG8010FrontOpeIp
rbmExc = baseinfo.rbmExc

class Test_iso_mail_check_alltype():

	def setup_method(self):
		clr_env.data_check_setup_met(dut='FrontDut')
		clr_env.data_check_setup_met(dut='BackDut')

	def teardown_method(self):
		clr_env.iso_teardown_met('mail', base_path)
		clr_env.clear_datacheck('mail', base_path)

		clr_env.iso_setup_class(dut='FrontDut')
		clr_env.iso_setup_class(dut='BackDut')

	def setup_class(self):
		# 获取参数
		fun.ssh_FrontDut.connect()
		fun.ssh_BackDut.connect()
		clr_env.iso_setup_class(dut='FrontDut')
		clr_env.iso_setup_class(dut='BackDut')
		self.case1_step1 = index.case1_step1
		self.case1_step11 = index.case1_step11
		self.case1_step2 = index.case1_step2
		self.delcheck = index.delcheck
		self.mail_sender = index.mail_sender
		self.mail_receivers = index.mail_receivers
		self.mail_cc = index.mail_cc
		self.mail_bcc = index.mail_bcc
		self.mail_host = index.mail_host
		self.mail_port = index.mail_port
		self.mail_user = index.mail_user
		self.mail_pass = index.mail_pass
		self.pop3_email = index.pop3_email
		self.pop3_pwd = index.pop3_pwd
		self.pop3_server_host = index.pop3_server_host
		self.pop3_server_port = index.pop3_server_port
		self.deny_mail = index.deny_mail
		self.deny_pwd = index.deny_pwd
		self.context = index.context
		self.deny_title = index.deny_title
		self.title = index.title
		self.deny_name_file = index.deny_name_file
		self.deny_extend_file = index.deny_extend_file
		self.file = index.file
		self.attach_file = index.attach_file
		self.attach_extend = index.attach_extend
		self.attach_path = index.attach_path


	@allure.feature('验证隔离下基于多种过滤方法过滤的邮件策略')
	def test_iso_mail_check_alltype_a1(self):

		# 下发配置
		print('1、下发邮件的隔离代理：代理ip为前置机安全卡的ip，port为8885（smtp）和8886（pop3），等待nginx的24个进程起来；cat /etc/jsac/customapp.stream应该包含代理ip和port，netstat -anp |grep tcp应该可以查看到监听ip和端口')
		fun.send(rbmExc, message.addsmtp_front['AddCustomAppPolicy'], FrontDomain, base_path)
		fun.send(rbmExc, message.addsmtp_back['AddCustomAppPolicy'], BackDomain, base_path)
		fun.wait_data('ps -ef |grep nginx', 'FrontDut', 'nginx: worker process')
		front_res1 = fun.nginx_worker('ps -ef |grep nginx', 'FrontDut', 'nginx: worker process', name='前置机nginx进程')
		assert front_res1 == 1
		fun.wait_data('ps -ef |grep nginx', 'BackDut', 'nginx: worker process')
		back_res1 = fun.nginx_worker('ps -ef |grep nginx', 'BackDut', 'nginx: worker process', name='后置机nginx进程')
		assert back_res1 == 1
		fun.send(rbmExc, message.addpop3_front['AddCustomAppPolicy'], FrontDomain, base_path)
		fun.send(rbmExc, message.addpop3_back['AddCustomAppPolicy'], BackDomain, base_path)
		fun.wait_data('ps -ef |grep nginx', 'FrontDut', 'nginx: worker process')
		front_res2 = fun.nginx_worker('ps -ef |grep nginx', 'FrontDut', 'nginx: worker process', name='前置机nginx进程')
		assert front_res2 == 1
		fun.wait_data('ps -ef |grep nginx', 'BackDut', 'nginx: worker process')
		back_res2 = fun.nginx_worker('ps -ef |grep nginx', 'BackDut', 'nginx: worker process', name='后置机nginx进程')
		assert back_res2 == 1
		# 检查配置下发是否成功
		for key in self.case1_step1:
			re = fun.wait_data(self.case1_step1[key][0], 'FrontDut', self.case1_step1[key][1], '配置', 100)
			print(re)
			assert self.case1_step1[key][1] in re

		for key in self.case1_step11:
			re = fun.wait_data(self.case1_step11[key][0], 'FrontDut', self.case1_step11[key][1], '配置', 100)
			print(re)
			assert self.case1_step11[key][1] in re

		print('2、下发地址白名单：liwanqiu66@163.com、m53667987@163.com；黑名单主题：test；黑名单文件名：test；附件扩展名黑名单：txt，等待nginx的24个进程起来；cat /etc/jsac/filter.json文件应该包含：allow-from、deny-topic、deny-basename、deny-suffix和地址白名单：liwanqiu66@163.com、m53667987@163.com；黑名单主题：test；黑名单文件名：test；附件扩展名黑名单：txt')
		fun.send(rbmExc, message.mailcheck1['SetMailCheck'], FrontDomain, base_path)
		fun.wait_data('ps -ef |grep nginx', 'FrontDut', 'nginx: worker process')
		add_check = fun.nginx_worker('ps -ef |grep nginx', 'FrontDut', 'nginx: worker process')
		assert add_check == 1
		for key in self.case1_step2:
			re = fun.wait_data(self.case1_step2[key][0], 'FrontDut', self.case1_step2[key][1], '配置', 100)
			print(re)
			assert self.case1_step2[key][1] in re

		# 1、发送邮件,邮件地址为非白名单地址
		print('3、控制台发送邮件，邮件地址为非白名单地址：jusontest@163.com，查看发送结果；发送失败')
		result1 = send_smtp.post_email(self.deny_mail, self.mail_receivers, self.mail_cc, self.mail_bcc, self.mail_host,
									   self.mail_port, self.deny_mail, self.deny_pwd, self.attach_path, self.deny_name_file, self.title, self.context, 0, 1)
		print('非白名单地址{}结果为:{}'.format(self.deny_mail,result1))
		assert result1 == 0

		# 2、发送邮件,邮件地址为黑名单主题
		print('4、控制台发送邮件，邮件主题为黑名单主题：test，查看发送结果；发送失败')
		result2 = send_smtp.post_email(self.mail_sender, self.mail_receivers, self.mail_cc, self.mail_bcc,
									   self.mail_host, self.mail_port, self.mail_user, self.mail_pass,
									   self.attach_path, self.deny_name_file, self.deny_title, self.context, 0, 1)
		print('黑名单主题{}结果为:{}'.format(self.deny_title,result2))
		assert result2 == 0

		# 3、发送邮件,邮件地址为黑名单文件名
		print('5、控制台发送邮件，邮件附件文件名为黑名单文件名：test，查看发送结果；发送失败')
		result3 = send_smtp.post_email(self.mail_sender, self.mail_receivers, self.mail_cc, self.mail_bcc,
									   self.mail_host, self.mail_port, self.mail_user, self.mail_pass,
									   self.attach_file, self.deny_name_file, self.title, self.context, 0, 1)
		print('黑名单文件名{}结果为:{}'.format(self.deny_name_file,result3))
		assert result3 == 0


		# 4、发送邮件,邮件地址为黑名单文件扩展名
		print('6、控制台发送邮件，邮件附件扩展名为黑名单扩展名：txt，查看发送结果；发送失败')
		result4 = send_smtp.post_email(self.mail_sender, self.mail_receivers, self.mail_cc, self.mail_bcc,
									   self.mail_host, self.mail_port, self.mail_user, self.mail_pass,
									   self.attach_extend, self.deny_extend_file, self.title, self.context, 0, 1)
		print('黑名单文件扩展名{}结果为:{}'.format(self.deny_extend_file,result4))
		assert result4 == 0

		# 5、发送邮件,邮件地址为白名单地址、非黑名单主题、非黑名单文件名、非黑名单文件扩展名
		print('7、控制台发送邮件，邮件地址为白名单地址：liwanqiu66@163.com；非黑名单主题：我不是黑名单主题，测试多种类型（隔离的数据结构检查）；附件文件名为非黑名单：1；附件扩展名为非黑名单：xls，查看发送结果；发送成功')
		result5 = send_smtp.post_email(self.mail_sender, self.mail_receivers, self.mail_cc, self.mail_bcc,
									   self.mail_host, self.mail_port, self.mail_user, self.mail_pass,
									   self.attach_path, self.file, self.title, self.context, 0, 1)
		print('各种参数均为白名单结果为:{}'.format(result5))
		assert result5 == 1

		# 接收邮件
		print('8、接收邮件，接收邮件地址为白名单地址：m53667987@163.com，查看pop3协议收到的邮件内容是否为刚刚发送的；接收邮件内容为非黑名单扩展名发送的')
		msg = recv_pop3.get_email(self.pop3_email, self.pop3_pwd, self.pop3_server_host, self.pop3_server_port)
		mail_list = recv_pop3.print_info(msg)  # 解析
		assert self.title, self.context in mail_list

		# 移除策略，还原环境
		print('9、移除邮件的隔离策略，清空环境，等待nginx的24个进程起来；cat /etc/jsac/customapp.stream应该不包含代理ip和port')
		fun.send(rbmExc, message.delsmtp_front['DelCustomAppPolicy'], FrontDomain, base_path)
		fun.send(rbmExc, message.delsmtp_back['DelCustomAppPolicy'], BackDomain, base_path)
		fun.wait_data('ps -ef |grep nginx', 'FrontDut', 'nginx: worker process')
		fdel_res1 = fun.nginx_worker('ps -ef |grep nginx', 'FrontDut', 'nginx: worker process', name='前置机nginx进程')
		assert fdel_res1 == 1
		fun.wait_data('ps -ef |grep nginx', 'BackDut', 'nginx: worker process')
		bdel_res1 = fun.nginx_worker('ps -ef |grep nginx', 'BackDut', 'nginx: worker process', name='后置机nginx进程')
		assert bdel_res1 == 1
		fun.send(rbmExc, message.delpop3_front['DelCustomAppPolicy'], FrontDomain, base_path)
		fun.send(rbmExc, message.delpop3_back['DelCustomAppPolicy'], BackDomain, base_path)
		fun.wait_data('ps -ef |grep nginx', 'FrontDut', 'nginx: worker process')
		fdel_res2 = fun.nginx_worker('ps -ef |grep nginx', 'FrontDut', 'nginx: worker process', name='前置机nginx进程')
		assert fdel_res2 == 1
		fun.wait_data('ps -ef |grep nginx', 'BackDut', 'nginx: worker process')
		bdel_res2 = fun.nginx_worker('ps -ef |grep nginx', 'BackDut', 'nginx: worker process', name='后置机nginx进程')
		assert bdel_res2 == 1
		# 检查策略移除是否成功
		for key in self.case1_step1:
			re = fun.wait_data(self.case1_step1[key][0], 'FrontDut', self.case1_step1[key][1], '配置', 100, flag='不存在')
			print(re)
			assert self.case1_step1[key][1] not in re

		# 检查邮件策略是否清空
		print('10、移除邮件策略，等待nginx的24个进程起来；cat /etc/jsac/filter.json文件应该不包含：mail协议')
		fun.send(rbmExc, message.delmailcheck['DropMailCheck'], FrontDomain, base_path)
		fun.wait_data('ps -ef |grep nginx', 'FrontDut', 'nginx: worker process')
		del_check = fun.nginx_worker('ps -ef |grep nginx', 'FrontDut', 'nginx: worker process')
		assert del_check == 1
		for key in self.delcheck:
			re = fun.wait_data(self.delcheck[key][0], 'FrontDut', self.delcheck[key][1], '配置', 100, flag='不存在')
			assert self.delcheck[key][1] not in re


	def teardown_class(self):
		# 回收环境
		clr_env.iso_setup_class(dut='FrontDut')
		clr_env.iso_setup_class(dut='BackDut')

		fun.rbm_close()
		fun.ssh_close('FrontDut')
		fun.ssh_close('BackDut')

