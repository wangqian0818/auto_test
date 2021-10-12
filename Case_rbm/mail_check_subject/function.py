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
	from mail_check_subject import index
	from mail_check_subject import message
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

rbmDomain = baseinfo.rbmDomain
rbmExc = baseinfo.rbmExc
proxy_ip = baseinfo.gwInternetIp
smtp_ip = baseinfo.smtp_ip

class Test_mail_check_subject():

	def setup_method(self):
		clr_env.data_check_setup_met()

	def teardown_method(self):
		clr_env.data_check_teardown_met('mail', base_path)

	def setup_class(self):
		# 获取参数
		fun.ssh_gw.connect()
		self.clr_env = clr_env
		self.case1_step1 = index.case1_step1
		self.case1_step11 = index.case1_step11
		self.case1_step2 = index.case1_step2
		self.case2_step1 = index.case2_step1
		self.case2_step11 = index.case2_step11
		self.case2_step2 = index.case2_step2
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
		self.file = index.file
		self.attach_path = index.attach_path
		self.context = index.context
		self.case1_title1 = index.case1_title1
		self.case1_title2 = index.case1_title2
		self.case2_title1 = index.case2_title1
		self.case2_title2 = index.case2_title2
		self.case2_title3 = index.case2_title3

		clr_env.clear_env()

	# @pytest.mark.skip(reseason="skip")
	@allure.feature('验证基于主题关键字过滤的邮件策略')
	def test_mail_check_subject_a1(self):

		# 下发配置
		fun.send(rbmExc, message.addsmtp['AddAgent'], rbmDomain, base_path)
		fun.wait_data('ps -ef |grep nginx', 'gw', 'nginx: worker process')
		smtp_res1 = fun.nginx_worker('ps -ef |grep nginx', 'gw', 'nginx: worker process')
		assert smtp_res1 == 1
		fun.send(rbmExc, message.addpop3['AddAgent'], rbmDomain, base_path)
		fun.wait_data('ps -ef |grep nginx', 'gw', 'nginx: worker process')
		pop3_res1 = fun.nginx_worker('ps -ef |grep nginx', 'gw', 'nginx: worker process')
		assert pop3_res1 == 1
		# 检查配置下发是否成功
		for key in self.case1_step1:
			re = fun.wait_data(self.case1_step1[key][0], 'gw', self.case1_step1[key][1], '配置', 100)
			print(re)
			assert self.case1_step1[key][1] in re

		for key in self.case1_step11:
			re = fun.wait_data(self.case1_step11[key][0], 'gw', self.case1_step11[key][1], '配置', 100)
			print(re)
			assert self.case1_step11[key][1] in re

		fun.send(rbmExc, message.mailcheck1['SetMailCheck'], rbmDomain, base_path)
		fun.wait_data('ps -ef |grep nginx', 'gw', 'nginx: worker process')
		add_check = fun.nginx_worker('ps -ef |grep nginx', 'gw', 'nginx: worker process')
		assert add_check == 1
		for key in self.case1_step2:
			re = fun.wait_data(self.case1_step2[key][0], 'gw', self.case1_step2[key][1], '配置', 100)
			print(re)
			assert self.case1_step2[key][1] in re

		# 发送邮件,邮件地址为黑名单主题
		result1 = send_smtp.post_email(self.mail_sender, self.mail_receivers, self.mail_cc, self.mail_bcc,
									   self.mail_host, self.mail_port, self.mail_user, self.mail_pass,
									   self.attach_path, self.file, self.case1_title1, self.context, 0, 0)
		print('黑名单主题{}结果为:{}'.format(self.case1_title1,result1))
		assert result1 == 0

		# 发送邮件,邮件地址为非黑名单主题
		result2 = send_smtp.post_email(self.mail_sender, self.mail_receivers, self.mail_cc, self.mail_bcc,
									   self.mail_host, self.mail_port, self.mail_user, self.mail_pass,
									   self.attach_path, self.file, self.case1_title2, self.context, 0, 0)
		print('非黑名单主题{}结果为:{}'.format(self.case1_title2,result2))
		assert result2 == 1

		# 接收邮件
		msg = recv_pop3.get_email(self.pop3_email, self.pop3_pwd, self.pop3_server_host, self.pop3_server_port)
		mail_list = recv_pop3.print_info(msg)  # 解析
		assert self.case1_title2, self.context in mail_list

		# 移除策略，还原环境
		fun.send(rbmExc, message.delsmtp['DelAgent'], rbmDomain, base_path)
		fun.wait_data('ps -ef |grep nginx', 'gw', 'nginx: worker process')
		del_smtp = fun.nginx_worker('ps -ef |grep nginx', 'gw', 'nginx: worker process')
		assert del_smtp == 1
		fun.send(rbmExc, message.delpop3['DelAgent'], rbmDomain, base_path)
		fun.wait_data('ps -ef |grep nginx', 'gw', 'nginx: worker process')
		del_pop3 = fun.nginx_worker('ps -ef |grep nginx', 'gw', 'nginx: worker process')
		assert del_pop3 == 1
		# 检查代理是否成功移除
		for key in self.case1_step1:
			re = fun.wait_data(self.case1_step1[key][0], 'gw', self.case1_step1[key][1], '配置', 100, flag='不存在')
			assert self.case1_step1[key][1] not in re
		# 检查邮件策略是否清空
		fun.send(rbmExc, message.delmailcheck['DropMailCheck'], rbmDomain, base_path)
		fun.wait_data('ps -ef |grep nginx', 'gw', 'nginx: worker process')
		del_check = fun.nginx_worker('ps -ef |grep nginx', 'gw', 'nginx: worker process')
		assert del_check == 1
		for key in self.delcheck:
			re = fun.wait_data(self.delcheck[key][0], 'gw', self.delcheck[key][1], '配置', 100, flag='不存在')
			assert self.delcheck[key][1] not in re

	@allure.feature('验证基于多个主题关键字过滤的邮件策略')
	def test_mail_check_subject_a2(self):

		# 下发配置
		fun.send(rbmExc, message.addsmtp['AddAgent'], rbmDomain, base_path)
		fun.wait_data('ps -ef |grep nginx', 'gw', 'nginx: worker process')
		smtp_res1 = fun.nginx_worker('ps -ef |grep nginx', 'gw', 'nginx: worker process')
		assert smtp_res1 == 1
		fun.send(rbmExc, message.addpop3['AddAgent'], rbmDomain, base_path)
		fun.wait_data('ps -ef |grep nginx', 'gw', 'nginx: worker process')
		pop3_res1 = fun.nginx_worker('ps -ef |grep nginx', 'gw', 'nginx: worker process')
		assert pop3_res1 == 1
		# 检查配置下发是否成功
		for key in self.case2_step1:
			re = fun.wait_data(self.case2_step1[key][0], 'gw', self.case2_step1[key][1], '配置', 100)
			print(re)
			assert self.case2_step1[key][1] in re

		for key in self.case2_step11:
			re = fun.wait_data(self.case2_step11[key][0], 'gw', self.case2_step11[key][1], '配置', 100)
			print(re)
			assert self.case2_step11[key][1] in re

		fun.send(rbmExc, message.mailcheck2['SetMailCheck'], rbmDomain, base_path)
		fun.wait_data('ps -ef |grep nginx', 'gw', 'nginx: worker process')
		add_check = fun.nginx_worker('ps -ef |grep nginx', 'gw', 'nginx: worker process')
		assert add_check == 1
		for key in self.case2_step2:
			re = fun.wait_data(self.case2_step2[key][0], 'gw', self.case2_step2[key][1], '配置', 100)
			print(re)
			assert self.case2_step2[key][1] in re

		# 发送邮件,邮件地址为黑名单主题
		result1 = send_smtp.post_email(self.mail_sender, self.mail_receivers, self.mail_cc, self.mail_bcc,
									   self.mail_host, self.mail_port, self.mail_user, self.mail_pass,
									   self.attach_path, self.file, self.case2_title1, self.context, 0, 0)
		print('第一个黑名单主题{}结果为:{}'.format(self.case2_title1,result1))
		assert result1 == 0

		result2 = send_smtp.post_email(self.mail_sender, self.mail_receivers, self.mail_cc, self.mail_bcc,
									   self.mail_host, self.mail_port, self.mail_user, self.mail_pass,
									   self.attach_path, self.file, self.case2_title2, self.context, 0, 0)
		print('第二个黑名单主题{}结果为:{}'.format(self.case2_title2,result2))
		assert result2 == 0

		# 发送邮件,邮件地址为非黑名单主题
		result3 = send_smtp.post_email(self.mail_sender, self.mail_receivers, self.mail_cc, self.mail_bcc,
									   self.mail_host, self.mail_port, self.mail_user, self.mail_pass,
									   self.attach_path, self.file, self.case2_title3, self.context, 0, 0)
		print('非黑名单主题{}结果为:{}'.format(self.case2_title3,result3))
		assert result3 == 1

		# 接收邮件
		msg = recv_pop3.get_email(self.pop3_email, self.pop3_pwd, self.pop3_server_host, self.pop3_server_port)
		mail_list = recv_pop3.print_info(msg)  # 解析
		assert self.case2_title3, self.context in mail_list
		print('白名单接收者{}成功接收邮件'.format(self.pop3_email))

		# 移除策略，还原环境
		fun.send(rbmExc, message.delsmtp['DelAgent'], rbmDomain, base_path)
		fun.wait_data('ps -ef |grep nginx', 'gw', 'nginx: worker process')
		del_smtp = fun.nginx_worker('ps -ef |grep nginx', 'gw', 'nginx: worker process')
		assert del_smtp == 1
		fun.send(rbmExc, message.delpop3['DelAgent'], rbmDomain, base_path)
		fun.wait_data('ps -ef |grep nginx', 'gw', 'nginx: worker process')
		del_pop3 = fun.nginx_worker('ps -ef |grep nginx', 'gw', 'nginx: worker process')
		assert del_pop3 == 1
		# 检查代理是否成功移除
		for key in self.case2_step1:
			re = fun.wait_data(self.case2_step1[key][0], 'gw', self.case2_step1[key][1], '配置', 100, flag='不存在')
			assert self.case2_step1[key][1] not in re
		# 检查邮件策略是否清空
		fun.send(rbmExc, message.delmailcheck['DropMailCheck'], rbmDomain, base_path)
		fun.wait_data('ps -ef |grep nginx', 'gw', 'nginx: worker process')
		del_check = fun.nginx_worker('ps -ef |grep nginx', 'gw', 'nginx: worker process')
		assert del_check == 1
		for key in self.delcheck:
			re = fun.wait_data(self.delcheck[key][0], 'gw', self.delcheck[key][1], '配置', 100, flag='不存在')
			assert self.delcheck[key][1] not in re

	def teardown_class(self):
		# 回收环境
		clr_env.clear_env()

		fun.rbm_close()
		fun.ssh_close('gw')


