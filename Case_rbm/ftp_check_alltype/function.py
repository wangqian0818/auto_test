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
	from ftp_check_alltype import index
	from ftp_check_alltype import message
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

from common import baseinfo
from common import clr_env
from common.rabbitmq import *
from data_check import con_ftp

datatime = time.strftime('%Y-%m-%d %H:%M:%S',time.localtime(time.time()))

rbmDomain = baseinfo.rbmDomain
rbmExc = baseinfo.rbmExc
proxy_ip = baseinfo.gwInternetIp
smtp_ip = baseinfo.smtp_ip

class Test_ftp_check_alltype():

	def setup_method(self):
		clr_env.data_check_setup_met()

	def teardown_method(self):
		clr_env.data_check_teardown_met('ftp', base_path)


	def setup_class(self):
		# 获取参数
		fun.ssh_gw.connect()
		self.clr_env = clr_env
		self.case1_step1 = index.case1_step1
		self.case1_step11 = index.case1_step11
		self.case1_step2 = index.case1_step2
		self.delcheck = index.delcheck
		self.host = index.host
		self.port = index.port
		self.username = index.username
		self.password = index.password
		self.deny_user = index.deny_user
		self.case1_upremotePath = index.case1_upremotePath
		self.case1_uplocalPath = index.case1_uplocalPath
		self.case1_deny_upremotePath = index.case1_deny_upremotePath
		self.case1_deny_uplocalPath = index.case1_deny_uplocalPath
		self.case1_downremotePath = index.case1_downremotePath
		self.case1_downlocalPath = index.case1_downlocalPath
		self.case1_deny_downremotePath = index.case1_deny_downremotePath
		self.case1_deny_downlocalPath = index.case1_deny_downlocalPath

		clr_env.clear_env()


	@allure.feature('验证基于多种过滤方法过滤的FTP传输策略')
	def test_ftp_check_alltype_a1(self):

		# 下发配置
		fun.send(rbmExc, message.addftp['AddAgent'], rbmDomain, base_path)
		fun.wait_data('ps -ef |grep nginx', 'gw', 'nginx: worker process')
		add_res1 = fun.nginx_worker('ps -ef |grep nginx', 'gw', 'nginx: worker process')
		assert add_res1 == 1
		# 检查配置下发是否成功
		for key in self.case1_step1:
			re = fun.wait_data(self.case1_step1[key][0], 'gw', self.case1_step1[key][1], '配置', 100)
			print(re)
			assert self.case1_step1[key][1] in re

		for key in self.case1_step11:
			re = fun.wait_data(self.case1_step11[key][0], 'gw', self.case1_step11[key][1], '配置', 100)
			print(re)
			assert self.case1_step11[key][1] in re

		fun.send(rbmExc, message.ftpcheck1['SetFtpCheck'], rbmDomain, base_path)
		fun.wait_data('ps -ef |grep nginx', 'gw', 'nginx: worker process')
		add_res2 = fun.nginx_worker('ps -ef |grep nginx', 'gw', 'nginx: worker process')
		assert add_res2 == 1
		for key in self.case1_step2:
			re = fun.wait_data(self.case1_step2[key][0], 'gw', self.case1_step2[key][1], '配置', 100)
			print(re)
			assert self.case1_step2[key][1] in re

		# 1、登录ftp服务器，用户为白名单用户
		fp = con_ftp.connect_ftp(self.host, self.port, self.username, self.password)
		print('欢迎语是：{}'.format(fp.getwelcome()))
		assert '220' in fp.getwelcome()

		# 2、登录ftp服务器，用户为非白名单用户
		fp2 = con_ftp.connect_ftp(self.host, self.port, self.deny_user, self.password)
		print('ftp非白名单用户{}结果为:{}'.format(self.deny_user,fp2))
		assert fp2 == 0

		# 3、登录ftp服务器，上传文件扩展名为白名单
		fp = con_ftp.connect_ftp(self.host, self.port, self.username, self.password)
		print('欢迎语是：{}'.format(fp.getwelcome()))
		result1 = con_ftp.uploadFile(fp, self.case1_upremotePath, self.case1_uplocalPath)
		print('ftp上传文件扩展名{}为白名单结果为:{}'.format(self.case1_uplocalPath,result1))
		assert result1 == 1

		# 4、登录ftp服务器，上传文件扩展名为非白名单
		fp = con_ftp.connect_ftp(self.host, self.port, self.username, self.password)
		print('欢迎语是：{}'.format(fp.getwelcome()))
		result2 = con_ftp.uploadFile(fp, self.case1_deny_upremotePath, self.case1_deny_uplocalPath)
		print('ftp上传文件扩展名{}为非白名单结果为:{}'.format(self.case1_deny_uplocalPath,result2))
		assert result2 == 0

		# 5、登录ftp服务器，下载文件扩展名为白名单(下载命令被禁止)
		fp = con_ftp.connect_ftp(self.host, self.port, self.username, self.password)
		print('欢迎语是：{}'.format(fp.getwelcome()))
		result3 = con_ftp.downFile(fp, self.case1_downremotePath, self.case1_downlocalPath)
		print('ftp下载(下载命令被禁止)文件扩展名{}为白名单结果为:{}'.format(self.case1_downremotePath,result3))
		assert result3 == 0

		#6、 登录ftp服务器，下载文件扩展名为非白名单(下载命令被禁止)
		fp = con_ftp.connect_ftp(self.host, self.port, self.username, self.password)
		print('欢迎语是：{}'.format(fp.getwelcome()))
		result4 = con_ftp.downFile(fp, self.case1_deny_downremotePath, self.case1_deny_downlocalPath)
		print('ftp下载(下载命令被禁止)文件扩展名{}为非白名单结果为:{}'.format(self.case1_deny_downremotePath,result4))
		assert result4 == 0

		# 移除策略，还原环境
		fun.send(rbmExc, message.delftp['DelAgent'], rbmDomain, base_path)
		fun.wait_data('ps -ef |grep nginx', 'gw', 'nginx: worker process')
		del_res1 = fun.nginx_worker('ps -ef |grep nginx', 'gw', 'nginx: worker process')
		assert del_res1 == 1
		# 检查代理是否成功移除
		for key in self.case1_step1:
			re = fun.wait_data(self.case1_step1[key][0], 'gw', self.case1_step1[key][1], '配置', 100, flag='不存在')
			assert self.case1_step1[key][1] not in re
		# 检查ftp传输策略是否清空
		fun.send(rbmExc, message.delftpcheck['DropFtpCheck'], rbmDomain, base_path)
		fun.wait_data('ps -ef |grep nginx', 'gw', 'nginx: worker process')
		del_res2 = fun.nginx_worker('ps -ef |grep nginx', 'gw', 'nginx: worker process')
		assert del_res2 == 1
		for key in self.delcheck:
			re = fun.wait_data(self.delcheck[key][0], 'gw', self.delcheck[key][1], '配置', 100, flag='不存在')
			assert self.delcheck[key][1] not in re

	def teardown_class(self):
		# 回收环境
		clr_env.clear_env()

		fun.rbm_close()
		fun.ssh_close('gw')


