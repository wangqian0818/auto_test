'''
脚本一：
用例名称：验证隔离下基于多种过滤方法过滤的FTP传输策略
编写人员：李皖秋
编写日期：2021.7.15
测试目的：验证隔离下基于多种过滤方法过滤的FTP传输策略
测试步骤：
1、下发ftp的隔离代理：代理ip为前置机安全卡的ip，port为8887，等待nginx的24个进程起来
2、下发ftp的用户白名单：test；上传文件扩展名白名单：txt；下载文件扩展名白名单：txt；命令控制白名单：不包含RETR，等待nginx的24个进程起来
3、控制台走ftp隔离登录ftp服务器，登录用户为白名单test，查看登录是否成功
4、控制台走ftp隔离登录ftp服务器，登录用户为非白名单lwq，查看登录是否成功
5、控制台走ftp隔离登录ftp服务器，上传文件扩展名为白名单txt，查看文件是否上传成功
6、控制台走ftp隔离登录ftp服务器，上传文件扩展名为非白名单pdf，查看文件是否上传成功
7、控制台走ftp隔离登录ftp服务器，下载文件扩展名为白名单txt（下载命令被禁止），查看文件是否下载成功
8、控制台走ftp隔离登录ftp服务器，下载文件扩展名为非白名单pdf（下载命令被禁止），查看文件是否下载成功
9、移除ftp的隔离策略，清空环境，等待nginx的24个进程起来
10、移除ftp传输策略，等待nginx的24个进程起来
预期结果：
1、cat /etc/jsac/customapp.stream应该包含代理ip和port，netstat -anp |grep tcp应该可以查看到监听ip和端口
2、cat /etc/jsac/filter.json文件应该包含：allow-user、allow-upload、allow-download、allow-cmd，用户白名单test、下载扩展名白名单txt，上传扩展名白名单txt，以及不包含命令RETR
3、登录成功
4、登录失败
5、上传成功
6、上传失败
7、下载失败
8、下载失败
9、cat /etc/jsac/customapp.stream应该不包含代理ip和port
10、cat /etc/jsac/filter.json文件应该不包含：ftp协议
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
	from iso_ftp_check_alltype import index
	from iso_ftp_check_alltype import message
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

FrontDomain = baseinfo.BG8010FrontDomain
BackDomain = baseinfo.BG8010BackDomain
proxy_ip = baseinfo.BG8010FrontOpeIp
rbmExc = baseinfo.rbmExc

class Test_iso_ftp_check_alltype():

	def setup_method(self):
		clr_env.data_check_setup_met(dut='FrontDut')
		clr_env.data_check_setup_met(dut='BackDut')

	def teardown_method(self):
		clr_env.iso_teardown_met('ftp', base_path)
		clr_env.clear_datacheck('ftp', base_path)

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
		self.case1_step22 = index.case1_step22
		self.delcheck = index.delcheck
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


	@allure.feature('验证隔离下基于多种过滤方法过滤的FTP传输策略')
	def test_iso_ftp_check_alltype_a1(self):

		# 下发配置
		print('1、下发ftp的隔离代理：代理ip为前置机安全卡的ip，port为8887，等待nginx的24个进程起来；cat /etc/jsac/customapp.stream应该包含代理ip和port，netstat -anp |grep tcp应该可以查看到监听ip和端口')
		fun.send(rbmExc, message.addftp_front['AddCustomAppPolicy'], FrontDomain, base_path)
		fun.send(rbmExc, message.addftp_back['AddCustomAppPolicy'], BackDomain, base_path)
		fun.wait_data('ps -ef |grep nginx', 'FrontDut', 'nginx: worker process')
		front_res = fun.nginx_worker('ps -ef |grep nginx', 'FrontDut', 'nginx: worker process', name='前置机nginx进程')
		assert front_res == 1
		fun.wait_data('ps -ef |grep nginx', 'BackDut', 'nginx: worker process')
		back_res = fun.nginx_worker('ps -ef |grep nginx', 'BackDut', 'nginx: worker process', name='后置机nginx进程')
		assert back_res == 1
		# 检查配置下发是否成功
		for key in self.case1_step1:
			re = fun.wait_data(self.case1_step1[key][0], 'FrontDut', self.case1_step1[key][1], '配置', 100)
			print(re)
			assert self.case1_step1[key][1] in re
		# 检查配置下发是否成功
		for key in self.case1_step11:
			re = fun.wait_data(self.case1_step11[key][0], 'FrontDut', self.case1_step11[key][1], '配置', 100)
			print(re)
			assert self.case1_step11[key][1] in re

		print('2、下发ftp的用户白名单：test；上传文件扩展名白名单：txt；下载文件扩展名白名单：txt；命令控制白名单：不包含RETR，等待nginx的24个进程起来；cat /etc/jsac/filter.json文件应该包含：allow-user、allow-upload、allow-download、allow-cmd，用户白名单test、下载扩展名白名单txt，上传扩展名白名单txt，以及不包含命令RETR')
		fun.send(rbmExc, message.ftpcheck1['SetFtpCheck'], FrontDomain, base_path)
		fun.wait_data('ps -ef |grep nginx', 'FrontDut', 'nginx: worker process')
		add_res2 = fun.nginx_worker('ps -ef |grep nginx', 'FrontDut', 'nginx: worker process')
		assert add_res2 == 1
		for key in self.case1_step2:
			re = fun.wait_data(self.case1_step2[key][0], 'FrontDut', self.case1_step2[key][1], '配置', 100)
			print(re)
			assert self.case1_step2[key][1] in re
		for key in self.case1_step22:
			re = fun.wait_data(self.case1_step22[key][0], 'FrontDut', self.case1_step22[key][1], '配置', 100, flag='不存在')
			print(re)
			assert self.case1_step22[key][1] not in re

		# 1、登录ftp服务器，用户为白名单用户
		print('3、控制台走ftp隔离登录ftp服务器，登录用户为白名单test，查看登录是否成功；登录成功')
		fp = con_ftp.connect_ftp(proxy_ip, self.port, self.username, self.password)
		print('欢迎语是：{}'.format(fp.getwelcome()))
		assert '220' in fp.getwelcome()

		# 2、登录ftp服务器，用户为非白名单用户
		print('4、控制台走ftp隔离登录ftp服务器，登录用户为非白名单lwq，查看登录是否成功；登录失败')
		fp2 = con_ftp.connect_ftp(proxy_ip, self.port, self.deny_user, self.password)
		print('ftp非白名单用户{}结果为:{}'.format(self.deny_user,fp2))
		assert fp2 == 0

		# 3、登录ftp服务器，上传文件扩展名为白名单
		print('5、控制台走ftp隔离登录ftp服务器，上传文件扩展名为白名单txt，查看文件是否上传成功；上传成功')
		fp = con_ftp.connect_ftp(proxy_ip, self.port, self.username, self.password)
		print('欢迎语是：{}'.format(fp.getwelcome()))
		result1 = con_ftp.uploadFile(fp, self.case1_upremotePath, self.case1_uplocalPath)
		print('ftp上传文件扩展名{}为白名单结果为:{}'.format(self.case1_uplocalPath,result1))
		assert result1 == 1

		# 4、登录ftp服务器，上传文件扩展名为非白名单
		print('6、控制台走ftp隔离登录ftp服务器，上传文件扩展名为非白名单pdf，查看文件是否上传成功；上传失败')
		fp = con_ftp.connect_ftp(proxy_ip, self.port, self.username, self.password)
		print('欢迎语是：{}'.format(fp.getwelcome()))
		result2 = con_ftp.uploadFile(fp, self.case1_deny_upremotePath, self.case1_deny_uplocalPath)
		print('ftp上传文件扩展名{}为非白名单结果为:{}'.format(self.case1_deny_uplocalPath,result2))
		assert result2 == 0

		# 5、登录ftp服务器，下载文件扩展名为白名单(下载命令被禁止)
		print('7、控制台走ftp隔离登录ftp服务器，下载文件扩展名为白名单txt（下载命令被禁止），查看文件是否下载成功；下载失败')
		fp = con_ftp.connect_ftp(proxy_ip, self.port, self.username, self.password)
		print('欢迎语是：{}'.format(fp.getwelcome()))
		result3 = con_ftp.downFile(fp, self.case1_downremotePath, self.case1_downlocalPath)
		print('ftp下载(下载命令被禁止)文件扩展名{}为白名单结果为:{}'.format(self.case1_downremotePath,result3))
		assert result3 == 0

		#6、 登录ftp服务器，下载文件扩展名为非白名单(下载命令被禁止)
		print('8、控制台走ftp隔离登录ftp服务器，下载文件扩展名为非白名单pdf（下载命令被禁止），查看文件是否下载成功；下载失败')
		fp = con_ftp.connect_ftp(proxy_ip, self.port, self.username, self.password)
		print('欢迎语是：{}'.format(fp.getwelcome()))
		result4 = con_ftp.downFile(fp, self.case1_deny_downremotePath, self.case1_deny_downlocalPath)
		print('ftp下载(下载命令被禁止)文件扩展名{}为非白名单结果为:{}'.format(self.case1_deny_downremotePath,result4))
		assert result4 == 0

		# 移除策略，还原环境
		print('9、移除ftp的隔离策略，清空环境，等待nginx的24个进程起来；cat /etc/jsac/customapp.stream应该不包含代理ip和port')
		fun.send(rbmExc, message.delftp_front['DelCustomAppPolicy'], FrontDomain, base_path)
		fun.send(rbmExc, message.delftp_back['DelCustomAppPolicy'], BackDomain, base_path)
		fun.wait_data('ps -ef |grep nginx', 'FrontDut', 'nginx: worker process')
		fdel_res = fun.nginx_worker('ps -ef |grep nginx', 'FrontDut', 'nginx: worker process', name='前置机nginx进程')
		assert fdel_res == 1
		fun.wait_data('ps -ef |grep nginx', 'BackDut', 'nginx: worker process')
		bdel_res = fun.nginx_worker('ps -ef |grep nginx', 'BackDut', 'nginx: worker process', name='后置机nginx进程')
		assert bdel_res == 1
		# 检查策略移除是否成功
		for key in self.case1_step1:
			re = fun.wait_data(self.case1_step1[key][0], 'FrontDut', self.case1_step1[key][1], '配置', 100, flag='不存在')
			print(re)
			assert self.case1_step1[key][1] not in re

		# 检查ftp传输策略是否清空
		print('10、移除ftp传输策略，等待nginx的24个进程起来；cat /etc/jsac/filter.json文件应该不包含：ftp协议')
		fun.send(rbmExc, message.delftpcheck['DropFtpCheck'], FrontDomain, base_path)
		fun.wait_data('ps -ef |grep nginx', 'FrontDut', 'nginx: worker process')
		del_res2 = fun.nginx_worker('ps -ef |grep nginx', 'FrontDut', 'nginx: worker process')
		assert del_res2 == 1
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


