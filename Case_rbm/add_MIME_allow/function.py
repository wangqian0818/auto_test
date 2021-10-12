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
	from add_MIME_allow import index
	from add_MIME_allow import message
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
#del sys.path[0]
from common import baseinfo
from common.rabbitmq import *
from data_check import http_check

datatime = time.strftime('%Y-%m-%d %H:%M:%S',time.localtime(time.time()))

rbmDomain = baseinfo.rbmDomain
rbmExc = baseinfo.rbmExc
url = baseinfo.http_url
http_content = baseinfo.http_content

class Test_add_MIME_allow():

	# def setup_method(self):
	#
	# 	self.clr_met = clr_env.clear_met
	#
	# 	for i in self.clr_met:
	# 		fun.cmd(i, 'gw')
	#
	# def teardown_method(self):
	# 	self.clr_met = clr_env.clear_met
	#
	# 	for i in self.clr_met:
	# 		fun.cmd(i, 'gw')


	def setup_class(self):
		# 获取参数
		fun.ssh_gw.connect()
		#fun.rbm.connect()
		self.case1_step1 = index.case1_step1
		self.case1_step2 = index.case1_step2
		self.case2_step1 = index.case2_step1
		self.case2_step2 = index.case2_step2
		self.data = index.data
		self.case1_uri = index.case1_uri
		self.case2_uri1 = index.case2_uri1
		self.case2_uri2 = index.case2_uri2
		self.case2_uri3 = index.case2_uri3
		self.case2_uri4 = index.case2_uri4
		self.case2_uri5 = index.case2_uri5
		self.base_uri = index.base_uri

	@allure.feature('验证基于多种MIME类型设置放行的网页访问策略')
	def test_add_MIME_allow(self):
		# 下发配置
		fun.send(rbmExc, message.addhttp['AddAgent'], rbmDomain, base_path)
		fun.wait_data('ps -ef |grep nginx', 'gw', 'nginx: worker process')
		fun.nginx_worker('ps -ef |grep nginx', 'gw', 'nginx: worker process')


		fun.send(rbmExc, message.httpcheck2['SetHttpCheck'], rbmDomain, base_path)
		fun.wait_data('ps -ef |grep nginx', 'gw', 'nginx: worker process')
		fun.nginx_worker('ps -ef |grep nginx', 'gw', 'nginx: worker process')

		#
		# # 配置清空
		# fun.send(rbmExc, message.delhttp['DelAgent'], rbmDomain, base_path)
		# fun.wait_data('ps -ef |grep nginx', 'gw', 'nginx: worker process')
		# fun.nginx_worker('ps -ef |grep nginx', 'gw', 'nginx: worker process')

	def teardown_class(self):
		# 回收环境
		# for i in clr_env.clear_env:
		# 	fun.cmd(i, 'gw')

		fun.rbm_close()
		fun.ssh_close('gw')


