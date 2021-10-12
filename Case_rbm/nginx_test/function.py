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
	from common import fun
	import common.ssh as c_ssh
	from nginx_test import message
	from nginx_test import index
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

rbmDomain = baseinfo.rbmDomain
rbmExc = baseinfo.rbmExc
proxy_ip = baseinfo.gwServerIp
smtp_ip = baseinfo.smtp_ip

class Test_nginx_test():

	def setup_class(self):
		# 获取参数
		fun.ssh_gw.connect()
		#fun.rbm.connect()
		self.clr_env = clr_env.clear_env
		self.case1_step1 = index.case1_step1
		self.case1_step2 = index.case1_step2

		for i in self.clr_env:
			print(i)
			dd = fun.cmd(i, 'gw')
			print(dd)

	@allure.feature('测试nginx')
	def test_nginx_test_a1(self):
		# 清空环境
		for i in self.clr_env:
			fun.cmd(i, 'gw')

		for i in range(100):
			# fun.cmd('systemctl reload nginx_fstack', 'gw')
			fun.send(rbmExc, message.addsmtp['AddAgent'], rbmDomain, base_path)
			fun.wait_data('ps -ef |grep nginx', 'gw', 'nginx: worker process')
			fun.nginx_worker('ps -ef |grep nginx', 'gw', 'nginx: worker process')
			fun.send(rbmExc, message.addpop3['AddAgent'], rbmDomain, base_path)
			fun.wait_data('ps -ef |grep nginx', 'gw', 'nginx: worker process')
			fun.nginx_worker('ps -ef |grep nginx', 'gw', 'nginx: worker process')
			ff = fun.cmd('ff_netstat -an', 'gw')
			print('ff结果为：{}'.format(ff))
			assert proxy_ip in ff

			fun.send(rbmExc, message.mailcheck1['SetMailCheck'], rbmDomain, base_path)
			fun.wait_data('ps -ef |grep nginx', 'gw', 'nginx: worker process')
			fun.nginx_worker('ps -ef |grep nginx', 'gw', 'nginx: worker process')

			# 配置清空
			fun.send(rbmExc, message.delsmtp['DelAgent'], rbmDomain, base_path)
			fun.wait_data('ps -ef |grep nginx', 'gw', 'nginx: worker process')
			fun.nginx_worker('ps -ef |grep nginx', 'gw', 'nginx: worker process')
			fun.send(rbmExc, message.delpop3['DelAgent'], rbmDomain, base_path)
			fun.wait_data('ps -ef |grep nginx', 'gw', 'nginx: worker process')
			fun.nginx_worker('ps -ef |grep nginx', 'gw', 'nginx: worker process')
			print('已经执行了{}次'.format(i+1))

	def teardown_class(self):
		# 回收环境
		fun.rbm_close()
		fun.ssh_close('gw')


