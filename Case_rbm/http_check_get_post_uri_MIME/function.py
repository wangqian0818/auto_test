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
	from http_check_get_post_uri_MIME import index
	from http_check_get_post_uri_MIME import message
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
from data_check import http_check

datatime = time.strftime('%Y-%m-%d %H:%M:%S',time.localtime(time.time()))

rbmDomain = baseinfo.rbmDomain
rbmExc = baseinfo.rbmExc
url = baseinfo.http_url
http_content = baseinfo.http_content

class Test_http_check_get_post_uri_MIME ():

	def setup_method(self):
		clr_env.data_check_setup_met()

	def teardown_method(self):
		clr_env.data_check_teardown_met('http', base_path)


	def setup_class(self):
		# 获取参数
		fun.ssh_gw.connect()
		self.clr_env = clr_env
		self.case1_step1 = index.case1_step1
		self.case1_step2 = index.case1_step2
		self.case2_step1 = index.case2_step1
		self.case2_step2 = index.case2_step2
		self.delcheck = index.delcheck
		self.data = index.data
		self.case1_get_data1 = index.case1_get_data1
		self.case1_get_data2 = index.case1_get_data2
		self.case1_post_data1 = index.case1_post_data1
		self.case1_post_data2 = index.case1_post_data2
		self.case1_uri1 = index.case1_uri1
		self.case1_uri2 = index.case1_uri2
		self.case1_MIME1 = index.case1_MIME1
		self.case1_MIME2 = index.case1_MIME2
		self.base_uri = index.base_uri

		clr_env.clear_env()

	# @pytest.mark.skip(reseason="skip")
	@allure.feature('验证基于URI黑名单、get请求方法、post请求方法、MIME多种类型设置放行的网页访问策略')
	def test_http_check_get_post_uri_MIME_a1(self):

		# 下发配置
		fun.send(rbmExc, message.addhttp['AddAgent'], rbmDomain, base_path)
		fun.wait_data('ps -ef |grep nginx', 'gw', 'nginx: worker process')
		add_res1 = fun.nginx_worker('ps -ef |grep nginx', 'gw', 'nginx: worker process')
		assert add_res1 == 1
		# 检查配置下发是否成功
		for key in self.case1_step1:
			re = fun.wait_data(self.case1_step1[key][0], 'gw', self.case1_step1[key][1], '配置', 100)
			print(re)
			assert self.case1_step1[key][1] in re

		fun.send(rbmExc, message.httpcheck1['SetHttpCheck'], rbmDomain, base_path)
		fun.wait_data('ps -ef |grep nginx', 'gw', 'nginx: worker process')
		add_res2 = fun.nginx_worker('ps -ef |grep nginx', 'gw', 'nginx: worker process')
		assert add_res2 == 1
		for key in self.case1_step2:
			re = fun.wait_data(self.case1_step2[key][0], 'gw', self.case1_step2[key][1], '配置', 100)
			print(re)
			assert self.case1_step2[key][1] in re

		# 1、发送get请求，不包含黑名单内容的普通请求
		content = http_check.http_get(url)
		print('1、get普通请求的请求内容为：{}'.format(content))
		assert content == http_content

		# 2、发送post请求，不包含黑名单内容的普通请求
		content = http_check.http_post(url)
		print('2、post普通请求的请求内容为：{}'.format(content))
		assert content == http_content

		# 3、发送get请求，请求内容包含第一个get黑名单
		status_code1 = http_check.http_get(url,self.case1_get_data1)
		print('3、get请求内容包含第一个get黑名单返回的状态码为：{}'.format(status_code1))
		assert status_code1 == 403

		# 4、发送get请求，请求内容包含第二个get黑名单
		status_code2 = http_check.http_get(url, self.case1_get_data2)
		print('4、get请求内容包含第二个get黑名单返回的状态码为：{}'.format(status_code2))
		assert status_code2 == 403

		# 5、发送get请求，请求内容包含第一个uri黑名单
		status_code3 = http_check.http_get(self.case1_uri1, self.data)
		print('5、get请求内容包含第一个uri黑名单返回的状态码为：{}'.format(status_code3))
		assert status_code3 == 403

		# 6、发送get请求，请求内容包含第二个uri黑名单
		status_code4 = http_check.http_get(self.case1_uri2, self.data)
		print('6、get请求内容包含第二个uri黑名单返回的状态码为：{}'.format(status_code4))
		assert status_code4 == 403

		# 7、发送get请求，请求内容包含第一个post黑名单
		content = http_check.http_get(url,self.case1_post_data1)
		print('7、get请求内容包含第一个post黑名单的请求内容为：{}'.format(content))
		assert content == http_content

		# 8、发送get请求，请求内容包含第二个post黑名单
		content = http_check.http_get(url,self.case1_post_data2)
		print('8、get请求内容包含第二个post黑名单的请求内容为：{}'.format(content))
		assert content == http_content

		# 9、发送post请求，请求内容包含第一个post黑名单
		status_code5 = http_check.http_post(url, self.case1_post_data1)
		print('9、post请求内容包含第一个post黑名单返回的状态码为：{}'.format(status_code5))
		assert status_code5 == 403

		# 10、发送post请求，请求内容包含第二个post黑名单
		status_code6 = http_check.http_post(url, self.case1_post_data2)
		print('10、post请求内容包含第二个post黑名单返回的状态码为：{}'.format(status_code6))
		assert status_code6 == 403

		# 11、发送post请求，请求内容包含第一个uri黑名单
		status_code7 = http_check.http_post(self.case1_uri1, self.data)
		print('11、post请求内容包含第一个uri黑名单返回的状态码为：{}'.format(status_code7))
		assert status_code7 == 403

		# 12、发送post请求，请求内容包含第二个uri黑名单
		status_code8 = http_check.http_post(self.case1_uri2, self.data)
		print('12、post请求内容包含第二个uri黑名单返回的状态码为：{}'.format(status_code8))
		assert status_code8 == 403

		# 13、发送post请求，请求内容包含第一个get黑名单
		content = http_check.http_post(url,self.case1_get_data1)
		print('13、post请求内容包含第一个get黑名单的请求内容为：{}'.format(content))
		assert content == http_content

		# 14、发送post请求，请求内容包含第二个get黑名单
		content = http_check.http_post(url,self.case1_get_data2)
		print('14、post请求内容包含第二个get黑名单的请求内容为：{}'.format(content))
		assert content == http_content

		# 15、发送get请求，请求内容包含第一个MIME白名单
		status_code9 = http_check.http_get(self.case1_MIME1, self.data, flag=1)
		print('15、get请求内容包含第一个MIME白名单返回的状态码为：{}'.format(status_code9))
		assert status_code9 == 200

		# 16、发送get请求，请求内容包含第二个MIME白名单
		status_code10 = http_check.http_get(self.case1_MIME2, self.data, flag=1)
		print('16、get请求内容包含第二个MIME白名单返回的状态码为：{}'.format(status_code10))
		assert status_code10 == 200

		# 17、发送get请求，请求内容包含MIME类型不在白名单
		status_code11 = http_check.http_get(self.base_uri, self.data, flag=1)
		print('17、get请求内容包含MIME类型不在白名单返回的状态码为：{}'.format(status_code11))
		assert status_code11 == 403

		# 18、发送get请求，请求内容包含MIME白名单和get黑名单
		status_code12 = http_check.http_get(self.case1_MIME1, self.case1_get_data2, flag=1)
		print('18、get请求内容包含MIME白名单和get黑名单返回的状态码为：{}'.format(status_code12))
		assert status_code12 == 403

		# 19、发送get请求，请求内容包含MIME白名单和post黑名单
		status_code13 = http_check.http_get(self.case1_MIME2, self.case1_post_data1, flag=1)
		print('19、get请求内容包含MIME白名单和post黑名单返回的状态码为：{}'.format(status_code13))
		assert status_code13 == 200

		# 移除策略，还原环境
		fun.send(rbmExc, message.delhttp['DelAgent'], rbmDomain, base_path)
		fun.wait_data('ps -ef |grep nginx', 'gw', 'nginx: worker process')
		del_res1 = fun.nginx_worker('ps -ef |grep nginx', 'gw', 'nginx: worker process')
		assert del_res1 == 1
		# 检查代理是否成功移除
		for key in self.case1_step1:
			re = fun.wait_data(self.case1_step1[key][0], 'gw', self.case1_step1[key][1], '配置', 100, flag='不存在')
			assert self.case1_step1[key][1] not in re
		# 检查网页访问策略是否清空
		fun.send(rbmExc, message.delhttpcheck['DropHttpCheck'], rbmDomain, base_path)
		fun.wait_data('ps -ef |grep nginx', 'gw', 'nginx: worker process')
		del_res2 = fun.nginx_worker('ps -ef |grep nginx', 'gw', 'nginx: worker process')
		assert del_res2 == 1
		for key in self.delcheck:
			re = fun.wait_data(self.delcheck[key][0], 'gw', self.delcheck[key][1], '配置', 100, flag='不存在')
			assert self.delcheck[key][1] not in re

	# @pytest.mark.skip(reseason="skip")
	@allure.feature('验证基于URI黑名单、get请求方法、post请求方法、MIME多种类型设置阻断的网页访问策略')
	def test_http_check_get_post_uri_MIME_a2(self):

		# 下发配置
		fun.send(rbmExc, message.addhttp['AddAgent'], rbmDomain, base_path)
		fun.wait_data('ps -ef |grep nginx', 'gw', 'nginx: worker process')
		add_res1 = fun.nginx_worker('ps -ef |grep nginx', 'gw', 'nginx: worker process')
		assert add_res1 == 1
		# 检查配置下发是否成功
		for key in self.case2_step1:
			re = fun.wait_data(self.case2_step1[key][0], 'gw', self.case2_step1[key][1], '配置', 100)
			print(re)
			assert self.case2_step1[key][1] in re

		fun.send(rbmExc, message.httpcheck2['SetHttpCheck'], rbmDomain, base_path)
		fun.wait_data('ps -ef |grep nginx', 'gw', 'nginx: worker process')
		add_res2 = fun.nginx_worker('ps -ef |grep nginx', 'gw', 'nginx: worker process')
		assert add_res2 == 1
		for key in self.case2_step2:
			re = fun.wait_data(self.case2_step2[key][0], 'gw', self.case2_step2[key][1], '配置', 100)
			print(re)
			assert self.case2_step2[key][1] in re

		# 1、发送get请求，不包含黑名单内容的普通请求
		content = http_check.http_get(url)
		print('1、get普通请求的请求内容为：{}'.format(content))
		assert content == http_content

		# 2、发送post请求，不包含黑名单内容的普通请求
		content = http_check.http_post(url)
		print('2、post普通请求的请求内容为：{}'.format(content))
		assert content == http_content

		# 3、发送get请求，请求内容包含第一个get黑名单
		status_code = http_check.http_get(url,self.case1_get_data1)
		print('3、get请求内容包含第一个get黑名单返回的状态码为：{}'.format(status_code))
		assert status_code == 403

		# 4、发送get请求，请求内容包含第二个get黑名单
		status_code = http_check.http_get(url, self.case1_get_data2)
		print('4、get请求内容包含第二个get黑名单返回的状态码为：{}'.format(status_code))
		assert status_code == 403

		# 5、发送get请求，请求内容包含第一个uri黑名单
		status_code = http_check.http_get(self.case1_uri1, self.data)
		print('5、get请求内容包含第一个uri黑名单返回的状态码为：{}'.format(status_code))
		assert status_code == 403

		# 6、发送get请求，请求内容包含第二个uri黑名单
		status_code = http_check.http_get(self.case1_uri2, self.data)
		print('6、get请求内容包含第二个uri黑名单返回的状态码为：{}'.format(status_code))
		assert status_code == 403

		# 7、发送get请求，请求内容包含第一个post黑名单
		content = http_check.http_get(url,self.case1_post_data1)
		print('7、get请求内容包含第一个post黑名单的请求内容为：{}'.format(content))
		assert content == http_content

		# 8、发送get请求，请求内容包含第二个post黑名单
		content = http_check.http_get(url,self.case1_post_data2)
		print('8、get请求内容包含第二个post黑名单的请求内容为：{}'.format(content))
		assert content == http_content

		# 9、发送post请求，请求内容包含第一个post黑名单
		status_code = http_check.http_post(url, self.case1_post_data1)
		print('9、post请求内容包含第一个post黑名单返回的状态码为：{}'.format(status_code))
		assert status_code == 403

		# 10、发送post请求，请求内容包含第二个post黑名单
		status_code = http_check.http_post(url, self.case1_post_data2)
		print('10、post请求内容包含第二个post黑名单返回的状态码为：{}'.format(status_code))
		assert status_code == 403

		# 11、发送post请求，请求内容包含第一个uri黑名单
		status_code = http_check.http_post(self.case1_uri1, self.data)
		print('11、post请求内容包含第一个uri黑名单返回的状态码为：{}'.format(status_code))
		assert status_code == 403

		# 12、发送post请求，请求内容包含第二个uri黑名单
		status_code = http_check.http_post(self.case1_uri2, self.data)
		print('12、post请求内容包含第二个uri黑名单返回的状态码为：{}'.format(status_code))
		assert status_code == 403

		# 13、发送post请求，请求内容包含第一个get黑名单
		content = http_check.http_post(url,self.case1_get_data1)
		print('13、post请求内容包含第一个get黑名单的请求内容为：{}'.format(content))
		assert content == http_content

		# 14、发送post请求，请求内容包含第二个get黑名单
		content = http_check.http_post(url,self.case1_get_data2)
		print('14、post请求内容包含第二个get黑名单的请求内容为：{}'.format(content))
		assert content == http_content

		# 15、发送get请求，请求内容包含第一个MIME黑名单
		status_code = http_check.http_get(self.case1_MIME1, self.data, flag=1)
		print('15、get请求内容包含第一个MIME黑名单返回的状态码为：{}'.format(status_code))
		assert status_code == 403

		# 16、发送get请求，请求内容包含第二个MIME黑名单
		status_code = http_check.http_get(self.case1_MIME2, self.data, flag=1)
		print('16、get请求内容包含第二个MIME黑名单返回的状态码为：{}'.format(status_code))
		assert status_code == 403

		# 17、发送get请求，请求内容包含MIME类型不在黑名单
		status_code = http_check.http_get(self.base_uri, self.data, flag=1)
		print('17、get请求内容包含MIME类型不在白名单返回的状态码为：{}'.format(status_code))
		assert status_code == 200

		# 18、发送get请求，请求内容包含MIME黑名单和post黑名单
		status_code = http_check.http_get(self.case1_MIME2, self.case1_post_data1, flag=1)
		print('18、get请求内容包含MIME黑名单和post黑名单返回的状态码为：{}'.format(status_code))
		assert status_code == 403

		# 18、发送get请求，请求内容包含MIME类型不为黑名单和get黑名单
		status_code = http_check.http_get(self.base_uri, self.case1_get_data1, flag=1)
		print('18、get请求内容包含MIME类型不为黑名单和get黑名单返回的状态码为：{}'.format(status_code))
		assert status_code == 403

		# 移除策略，还原环境
		fun.send(rbmExc, message.delhttp['DelAgent'], rbmDomain, base_path)
		fun.wait_data('ps -ef |grep nginx', 'gw', 'nginx: worker process')
		del_res1 = fun.nginx_worker('ps -ef |grep nginx', 'gw', 'nginx: worker process')
		assert del_res1 == 1
		# 检查代理是否成功移除
		for key in self.case2_step1:
			re = fun.wait_data(self.case2_step1[key][0], 'gw', self.case2_step1[key][1], '配置', 100, flag='不存在')
			assert self.case2_step1[key][1] not in re
		# 检查网页访问策略是否清空
		fun.send(rbmExc, message.delhttpcheck['DropHttpCheck'], rbmDomain, base_path)
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