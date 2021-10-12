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
	from iso_customapp_priority import index
	from iso_customapp_priority import message
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
#sys.path.append(os.getcwd())

from common import clr_env
from common import baseinfo
from common.rabbitmq import *
from data_check import http_check


datatime = time.strftime('%Y-%m-%d %H:%M:%S',time.localtime(time.time()))

FrontDomain = baseinfo.BG8010FrontDomain
BackDomain = baseinfo.BG8010BackDomain
proxy_ip = baseinfo.BG8010FrontOpeIp
proxy_port = baseinfo.app_proxy_port
rbmExc = baseinfo.rbmExc
url = 'http://'+ index.app_ip
http_content = baseinfo.http_content

class Test_customapp_priority():

    def setup_method(self):
        clr_env.data_check_setup_met(dut='FrontDut')
        clr_env.data_check_setup_met(dut='BackDut')

    def teardown_method(self):
        clr_env.iso_teardown_met('app_allow', base_path)
        # print(1111111111)


    def setup_class(self):
        # 获取参数
        fun.ssh_FrontDut.connect()
        fun.ssh_BackDut.connect()
        self.case0_step1 = index.case0_step1
        self.case1_step1 = index.case1_step1
        self.case1_step2 = index.case1_step2
        self.case1_step3 = index.case1_step3
        self.case1_step4 = index.case1_step4
        self.case2_step1 = index.case2_step1
        self.case2_step2 = index.case2_step2
        self.case2_step3 = index.case2_step3
        self.case2_step4 = index.case2_step4

        clr_env.iso_setup_class(dut='FrontDut')
        clr_env.iso_setup_class(dut='BackDut')
    #@pytest.mark.skip(reseason="skip")
    @allure.feature('验证定制应用多个规则下的动作优先级1')
    def test_customapp_priority1(self):

        # 下发配置
        fun.send(rbmExc, message.add_app_priority1_front['AddCustomAppPolicy'], FrontDomain, base_path)
        fun.send(rbmExc, message.add_app_priority1_back['AddCustomAppPolicy'], BackDomain, base_path)
        fun.wait_data('ps -ef |grep nginx', 'FrontDut', 'nginx: worker process')
        front_res1 = fun.nginx_worker('ps -ef |grep nginx', 'FrontDut', 'nginx: worker process', name='前置机nginx进程')
        assert front_res1 == 1
        fun.wait_data('ps -ef |grep nginx', 'BackDut', 'nginx: worker process')
        back_res1 = fun.nginx_worker('ps -ef |grep nginx', 'BackDut', 'nginx: worker process',name= '后置机nginx进程')
        assert back_res1 == 1
        # 检查配置下发是否成功
        for key in self.case1_step1:
            re = fun.wait_data(self.case1_step1[key][0], 'FrontDut', self.case1_step1[key][1], '前置机配置', 100)
            assert self.case1_step1[key][1] in re

        for key in self.case1_step2:
            re = fun.wait_data(self.case1_step2[key][0], 'FrontDut', self.case1_step2[key][1], '前置机配置', 100)
            assert self.case1_step2[key][1] in re

        for key in self.case0_step1:
            re = fun.wait_data(self.case0_step1[key][0], 'BackDut', self.case0_step1[key][1], '后置机配置', 100)
            assert self.case0_step1[key][1] in re

        # 发送请求，检测定制应用通信策略是否生效
        status_code = http_check.http_get(url,flag=1)
        print('url:',url)
        print('验证优先级1，get请求的请求内容为：{}'.format(status_code), )
        assert status_code == 200

        # 文件查看audit日志
        fun.wait_data(f"grep -n {proxy_port} /usr/local/nginx/logs/audit.log |tail -1", 'FrontDut',self.case1_step3['step1'][0], '检查Default Deny', 300, flag='存在')
        for key in self.case1_step3:
            re = fun.cmd(f"grep -n {proxy_port} /usr/local/nginx/logs/audit.log |tail -1 ", 'FrontDut')
            print('re:', re)
            assert self.case1_step3[key][0] in re

         # 移除策略配置
        fun.send(rbmExc, message.del_app_upstream_front['DelCustomAppPolicy'], FrontDomain, base_path)
        fun.send(rbmExc, message.del_app_upstream_back['DelCustomAppPolicy'], BackDomain, base_path)
        fun.wait_data('ps -ef |grep nginx', 'FrontDut', 'nginx: worker process')
        front_res1 = fun.nginx_worker('ps -ef |grep nginx', 'FrontDut', 'nginx: worker process', name='前置机nginx进程')
        assert front_res1 == 1
        fun.wait_data('ps -ef |grep nginx', 'BackDut', 'nginx: worker process')
        back_res1 = fun.nginx_worker('ps -ef |grep nginx', 'BackDut', 'nginx: worker process', name='后置机nginx进程')
        assert back_res1 == 1
        #检查配置移除是否成功
        for key in self.case1_step4:
            re = fun.wait_data(self.case1_step4[key][0], 'FrontDut', self.case1_step4[key][1], '前置机配置', 100 ,flag='不存在')
            assert self.case1_step4[key][1] not in re

        for key in self.case0_step1:
            re = fun.wait_data(self.case0_step1[key][0], 'BackDut', self.case0_step1[key][1], '后置机配置', 100, flag='不存在')
            assert self.case0_step1[key][1] not in re



    # @pytest.mark.skip(reseason="skip")
    @allure.feature('验证定制应用多个规则下的动作优先级2')
    def test_customapp_priority2(self):

        # 下发配置
        fun.send(rbmExc, message.add_app_priority2_front['AddCustomAppPolicy'], FrontDomain, base_path)
        fun.send(rbmExc, message.add_app_priority2_back['AddCustomAppPolicy'], BackDomain, base_path)
        fun.wait_data('ps -ef |grep nginx', 'FrontDut', 'nginx: worker process')
        front_res1 = fun.nginx_worker('ps -ef |grep nginx', 'FrontDut', 'nginx: worker process', name='前置机nginx进程')
        assert front_res1 == 1
        fun.wait_data('ps -ef |grep nginx', 'BackDut', 'nginx: worker process')
        back_res1 = fun.nginx_worker('ps -ef |grep nginx', 'BackDut', 'nginx: worker process', name='后置机nginx进程')
        assert back_res1 == 1
        # 检查配置下发是否成功
        for key in self.case2_step1:
            re = fun.cmd(self.case2_step1[key][0], 'FrontDut')
            print(re)
            fun.wait_data(self.case2_step1[key][0], 'FrontDut', self.case2_step1[key][1], '前置机配置', 100)
            assert self.case2_step1[key][1] in re

        for key in self.case2_step2:
            re = fun.cmd(self.case2_step2[key][0], 'FrontDut')
            print(re)
            fun.wait_data(self.case2_step2[key][0], 'FrontDut', self.case2_step2[key][1], '前置机配置', 100)
            assert self.case2_step2[key][1] in re

        for key in self.case0_step1:
            re = fun.wait_data(self.case0_step1[key][0], 'BackDut', self.case0_step1[key][1], '后置机配置', 100)
            assert self.case0_step1[key][1] in re

        # 发送请求，检测定制应用通信策略是否生效
        status_code = http_check.http_get(url,flag=1)
        print('url:', url)
        print('验证优先级2，get请求的请求内容为：{}'.format(status_code), '，请求被禁止。')
        assert status_code == 0

        # 文件查看audit日志
        fun.wait_data(f"grep -n {proxy_port} /usr/local/nginx/logs/audit.log |tail -1", 'FrontDut',self.case2_step3['step1'][0], '检查Default Deny', 300, flag='存在')
        for key in self.case2_step3:
            re = fun.cmd(f"grep -n {proxy_port} /usr/local/nginx/logs/audit.log |tail -1 ", 'FrontDut')
            print('re:', re)
            assert self.case2_step3[key][0] in re

        # 移除策略配置
        fun.send(rbmExc, message.del_app_upstream_front['DelCustomAppPolicy'], FrontDomain, base_path)
        fun.send(rbmExc, message.del_app_upstream_back['DelCustomAppPolicy'], BackDomain, base_path)
        fun.wait_data('ps -ef |grep nginx', 'FrontDut', 'nginx: worker process')
        front_res1 = fun.nginx_worker('ps -ef |grep nginx', 'FrontDut', 'nginx: worker process', name='前置机nginx进程')
        assert front_res1 == 1
        fun.wait_data('ps -ef |grep nginx', 'BackDut', 'nginx: worker process')
        back_res1 = fun.nginx_worker('ps -ef |grep nginx', 'BackDut', 'nginx: worker process', name='后置机nginx进程')
        assert back_res1 == 1
        # 检查配置移除是否成功
        for key in self.case2_step4:
            re = fun.wait_data(self.case2_step4[key][0], 'FrontDut', self.case2_step4[key][1], '前置机配置', 100 ,flag='不存在')
            assert self.case2_step4[key][1] not in re

        for key in self.case0_step1:
            re = fun.wait_data(self.case0_step1[key][0], 'BackDut', self.case0_step1[key][1], '后置机配置', 100, flag='不存在')
            assert self.case0_step1[key][1] not in re




    def teardown_class(self):
        # 回收环境
        clr_env.iso_setup_class(dut='FrontDut')
        clr_env.iso_setup_class(dut='BackDut')

        fun.rbm_close()
        fun.ssh_close('FrontDut')
        fun.ssh_close('BackDut')
