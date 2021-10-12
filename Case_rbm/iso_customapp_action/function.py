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
	from iso_customapp_action import index
	from iso_customapp_action import message
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
# dport = baseinfo.http_server_port

class Test_customapp_action():

    def setup_method(self):
        clr_env.data_check_setup_met(dut='FrontDut')
        clr_env.data_check_setup_met(dut='BackDut')

    def teardown_method(self):
        clr_env.iso_teardown_met('app_allow', base_path)
        clr_env.iso_teardown_met('app_deny', base_path)
        clr_env.iso_teardown_met('app_end_deny', base_path)
        # print(1111111111)


    def setup_class(self):
        # 获取参数
        fun.ssh_FrontDut.connect()
        fun.ssh_BackDut.connect()
        self.case0_step1 = index.case0_step1
        self.case1_step1 = index.case1_step1
        self.case1_step2 = index.case1_step2
        self.case1_step3 = index.case1_step3
        # self.case2_step1 = index.case2_step1
        # self.case2_step2 = index.case2_step2
        self.case3_step1 = index.case3_step1
        self.case3_step2 = index.case3_step2
        self.case3_step3 = index.case3_step3
        self.case4_step1 = index.case4_step1
        self.case4_step2 = index.case4_step2
        self.case4_step3 = index.case4_step3
        self.case4_step4 = index.case4_step4
        self.case6_step1 = index.case6_step1
        self.case6_step2 = index.case6_step2
        self.case6_step3 = index.case6_step3
        self.case7_step1 = index.case7_step1
        self.case7_step2 = index.case7_step2
        self.case7_step3 = index.case7_step3
        self.case7_step4 = index.case7_step4

        clr_env.iso_setup_class(dut='FrontDut')
        clr_env.iso_setup_class(dut='BackDut')

    # @pytest.mark.skip(reseason="skip")
    @allure.feature('验证默认动作为允许，应用、规则动作为允许时的定制应用通行策略 ')
    def test_customapp_default_action_allow(self):

        # 下发配置
        fun.send(rbmExc, message.add_app_default_action_front['AddCustomAppPolicy'], FrontDomain, base_path)
        fun.send(rbmExc, message.add_app_default_action_back['AddCustomAppPolicy'], BackDomain, base_path)
        fun.wait_data('ps -ef |grep nginx', 'FrontDut', 'nginx: worker process')
        front_res1 = fun.nginx_worker('ps -ef |grep nginx', 'FrontDut', 'nginx: worker process',name='前置机nginx进程')
        assert front_res1 ==1
        fun.wait_data('ps -ef |grep nginx', 'BackDut', 'nginx: worker process')
        back_res1 = fun.nginx_worker('ps -ef |grep nginx', 'BackDut', 'nginx: worker process',name='后置机nginx进程')
        assert back_res1 == 1
        fun.send(rbmExc, message.set_app_default_action_allow['SetCustomAppAction'], FrontDomain, base_path)
        fun.wait_data('ps -ef |grep nginx', 'FrontDut', 'nginx: worker process')
        front_res1 = fun.nginx_worker('ps -ef |grep nginx', 'FrontDut', 'nginx: worker process', name='前置机nginx进程')
        assert front_res1 == 1
        # 检查配置下发是否成功
        for key in self.case1_step1:
            # re = fun.cmd(self.case1_step1[key][0], 'FrontDut')
            # print(re)
            re = fun.wait_data(self.case1_step1[key][0], 'FrontDut', self.case1_step1[key][1], '前置机配置', 100)
            assert self.case1_step1[key][1] in re

        for key in self.case1_step2:
            # re = fun.cmd(self.case1_step2[key][0], 'FrontDut')
            # print(re)
            re = fun.wait_data(self.case1_step2[key][0], 'FrontDut', self.case1_step2[key][1], '前置机配置', 100)
            assert self.case1_step2[key][1] in re

        for key in self.case0_step1:
            re = fun.wait_data(self.case0_step1[key][0],'BackDut',self.case0_step1[key][1],'后置机配置',100)
            assert  self.case0_step1[key][1] in re

        # 发送请求，检测定制应用通信策略是否生效
        status_code = http_check.http_get(url,flag=1)
        print('url:', url)
        print('验证默认动作为允许，应用、规则动作为允许时的定制应用通行策略，get请求的请求内容为：{}'.format(status_code))
        assert status_code == 200

        #移除策略
        fun.send(rbmExc, message.del_app_upstream_front['DelCustomAppPolicy'], FrontDomain, base_path)
        fun.send(rbmExc, message.del_app_upstream_back['DelCustomAppPolicy'], BackDomain, base_path)
        fun.wait_data('ps -ef |grep nginx', 'FrontDut', 'nginx: worker process')
        front_res1 = fun.nginx_worker('ps -ef |grep nginx', 'FrontDut', 'nginx: worker process',name='前置机nginx进程')
        assert front_res1 == 1
        fun.wait_data('ps -ef |grep nginx', 'BackDut', 'nginx: worker process')
        back_res1 = fun.nginx_worker('ps -ef |grep nginx', 'BackDut', 'nginx: worker process',name='后置机nginx进程')
        assert back_res1 == 1
        # 检查配置移除是否成功
        for key in self.case1_step3:
            # re = fun.cmd(self.case1_step1[key][0], 'FrontDut')
            # print(re)
            re = fun.wait_data(self.case1_step3[key][0], 'FrontDut', self.case1_step3[key][1], '前置机配置', 100,flag='不存在')
            assert self.case1_step3[key][1] not in re

        for key in self.case0_step1:
            re = fun.wait_data(self.case0_step1[key][0],'BackDut',self.case0_step1[key][1],'后置机配置',100,flag='不存在')
            assert self.case0_step1[key][1] not in re



    # @pytest.mark.skip(reseason="skip")
    @allure.feature('验证应用动作为允许，默认动作允许、规则动作为拒绝时的定制应用通行策略')
    def test_customapp_app_action_allow(self):

        # 下发配置
        fun.send(rbmExc, message.add_app_action_allow_front['AddCustomAppPolicy'], FrontDomain, base_path)
        fun.send(rbmExc, message.add_app_action_allow_back['AddCustomAppPolicy'], BackDomain, base_path)
        fun.wait_data('ps -ef |grep nginx', 'FrontDut', 'nginx: worker process')
        front_res1 = fun.nginx_worker('ps -ef |grep nginx', 'FrontDut', 'nginx: worker process',name='前置机nginx进程')
        assert front_res1 == 1
        fun.wait_data('ps -ef |grep nginx', 'BackDut', 'nginx: worker process')
        back_res1 = fun.nginx_worker('ps -ef |grep nginx', 'BackDut', 'nginx: worker process',name='后置机nginx进程')
        assert back_res1 == 1
        fun.send(rbmExc, message.set_app_default_action_allow['SetCustomAppAction'], FrontDomain, base_path)
        fun.wait_data('ps -ef |grep nginx', 'FrontDut', 'nginx: worker process')
        front_res1 = fun.nginx_worker('ps -ef |grep nginx', 'FrontDut', 'nginx: worker process', name='前置机nginx进程')
        assert front_res1 == 1
        # 检查配置下发是否成功
        for key in self.case3_step1:
            re = fun.wait_data(self.case3_step1[key][0], 'FrontDut', self.case3_step1[key][1], '前置机配置', 100)
            assert self.case3_step1[key][1] in re

        for key in self.case3_step2:
            re = fun.wait_data(self.case3_step2[key][0], 'FrontDut', self.case3_step2[key][1], '前置机配置', 100)
            assert self.case3_step2[key][1] in re

        for key in self.case0_step1:
            re = fun.wait_data(self.case0_step1[key][0],'BackDut',self.case0_step1[key][1],'后置机配置',100)
            assert  self.case0_step1[key][1] in re

        # 发送请求，检测定制应用通信策略是否生效
        status_code = http_check.http_get(url,flag=1)
        print('url:', url)
        print('验证应用动作为允许，默认动作允许、规则动作为拒绝时的定制应用通行策略，get请求的请求内容为：{}'.format(status_code))
        assert status_code == 200

        #移除策略
        fun.send(rbmExc, message.del_app_upstream_front['DelCustomAppPolicy'], FrontDomain, base_path)
        fun.send(rbmExc, message.del_app_upstream_back['DelCustomAppPolicy'], BackDomain, base_path)
        fun.wait_data('ps -ef |grep nginx', 'FrontDut', 'nginx: worker process')
        front_res1 = fun.nginx_worker('ps -ef |grep nginx', 'FrontDut', 'nginx: worker process', name='前置机nginx进程')
        assert front_res1 == 1
        fun.wait_data('ps -ef |grep nginx', 'BackDut', 'nginx: worker process')
        back_res1 = fun.nginx_worker('ps -ef |grep nginx', 'BackDut', 'nginx: worker process', name='后置机nginx进程')
        assert back_res1 == 1
        # 检查配置移除是否成功
        for key in self.case3_step3:
            re = fun.wait_data(self.case3_step3[key][0], 'FrontDut', self.case3_step3[key][1], '前置机配置', 100,flag='不存在')
            assert self.case3_step3[key][1] not in re

        for key in self.case0_step1:
            re = fun.wait_data(self.case0_step1[key][0],'BackDut',self.case0_step1[key][1],'后置机配置',100,flag='不存在')
            assert self.case0_step1[key][1] not in re



    # @pytest.mark.skip(reseason="skip")
    @allure.feature('验证应用动作为拒绝，默认动作、规则动作为允许时的定制应用通行策略')
    def test_customapp_app_action_deny(self):

        # 下发配置
        fun.send(rbmExc, message.add_app_action_deny_front['AddCustomAppPolicy'], FrontDomain, base_path)
        fun.send(rbmExc, message.add_app_action_deny_back['AddCustomAppPolicy'], BackDomain, base_path)
        fun.wait_data('ps -ef |grep nginx', 'FrontDut', 'nginx: worker process')
        front_res1 = fun.nginx_worker('ps -ef |grep nginx', 'FrontDut', 'nginx: worker process',name='前置机nginx进程')
        assert front_res1 == 1
        fun.wait_data('ps -ef |grep nginx', 'BackDut', 'nginx: worker process')
        back_res1 = fun.nginx_worker('ps -ef |grep nginx', 'BackDut', 'nginx: worker process',name='后置机nginx进程')
        assert back_res1 == 1
        fun.send(rbmExc, message.set_app_default_action_allow['SetCustomAppAction'], FrontDomain, base_path)
        fun.wait_data('ps -ef |grep nginx', 'FrontDut', 'nginx: worker process')
        front_res1 = fun.nginx_worker('ps -ef |grep nginx', 'FrontDut', 'nginx: worker process',name='前置机nginx进程')
        assert front_res1 == 1
        # 检查配置下发是否成功
        for key in self.case4_step1:
            re = fun.wait_data(self.case4_step1[key][0], 'FrontDut', self.case4_step1[key][1], '前置机配置', 100)
            assert self.case4_step1[key][1] in re

        for key in self.case4_step2:
            re = fun.wait_data(self.case4_step2[key][0], 'FrontDut', self.case4_step2[key][1], '前置机配置', 100)
            assert self.case4_step2[key][1] in re

        for key in self.case0_step1:
            re = fun.wait_data(self.case0_step1[key][0],'BackDut',self.case0_step1[key][1],'后置机配置',100)
            assert  self.case0_step1[key][1] in re

        # 发送请求，检测定制应用通信策略是否生效
        status_code = http_check.http_get(url,flag=1)
        print('url:', url)
        print('验证应用动作为拒绝，默认动作、规则动作为允许时的定制应用通行策略，get请求的请求内容为：{}'.format(status_code),'，请求被禁止。')
        assert status_code == 0

        # 文件查看audit日志
        # fun.wait_data(f"grep -n {proxy_port} /usr/local/nginx/logs/audit.log |tail -1", 'FrontDut',self.case4_step3['step1'][0], '检查Default Deny', 300, flag='存在')
        fun.wait_data(f"grep -n {proxy_port} /usr/local/nginx/logs/audit.log |tail -1", 'FrontDut',self.case4_step3['step1'][0], '检查Default Deny', 300)
        for key in self.case4_step3:
            re = fun.cmd(f"grep -n {proxy_port} /usr/local/nginx/logs/audit.log |tail -1 ", 'FrontDut')
            print('re:', re)
            assert self.case4_step3[key][0] in re

        #移除策略
        fun.send(rbmExc, message.del_app_action_front['DelCustomAppPolicy'], FrontDomain, base_path)
        fun.send(rbmExc, message.del_app_action_back['DelCustomAppPolicy'], BackDomain, base_path)
        fun.wait_data('ps -ef |grep nginx', 'FrontDut', 'nginx: worker process')
        front_res1 = fun.nginx_worker('ps -ef |grep nginx', 'FrontDut', 'nginx: worker process', name='前置机nginx进程')
        assert front_res1 == 1
        fun.wait_data('ps -ef |grep nginx', 'BackDut', 'nginx: worker process')
        back_res1 = fun.nginx_worker('ps -ef |grep nginx', 'BackDut', 'nginx: worker process', name='后置机nginx进程')
        assert back_res1 == 1
        #检查配置移除是否成功
        for key in self.case4_step4:
            re = fun.wait_data(self.case4_step4[key][0], 'FrontDut', self.case4_step4[key][1], '前置机配置', 100,flag='不存在')
            assert self.case4_step4[key][1] not in re

        for key in self.case0_step1:
            re = fun.wait_data(self.case0_step1[key][0], 'BackDut', self.case0_step1[key][1], '后置机配置', 100, flag='不存在')
            assert self.case0_step1[key][1] not in re




    # @pytest.mark.skip(reseason="skip")
    @allure.feature('验证规则动作为允许，应用动作、默认动作为拒绝时的定制应用通行策略')
    def test_customapp_ruler_action_allow(self):

        # 下发配置
        fun.send(rbmExc, message.add_app_ruler_action_allow_front['AddCustomAppPolicy'], FrontDomain, base_path)
        fun.send(rbmExc, message.add_app_ruler_action_allow_back['AddCustomAppPolicy'], BackDomain, base_path)
        fun.wait_data('ps -ef |grep nginx', 'FrontDut', 'nginx: worker process')
        front_res1 = fun.nginx_worker('ps -ef |grep nginx', 'FrontDut', 'nginx: worker process',name='前置机nginx进程')
        assert front_res1 == 1
        fun.wait_data('ps -ef |grep nginx', 'BackDut', 'nginx: worker process')
        back_res1 = fun.nginx_worker('ps -ef |grep nginx', 'BackDut', 'nginx: worker process',name='后置机nginx进程')
        assert back_res1 == 1
        fun.send(rbmExc, message.set_app_default_action_deny['SetCustomAppAction'], FrontDomain, base_path)
        fun.wait_data('ps -ef |grep nginx', 'FrontDut', 'nginx: worker process')
        front_res1 = fun.nginx_worker('ps -ef |grep nginx', 'FrontDut', 'nginx: worker process',name= '前置机nginx进程')
        assert front_res1 == 1
        # 检查配置下发是否成功
        for key in self.case6_step1:
            re = fun.wait_data(self.case6_step1[key][0], 'FrontDut', self.case6_step1[key][1], '前置机配置', 100)
            assert self.case6_step1[key][1] in re

        for key in self.case6_step2:
            re = fun.wait_data(self.case6_step2[key][0], 'FrontDut', self.case6_step2[key][1], '前置机配置', 100)
            assert self.case6_step2[key][1] in re

        for key in self.case0_step1:
            re = fun.wait_data(self.case0_step1[key][0], 'BackDut', self.case0_step1[key][1], '后置机配置', 100)
            assert self.case0_step1[key][1] in re

        # 发送请求，检测定制应用通信策略是否生效
        status_code = http_check.http_get(url,flag=1)
        print('url:', url)
        print('验证规则动作为允许，应用动作、默认动作为拒绝时的定制应用通行策略，get请求的请求内容为：{}'.format(status_code))
        assert status_code == 200

        #移除策略
        fun.send(rbmExc, message.del_app_end_deny_front['DelCustomAppPolicy'], FrontDomain, base_path)
        fun.send(rbmExc, message.del_app_end_deny_back['DelCustomAppPolicy'], BackDomain, base_path)
        fun.wait_data('ps -ef |grep nginx', 'FrontDut', 'nginx: worker process')
        front_res1 = fun.nginx_worker('ps -ef |grep nginx', 'FrontDut', 'nginx: worker process', name='前置机nginx进程')
        assert front_res1 == 1
        fun.wait_data('ps -ef |grep nginx', 'BackDut', 'nginx: worker process')
        back_res1 = fun.nginx_worker('ps -ef |grep nginx', 'BackDut', 'nginx: worker process', name='后置机nginx进程')
        assert back_res1 == 1
        # 检查配置移除是否成功
        for key in self.case6_step3:
            re = fun.wait_data(self.case6_step3[key][0], 'FrontDut', self.case6_step3[key][1], '前置机配置', 100,flag='不存在')
            assert self.case6_step3[key][1] not in re

        for key in self.case0_step1:
            re = fun.wait_data(self.case0_step1[key][0], 'BackDut', self.case0_step1[key][1], '后置机配置', 100, flag='不存在')
            assert self.case0_step1[key][1] not in re



    # @pytest.mark.skip(reseason="skip")
    @allure.feature('验证规则动作为拒绝，默认动作、应用动作为允许时的定制应用通行策略')
    def test_customapp_ruler_action_deny(self):

        # 下发配置
        fun.send(rbmExc, message.add_app_ruler_action_deny_front['AddCustomAppPolicy'], FrontDomain, base_path)
        fun.send(rbmExc, message.add_app_ruler_action_deny_back['AddCustomAppPolicy'], BackDomain, base_path)
        fun.wait_data('ps -ef |grep nginx', 'FrontDut', 'nginx: worker process')
        front_res1 = fun.nginx_worker('ps -ef |grep nginx', 'FrontDut', 'nginx: worker process',name= '前置机nginx进程')
        assert front_res1 == 1
        fun.wait_data('ps -ef |grep nginx', 'BackDut', 'nginx: worker process')
        back_res1 = fun.nginx_worker('ps -ef |grep nginx', 'BackDut', 'nginx: worker process', name='后置机nginx进程')
        assert back_res1 == 1
        fun.send(rbmExc, message.set_app_default_action_allow['SetCustomAppAction'], FrontDomain, base_path)
        fun.wait_data('ps -ef |grep nginx', 'FrontDut', 'nginx: worker process')
        front_res1 = fun.nginx_worker('ps -ef |grep nginx', 'FrontDut', 'nginx: worker process', name='前置机nginx进程')
        assert front_res1 == 1
        # 检查配置下发是否成功
        for key in self.case7_step1:
            re = fun.wait_data(self.case7_step1[key][0], 'FrontDut', self.case7_step1[key][1], '前置机配置', 100)
            assert self.case7_step1[key][1] in re

        for key in self.case7_step2:
            re = fun.wait_data(self.case7_step2[key][0], 'FrontDut', self.case7_step2[key][1], '前置机配置', 100)
            assert self.case7_step2[key][1] in re

        for key in self.case0_step1:
            re = fun.wait_data(self.case0_step1[key][0], 'BackDut', self.case0_step1[key][1], '后置机配置', 100)
            assert self.case0_step1[key][1] in re

        # 发送请求，检测定制应用通信策略是否生效
        status_code = http_check.http_get(url,flag=1)
        print('url:', url)
        print('验证规则动作为拒绝，默认动作、应用动作为允许时的定制应用通行策略，get请求的请求内容为：{}'.format(status_code),'，请求被禁止。')
        assert status_code == 0

        # 文件查看audit日志
        fun.wait_data(f"grep -n {proxy_port} /usr/local/nginx/logs/audit.log |tail -1", 'FrontDut',self.case7_step3['step1'][0], '检查cmdword get', 300, flag='存在')
        for key in self.case7_step3:
            re = fun.cmd(f"grep -n {proxy_port} /usr/local/nginx/logs/audit.log |tail -1 ", 'FrontDut')
            print('re:', re)
            assert self.case7_step3[key][0] in re

        #移除策略
        fun.send(rbmExc, message.del_app_upstream_front['DelCustomAppPolicy'], FrontDomain, base_path)
        fun.send(rbmExc, message.del_app_upstream_back['DelCustomAppPolicy'], BackDomain, base_path)
        fun.wait_data('ps -ef |grep nginx', 'FrontDut', 'nginx: worker process')
        front_res1 = fun.nginx_worker('ps -ef |grep nginx', 'FrontDut', 'nginx: worker process', name='前置机nginx进程')
        assert front_res1 == 1
        fun.wait_data('ps -ef |grep nginx', 'BackDut', 'nginx: worker process')
        back_res1 = fun.nginx_worker('ps -ef |grep nginx', 'BackDut', 'nginx: worker process', name='后置机nginx进程')
        assert back_res1 == 1
        # 检查配置移除是否成功
        for key in self.case7_step4:
            re = fun.wait_data(self.case7_step4[key][0], 'FrontDut', self.case7_step4[key][1], '前置机配置', 100,flag='不存在')
            assert self.case7_step4[key][1] not in re

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
