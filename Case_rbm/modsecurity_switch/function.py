'''
脚本一：
用例名称：验证防护开关的开启与关闭
编写人员：马丹丹
编写日期：2021/7/22
测试目的：验证防护开关的开启与关闭
测试步骤：
1.下发http透明代理，ps -ef |grep nginx等待nginx的24个进程起来
2.开启防护开关
3.关闭防护开关
4.移除http透明代理，ps -ef |grep nginx等待nginx的24个进程起来
预期结果：
1.使用命令cat /usr/local/nginx/conf/nginx.conf在网关设备查询代理，查询到“server 目的ip:2221”说明代理下发成功
2.使用命令cat /usr/local/nginx/conf/nginx.conf在网关设备查询代理，查询到modsecurity on说明开关开启成功
3.使用命令cat /usr/local/nginx/conf/nginx.conf在网关设备查询代理，查询到modsecurity off说明开关开启成功
4.使用命令cat /usr/local/nginx/conf/nginx.conf在网关设备查询代理，查询不到“server 目的ip:2221”说明代理移除成功

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
	from modsecurity_switch import index
	from modsecurity_switch import message
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

domain_rmb=baseinfo.rbmDomain
rbmExc = baseinfo.rbmExc

class Test_modsecurity_switch():

    def setup_method(self):
        clr_env.data_check_setup_met(dut='gw')

    def teardown_method(self):

        fun.send(rbmExc, message.modsecurity_DelAgent['DelAgent'], domain_rmb, base_path)


    def setup_class(self):
        # 获取参数
        fun.ssh_gw.connect()
        # fun.ssh_c.connect()
        self.case1_step1 = index.case1_step1
        self.case1_step2 = index.case1_step2

    # @pytest.mark.skip(reseason="skip")
    @allure.feature('验证防护开关的开启与关闭')
    def test_modsecurity_switch_start_stop(self):

        # 下发http代理
        print('1.下发http透明代理，ps -ef |grep nginx等待nginx的24个进程起来，使用命令cat /usr/local/nginx/conf/nginx.conf在网关设备查询代理，查询到“server 目的ip:2221”说明代理下发成功')
        fun.send(rbmExc, message.modsecurity_AddAgent['AddAgent'], domain_rmb, base_path)
        fun.wait_data('ps -ef |grep nginx', 'gw', 'nginx: worker process')
        gw_res1 = fun.nginx_worker('ps -ef |grep nginx', 'gw', 'nginx: worker process', name='网关nginx进程')
        assert gw_res1 == 1
        # 检查配置下发是否成功
        for key in self.case1_step1:
            re1 = fun.wait_data(self.case1_step1[key][0], 'gw', self.case1_step1[key][1], '检查http透明代理下发', 100)
            assert self.case1_step1[key][1] in re1


        # 开启防护开关
        print('2.开启防护开关，使用命令cat /usr/local/nginx/conf/nginx.conf在网关设备查询代理，查询到modsecurity on说明开关开启成功')
        fun.send(rbmExc, message.modsecurity_SetAppProtectEnable_open['SetAppProtectEnable'], domain_rmb, base_path)
        # 检查配置下发是否成功
        for key in self.case1_step2:
            re1 = fun.wait_data(self.case1_step2[key][0], 'gw', self.case1_step2[key][1], '检查防护开关', 100)
            assert self.case1_step2[key][1] in re1

        # 关闭防护开关
        print('3.关闭防护开关，使用命令cat /usr/local/nginx/conf/nginx.conf在网关设备查询代理，查询到modsecurity off说明开关开启成功')
        fun.send(rbmExc, message.modsecurity_SetAppProtectEnable_close['SetAppProtectEnable'], domain_rmb,base_path)
        # 检查配置下发是否成功
        for key in self.case1_step2:
            re1 = fun.wait_data(self.case1_step2[key][0], 'gw', self.case1_step2[key][2], '检查防护开关', 100)
            assert self.case1_step2[key][2] in re1

        # 移除http代理
        print('4.移除http透明代理，ps -ef |grep nginx等待nginx的24个进程起来，使用命令cat /usr/local/nginx/conf/nginx.conf在网关设备查询代理，查询不到“server 目的ip:2221”说明代理移除成功')
        fun.send(rbmExc, message.modsecurity_DelAgent['DelAgent'], domain_rmb, base_path)
        fun.wait_data('ps -ef |grep nginx', 'gw', 'nginx: worker process')
        gw_res1 = fun.nginx_worker('ps -ef |grep nginx', 'gw', 'nginx: worker process', name='网关nginx进程')
        assert gw_res1 == 1
        # 检查配置下发是否成功
        for key in self.case1_step1:
            re1 = fun.wait_data(self.case1_step1[key][0], 'gw', self.case1_step1[key][1], '检查http透明代理移除', 100 , flag='不存在')
            assert self.case1_step1[key][1] not in re1





    def teardown_class(self):
        # 回收环境
        fun.rbm_close()
        # fun.ssh_close('c')
        # fun.ssh_close('s')
        fun.ssh_close('gw')
