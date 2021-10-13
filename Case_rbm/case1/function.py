# encoding='utf-8'
try:
    import os, sys, pytest, allure, time, re, time
except Exception as err:
    print('导入CPython内置函数库失败!错误信息如下:')
    print(err)
    sys.exit(0)  # 避免程序继续运行造成的异常崩溃,友好退出程序

base_path = os.path.dirname(os.path.abspath(__file__))  # 获取当前项目文件夹
base_path = base_path.replace('\\', '/')
sys.path.insert(0, base_path)  # 将当前目录添加到系统环境变量,方便下面导入版本配置等文件
print(base_path)
try:
    from case1 import index
    from case1 import message
    from common import fun
    import common.ssh as c_ssh
except Exception as err:
    print(
        '导入基础函数库失败!请检查相关文件是否存在.\n文件位于: ' + str(base_path) + '/common/ 目录下.\n分别为:pcap.py  rabbitmq.py  ssh.py\n错误信息如下:')
    print(err)
    sys.exit(0)  # 避免程序继续运行造成的异常崩溃,友好退出程序
else:
    del sys.path[0]  # 及时删除导入的环境变量,避免重复导入造成的异常错误

from common import baseinfo
from common import clr_env
from common.rabbitmq import *

datatime = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(time.time()))

rbmDomain = baseinfo.rbmDomain
rbmExc = baseinfo.rbmExc
FrontDomain = baseinfo.BG8010FrontDomain
BackDomain = baseinfo.BG8010BackDomain
url = baseinfo.http_url
http_content = baseinfo.http_content


class Test_http_check_get():

    def setup_class(self):
        # 获取参数
        fun.ssh_gw.connect()
        fun.ssh_FrontDut.connect()
        fun.ssh_BackDut.connect()
        self.clr_env = clr_env
        self.case1_step1 = index.case1_step1
        self.case1_step2 = index.case1_step2
        self.data = index.data
        self.case1_data = index.case1_data

        # clr_env.clear_env()

    # def setup_method(self):
    #     clr_env.data_check_setup_met()
    #
    # def teardown_method(self):
    #     clr_env.data_check_teardown_met('http', base_path)

    @allure.feature('验证基于GET方法的网页访问策略的过滤')
    def test_case1(self):

        # 网关设备的nginx查询有问题，返回None
        # re = fun.cmd('systemctl status agentjsac', 'gw')
        # assert re != None
        # re = fun.cmd('ps -ef |grep agentjsac', 'gw')
        # assert re != None
        # re = fun.cmd('netstat -anp', 'gw')
        # assert re != None
        # re = fun.cmd('systemctl status nginx_kernel', 'gw')
        # assert re != None
        # re = fun.cmd('ps -ef |grep nginx', 'gw')
        # assert re != None

        # 隔离的前置机查询nginx没有问题
        re = fun.cmd('systemctl status agentjsac', 'FrontDut')
        assert re != None
        re = fun.cmd('ps -ef |grep agentjsac', 'FrontDut')
        assert re != None
        re = fun.cmd('netstat -anp', 'FrontDut')
        assert re != None
        re = fun.cmd('systemctl status nginx_kernel', 'FrontDut')
        assert re != None
        re = fun.cmd('ps -ef |grep nginx', 'FrontDut')
        assert re != None



    # 下发配置
    # fun.send(rbmExc, message.addhttp['AddAgent'], rbmDomain, base_path)
    # fun.wait_data('ps -ef |grep nginx', 'gw', 'nginx: worker process')
    # fun.nginx_worker('ps -ef |grep nginx', 'gw', 'nginx: worker process')
    # 检查配置下发是否成功
    # for key in self.case1_step1:
    #     re = fun.wait_data(self.case1_step1[key][0], 'gw', self.case1_step1[key][1], '配置', 100)
    #     print('添加策略_re: ', re)
    #     assert self.case1_step1[key][1] in re

    # # 数据检查
    # fun.send(rbmExc, message.httpcheck1['SetHttpCheck'], rbmDomain, base_path)
    # fun.wait_data('ps -ef |grep nginx', 'gw', 'nginx: worker process')
    # fun.nginx_worker('ps -ef |grep nginx', 'gw', 'nginx: worker process')
    # for key in self.case1_step2:
    #     re = fun.wait_data(self.case1_step2[key][0], 'gw', self.case1_step2[key][1], '配置', 100)
    #     print("需包含字符串：", self.case1_step2[key][1])
    #     print('httpCheck_re: ', re)
    #     assert self.case1_step2[key][1] in re
    #
    # # 发送get请求，不包含黑名单内容的普通请求
    # content = http_check.http_get(url)
    # print('get普通请求的请求内容为：{}'.format(content))
    # assert content == http_content
    #
    # result = fun.search('/opt', 'sh', 'gw')
    # print('---------fun.search: \n', result)

    # def teardown_class(self):
        # 回收环境
        # clr_env.clear_env()
        # fun.ssh_close('gw')
        # fun.ssh_close('FrontDut')
        # fun.ssh_close('BackDut')
