'''
脚本一：
用例名称：验证隔离下基于GET方法的网页访问策略的过滤
编写人员：李皖秋
编写日期：2021.7.6
测试目的：验证隔离下基于GET方法的网页访问策略的过滤
测试步骤：
1、下发http的隔离策略：代理ip为前置机安全卡的ip，port为2287，等待nginx的24个进程起来
2、下发http的get黑名单，参数为：123，等待nginx的24个进程起来
3、控制台发送get请求，不包含请求内容
4、控制台发送get请求，请求内容不包含黑名单
5、控制台发送get请求，请求内容包含黑名单
6、移除http的隔离策略，清空环境，等待nginx的24个进程起来
7、移除网页访问策略，等待nginx的24个进程起来
预期结果：
1、cat /etc/jsac/http.stream应该包含代理ip和port，且netstat -anp |grep tcp应该可以查看到监听ip和端口
2、cat /etc/jsac/http.json文件应该包含：c_get_args和get黑名单参数：123
3、请求成功，请求到的内容为server的index.html文件内包含的内容
4、请求成功，请求到的内容为server的index.html文件内包含的内容
5、请求失败，状态码返回为403
6、cat /etc/jsac/http.stream应该不包含代理ip和port
7、cat /etc/jsac/http.json文件应该不包含：http协议

脚本二：
用例名称：验证隔离下基于GET方法的多个网页访问策略的过滤
编写人员：李皖秋
编写日期：2021.7.7
测试目的：验证隔离下基于GET方法的多个网页访问策略的过滤
测试步骤：
1、下发http的隔离代理：代理ip为前置机安全卡的ip，port为2287，等待nginx的24个进程起来
2、下发多个http的get黑名单，参数1为：test，参数2为juson，等待nginx的24个进程起来
3、控制台发送get请求，不包含请求内容
4、控制台发送get请求，请求内容不包含黑名单
5、控制台发送get请求，请求内容包含黑名单test
6、控制台发送get请求，请求内容包含黑名单juson
7、移除http的隔离策略，清空环境，等待nginx的24个进程起来
8、移除网页访问策略，等待nginx的24个进程起来
预期结果：
1、cat /etc/jsac/http.stream应该包含代理ip和port，且netstat -anp |grep tcp应该可以查看到监听ip和端口
2、cat /etc/jsac/http.json文件应该包含：c_get_args和get黑名单参数：test和juson
3、请求成功，请求到的内容为server的index.html文件内包含的内容
4、请求成功，请求到的内容为server的index.html文件内包含的内容
5、请求失败，状态码返回为403
6、请求失败，状态码返回为403
7、cat /etc/jsac/http.stream应该不包含代理ip和port
8、cat /etc/jsac/http.json文件应该不包含：http协议
'''

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
    from iso_http_check_get import index
    from iso_http_check_get import message
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
# dir_dir_path=os.path.abspath(os.path.join(os.getcwd()))
# sys.path.append(os.getcwd())

# del sys.path[0]
# del sys.path[0]
from common import baseinfo
from common import clr_env
from common.rabbitmq import *
from data_check import http_check

datatime = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(time.time()))

FrontDomain = baseinfo.BG8010FrontDomain
BackDomain = baseinfo.BG8010BackDomain
proxy_ip = baseinfo.BG8010FrontOpeIp
rbmExc = baseinfo.rbmExc
http_url = index.http_url
http_content = baseinfo.http_content


class Test_iso_http_check_get():

    def setup_class(self):
        # 获取参数
        fun.ssh_FrontDut.connect()
        fun.ssh_BackDut.connect()
        self.case1_step1 = index.case1_step1
        self.case1_step11 = index.case1_step11
        self.case1_step2 = index.case1_step2
        self.case2_step2 = index.case2_step2
        self.delcheck = index.delcheck
        self.data = index.data
        self.case1_data = index.case1_data
        self.case2_data1 = index.case2_data1
        self.case2_data2 = index.case2_data2

        clr_env.iso_setup_class(dut='FrontDut')
        clr_env.iso_setup_class(dut='BackDut')

    def setup_method(self):
        clr_env.data_check_setup_met(dut='FrontDut')
        clr_env.data_check_setup_met(dut='BackDut')

    def teardown_method(self):

        clr_env.iso_teardown_met('http', base_path)
        clr_env.clear_datacheck('http', base_path)

        clr_env.iso_setup_class(dut='FrontDut')
        clr_env.iso_setup_class(dut='BackDut')

    # @pytest.mark.skip(reseason="skip")
    @allure.feature('验证基于GET方法的网页访问策略的过滤')
    def test_iso_http_check_get_a1(self):

        # 下发配置
        print('1、下发http的隔离代理：代理ip为前置机安全卡的ip，port为2287，等待nginx的24个进程起来;预期netstat -anp |grep tcp应该可以查看到监听ip和端口')
        fun.send(rbmExc, message.addhttp_front['AddCustomAppPolicy'], FrontDomain, base_path)
        fun.send(rbmExc, message.addhttp_back['AddCustomAppPolicy'], BackDomain, base_path)
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

        for key in self.case1_step11:
            re = fun.wait_data(self.case1_step11[key][0], 'FrontDut', self.case1_step11[key][1], '配置', 100)
            print(re)
            assert self.case1_step11[key][1] in re

        # 数据检查
        print('2、下发http的get黑名单，参数为：123，等待nginx的24个进程起来;预期cat /etc/jsac/http.json文件应该包含：c_get_args和get黑名单参数：123')
        fun.send(rbmExc, message.httpcheck1['SetHttpCheck'], FrontDomain, base_path)
        fun.wait_data('ps -ef |grep nginx', 'FrontDut', 'nginx: worker process')
        add_res2 = fun.nginx_worker('ps -ef |grep nginx', 'FrontDut', 'nginx: worker process')
        assert add_res2 == 1
        for key in self.case1_step2:
            re = fun.wait_data(self.case1_step2[key][0], 'FrontDut', self.case1_step2[key][1], '配置', 100)
            assert self.case1_step2[key][1] in re

        # 发送get请求，不包含黑名单内容的普通请求
        print('3、控制台发送get请求，不包含请求内容;请求成功，请求到的内容为server的index.html文件内包含的内容')
        content = http_check.http_get(http_url)
        print('get普通请求的请求内容为：{}'.format(content))
        assert content == http_content

        # 发送get请求，请求内容不包含黑名单内容
        print('4、控制台发送get请求，请求内容不包含黑名单;请求成功，请求到的内容为server的index.html文件内包含的内容')
        content = http_check.http_get(http_url, self.data)
        print('get请求内容不包含黑名单的请求应返回的内容为：{}'.format(content))
        assert content == http_content

        # 发送get请求，请求内容包含黑名单
        print('5、控制台发送get请求，请求内容包含黑名单;请求失败，状态码返回为403')
        status_code = http_check.http_get(http_url, self.case1_data)
        print('get请求内容包含黑名单返回的状态码为：{}'.format(status_code))
        assert status_code == 403

        # 移除策略，还原环境
        print('6、移除代理策略，清空环境，等待nginx的24个进程起来;netstat -anp |grep tcp应该查看不到监听ip和端口')
        fun.send(rbmExc, message.delhttp_front['DelCustomAppPolicy'], FrontDomain, base_path)
        fun.send(rbmExc, message.delhttp_back['DelCustomAppPolicy'], BackDomain, base_path)
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

        # 检查网页访问策略是否清空
        print('7、移除网页访问策略，等待nginx的24个进程起来;cat /etc/jsac/http.json文件应该不包含：http协议')
        fun.send(rbmExc, message.delhttpcheck['DropHttpCheck'], FrontDomain, base_path)
        fun.wait_data('ps -ef |grep nginx', 'FrontDut', 'nginx: worker process')
        del_res2 = fun.nginx_worker('ps -ef |grep nginx', 'FrontDut', 'nginx: worker process')
        assert del_res2 == 1
        for key in self.delcheck:
            re = fun.wait_data(self.delcheck[key][0], 'FrontDut', self.delcheck[key][1], '配置', 100, flag='不存在')
            assert self.delcheck[key][1] not in re

    # @pytest.mark.skip(reseason="skip")
    @allure.feature('验证基于GET方法的多个网页访问策略的过滤')
    def test_iso_http_check_get_a2(self):

        # 下发配置
        print('1、下发http的隔离代理：代理ip为前置机安全卡的ip，port为2287，等待nginx的24个进程起来;预期netstat -anp |grep tcp应该可以查看到监听ip和端口')
        fun.send(rbmExc, message.addhttp_front['AddCustomAppPolicy'], FrontDomain, base_path)
        fun.send(rbmExc, message.addhttp_back['AddCustomAppPolicy'], BackDomain, base_path)
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

        for key in self.case1_step11:
            re = fun.wait_data(self.case1_step11[key][0], 'FrontDut', self.case1_step11[key][1], '配置', 100)
            print(re)
            assert self.case1_step11[key][1] in re

        # 数据检查
        print('2、下发多个http的get黑名单，参数1为：test，参数2为juson，等待nginx的24个进程起来;cat /etc/jsac/http.json文件应该包含：c_get_args和get黑名单参数：test和juson')
        fun.send(rbmExc, message.httpcheck2['SetHttpCheck'], FrontDomain, base_path)
        fun.wait_data('ps -ef |grep nginx', 'FrontDut', 'nginx: worker process')
        add_res2 = fun.nginx_worker('ps -ef |grep nginx', 'FrontDut', 'nginx: worker process')
        assert add_res2 == 1
        for key in self.case2_step2:
            re = fun.wait_data(self.case2_step2[key][0], 'FrontDut', self.case2_step2[key][1], '配置', 100)
            print(re)
            assert self.case2_step2[key][1] in re

        # 发送get请求，不包含黑名单内容的普通请求
        print('3、控制台发送get请求，不包含请求内容;请求成功，请求到的内容为server的index.html文件内包含的内容')
        content = http_check.http_get(http_url)
        print('多个黑名单时get普通请求的请求内容为：{}'.format(content))
        assert content == http_content

        # 发送get请求，请求内容不包含黑名单内容
        print('4、控制台发送get请求，请求内容不包含黑名单;请求成功，请求到的内容为server的index.html文件内包含的内容')
        content = http_check.http_get(http_url, self.data)
        print('多个黑名单时get请求内容不包含黑名单的请求应返回的内容为：{}'.format(content))
        assert content == http_content

        # 发送get请求，请求内容包含第一个黑名单
        print('5、控制台发送get请求，请求内容包含黑名单test;请求失败，状态码返回为403')
        status_code = http_check.http_get(http_url, self.case2_data1)
        print('多个黑名单时get请求内容包含第一个黑名单返回的状态码为：{}'.format(status_code))
        assert status_code == 403

        # 发送get请求，请求内容包含第二个黑名单
        print('6、控制台发送get请求，请求内容包含黑名单juson;请求失败，状态码返回为403')
        status_code = http_check.http_get(http_url, self.case2_data2)
        print('多个黑名单时get请求内容包含第二个黑名单返回的状态码为：{}'.format(status_code))
        assert status_code == 403

        # 移除策略，还原环境
        print('7、移除代理策略，清空环境，等待nginx的24个进程起来;netstat -anp |grep tcp应该查看不到监听ip和端口')
        fun.send(rbmExc, message.delhttp_front['DelCustomAppPolicy'], FrontDomain, base_path)
        fun.send(rbmExc, message.delhttp_back['DelCustomAppPolicy'], BackDomain, base_path)
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

        # 检查网页访问策略是否清空
        print('8、移除网页访问策略，等待nginx的24个进程起来;cat /etc/jsac/http.json文件应该不包含：http协议')
        fun.send(rbmExc, message.delhttpcheck['DropHttpCheck'], FrontDomain, base_path)
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
