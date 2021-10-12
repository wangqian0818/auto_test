'''
脚本一：
用例名称：验证隔离下基于上传扩展名过滤的FTP传输策略
编写人员：李皖秋
编写日期：2021.7.15
测试目的：验证隔离下基于上传扩展名过滤的FTP传输策略
测试步骤：
1、下发ftp的隔离代理：代理ip为前置机安全卡的ip，port为8887，等待nginx的24个进程起来
2、下发ftp的上传扩展名白名单：txt，等待nginx的24个进程起来
3、控制台走ftp隔离登录ftp服务器，上传文件扩展名为白名单txt，查看上传是否成功
4、控制台走ftp隔离登录ftp服务器，上传文件扩展名为非白名单pdf，查看上传是否成功
5、移除ftp的隔离策略，清空环境，等待nginx的24个进程起来
6、移除ftp传输策略，等待nginx的24个进程起来
预期结果：
1、cat /etc/jsac/customapp.stream应该包含代理ip和port，netstat -anp |grep tcp应该可以查看到监听ip和端口
2、cat /etc/jsac/filter.json文件应该包含：allow-upload和上传扩展名白名单：txt
3、上传成功
4、上传失败
5、cat /etc/jsac/customapp.stream应该不包含代理ip和port
6、cat /etc/jsac/filter.json文件应该不包含：ftp协议

脚本二：
用例名称：验证隔离下基于多个上传扩展名过滤的FTP传输策略
编写人员：李皖秋
编写日期：2021.7.15
测试目的：验证隔离下基于多个上传扩展名过滤的FTP传输策略
测试步骤：
1、下发ftp的隔离代理：代理ip为前置机安全卡的ip，port为8887，等待nginx的24个进程起来
2、下发ftp的上传扩展名白名单：txt、xls，等待nginx的24个进程起来
3、控制台走ftp隔离登录ftp服务器，上传文件扩展名为白名单txt，查看上传是否成功
4、控制台走ftp隔离登录ftp服务器，上传文件扩展名为白名单xls，查看上传是否成功
5、控制台走ftp隔离登录ftp服务器，上传文件扩展名为非白名单pdf，查看上传是否成功
6、移除ftp的隔离策略，清空环境，等待nginx的24个进程起来
7、移除ftp传输策略，等待nginx的24个进程起来
预期结果：
1、cat /etc/jsac/customapp.stream应该包含代理ip和port，netstat -anp |grep tcp应该可以查看到监听ip和端口
2、cat /etc/jsac/filter.json文件应该包含：allow-upload和上传扩展名白名单：txt、xls
3、上传成功
4、上传成功
5、上传失败
6、cat /etc/jsac/customapp.stream应该不包含代理ip和port
7、cat /etc/jsac/filter.json文件应该不包含：ftp协议
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
    from iso_ftp_check_upload import index
    from iso_ftp_check_upload import message
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

from common import baseinfo
from common import clr_env
from common.rabbitmq import *
from data_check import con_ftp

datatime = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(time.time()))

FrontDomain = baseinfo.BG8010FrontDomain
BackDomain = baseinfo.BG8010BackDomain
proxy_ip = baseinfo.BG8010FrontOpeIp
rbmExc = baseinfo.rbmExc


class Test_iso_ftp_check_upload():

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
        self.case2_step2 = index.case2_step2
        self.delcheck = index.delcheck
        self.port = index.port
        self.username = index.username
        self.password = index.password
        self.case1_upremotePath = index.case1_upremotePath
        self.case1_uplocalPath = index.case1_uplocalPath
        self.case1_deny_upremotePath = index.case1_deny_upremotePath
        self.case1_deny_uplocalPath = index.case1_deny_uplocalPath
        self.case2_upremotePath = index.case2_upremotePath
        self.case2_uplocalPath = index.case2_uplocalPath
        self.case2_allow_upremotePath = index.case2_allow_upremotePath
        self.case2_allow_uplocalPath = index.case2_allow_uplocalPath
        self.case2_deny_upremotePath = index.case2_deny_upremotePath
        self.case2_deny_uplocalPath = index.case2_deny_uplocalPath


    @allure.feature('验证隔离下基于上传扩展名过滤的FTP传输策略')
    def test_iso_ftp_check_upload_a1(self):

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

        print('2、下发ftp的上传扩展名白名单：txt，等待nginx的24个进程起来；cat /etc/jsac/filter.json文件应该包含：allow-upload和上传扩展名白名单：txt')
        fun.send(rbmExc, message.ftpcheck1['SetFtpCheck'], FrontDomain, base_path)
        fun.wait_data('ps -ef |grep nginx', 'FrontDut', 'nginx: worker process')
        add_res2 = fun.nginx_worker('ps -ef |grep nginx', 'FrontDut', 'nginx: worker process')
        assert add_res2 == 1
        for key in self.case1_step2:
            re = fun.wait_data(self.case1_step2[key][0], 'FrontDut', self.case1_step2[key][1], '配置', 100)
            print(re)
            assert self.case1_step2[key][1] in re

        # 登录ftp服务器，上传文件扩展名为白名单
        print('3、控制台走ftp隔离登录ftp服务器，上传文件扩展名为白名单txt，查看上传是否成功；上传成功')
        fp = con_ftp.connect_ftp(proxy_ip, self.port, self.username, self.password)
        print('欢迎语是：{}'.format(fp.getwelcome()))
        result1 = con_ftp.uploadFile(fp, self.case1_upremotePath, self.case1_uplocalPath)
        print('ftp上传文件扩展名{}为白名单结果为:{}'.format(self.case1_uplocalPath, result1))
        assert result1 == 1

        # 登录ftp服务器，上传文件扩展名为非白名单
        print('4、控制台走ftp隔离登录ftp服务器，上传文件扩展名为非白名单pdf，查看上传是否成功；上传失败')
        fp = con_ftp.connect_ftp(proxy_ip, self.port, self.username, self.password)
        print('欢迎语是：{}'.format(fp.getwelcome()))
        result2 = con_ftp.uploadFile(fp, self.case1_deny_upremotePath, self.case1_deny_uplocalPath)
        print('ftp上传文件扩展名{}为非白名单结果为:{}'.format(self.case1_deny_uplocalPath, result2))
        assert result2 == 0

        # 移除策略，还原环境
        print('5、移除ftp的隔离策略，清空环境，等待nginx的24个进程起来；cat /etc/jsac/customapp.stream应该不包含代理ip和port')
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
        print('6、移除ftp传输策略，等待nginx的24个进程起来；cat /etc/jsac/filter.json文件应该不包含：ftp协议')
        fun.send(rbmExc, message.delftpcheck['DropFtpCheck'], FrontDomain, base_path)
        fun.wait_data('ps -ef |grep nginx', 'FrontDut', 'nginx: worker process')
        del_res2 = fun.nginx_worker('ps -ef |grep nginx', 'FrontDut', 'nginx: worker process')
        assert del_res2 == 1
        for key in self.delcheck:
            re = fun.wait_data(self.delcheck[key][0], 'FrontDut', self.delcheck[key][1], '配置', 100, flag='不存在')
            assert self.delcheck[key][1] not in re

    # @pytest.mark.skip(reseason="skip")
    @allure.feature('验证隔离下基于多个上传扩展名过滤的FTP传输策略')
    def test_iso_ftp_check_upload_a2(self):

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

        print('2、下发ftp的上传扩展名白名单：txt、xls，等待nginx的24个进程起来；cat /etc/jsac/filter.json文件应该包含：allow-upload和上传扩展名白名单：txt、xls')
        fun.send(rbmExc, message.ftpcheck2['SetFtpCheck'], FrontDomain, base_path)
        fun.wait_data('ps -ef |grep nginx', 'FrontDut', 'nginx: worker process')
        add_res2 = fun.nginx_worker('ps -ef |grep nginx', 'FrontDut', 'nginx: worker process')
        assert add_res2 == 1
        for key in self.case2_step2:
            re = fun.wait_data(self.case2_step2[key][0], 'FrontDut', self.case2_step2[key][1], '配置', 100)
            print(re)
            assert self.case2_step2[key][1] in re

        # 登录ftp服务器，上传文件扩展名为白名单
        print('3、控制台走ftp隔离登录ftp服务器，上传文件扩展名为白名单txt，查看上传是否成功；上传成功')
        fp = con_ftp.connect_ftp(proxy_ip, self.port, self.username, self.password)
        print('欢迎语是：{}'.format(fp.getwelcome()))
        result1 = con_ftp.uploadFile(fp, self.case2_upremotePath, self.case2_uplocalPath)
        print('第一个ftp上传文件扩展名{}为白名单结果为:{}'.format(self.case2_uplocalPath, result1))
        assert result1 == 1

        # 登录ftp服务器，上传文件扩展名为白名单
        print('4、控制台走ftp隔离登录ftp服务器，上传文件扩展名为白名单xls，查看上传是否成功；上传成功')
        fp = con_ftp.connect_ftp(proxy_ip, self.port, self.username, self.password)
        print('欢迎语是：{}'.format(fp.getwelcome()))
        result2 = con_ftp.uploadFile(fp, self.case2_allow_upremotePath, self.case2_allow_uplocalPath)
        print('第二个ftp上传文件扩展名{}为白名单结果为:{}'.format(self.case2_allow_uplocalPath, result2))
        assert result2 == 1

        # 登录ftp服务器，上传文件扩展名为非白名单
        print('5、控制台走ftp隔离登录ftp服务器，上传文件扩展名为非白名单pdf，查看上传是否成功；上传失败')
        fp = con_ftp.connect_ftp(proxy_ip, self.port, self.username, self.password)
        print('欢迎语是：{}'.format(fp.getwelcome()))
        result3 = con_ftp.uploadFile(fp, self.case2_deny_upremotePath, self.case2_deny_uplocalPath)
        print('ftp上传文件扩展名{}为非白名单结果为:{}'.format(self.case2_deny_uplocalPath, result3))
        assert result3 == 0

        # 移除策略，还原环境
        print('6、移除ftp的隔离策略，清空环境，等待nginx的24个进程起来；cat /etc/jsac/customapp.stream应该不包含代理ip和port')
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
        print('7、移除ftp传输策略，等待nginx的24个进程起来；cat /etc/jsac/filter.json文件应该不包含：ftp协议')
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