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
	from iso_tcp_basic import index
	from iso_tcp_basic import message
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
from data_check import send_smtp
from data_check import recv_pop3
from data_check import con_ftp
from data_check import http_check


datatime = time.strftime('%Y-%m-%d %H:%M:%S',time.localtime(time.time()))

FrontDomain = baseinfo.BG8010FrontDomain
BackDomain = baseinfo.BG8010BackDomain
proxy_ip = baseinfo.BG8010FrontOpeIp
rbmExc = baseinfo.rbmExc
http_url = index.http_url
http_content = baseinfo.http_content
BG8010ServerPwd =baseinfo.BG8010ServerPwd
ssh_proxy_port = baseinfo.ssh_proxy_port

class Test_iso_tcp_basic():

    def setup_method(self):
        clr_env.data_check_setup_met(dut='FrontDut')
        clr_env.data_check_setup_met(dut='BackDut')

    def teardown_method(self):
        clr_env.iso_setup_class(dut='FrontDut')
        clr_env.iso_setup_class(dut='BackDut')

    def setup_class(self):
        # 获取参数
        fun.ssh_FrontDut.connect()
        fun.ssh_BackDut.connect()
        fun.ssh_BG8010Client.connect()
        fun.ssh_BG8010Server.connect()
        self.case1_step1 = index.case1_step1
        self.case1_step11 = index.case1_step11
        self.case2_step1 = index.case2_step1
        self.case2_step11 = index.case2_step11
        self.case3_step1 = index.case3_step1
        self.case3_step11 = index.case3_step11
        self.case4_step1 = index.case4_step1
        self.case4_step11 = index.case4_step11
        self.case5_step1 = index.case5_step1
        self.case5_step11 = index.case5_step11
        self.mail_sender = index.mail_sender
        self.mail_receivers = index.mail_receivers
        self.mail_cc = index.mail_cc
        self.mail_bcc = index.mail_bcc
        self.mail_host = index.mail_host
        self.mail_port = index.mail_port
        self.mail_user = index.mail_user
        self.mail_pass = index.mail_pass
        self.pop3_email = index.pop3_email
        self.pop3_pwd = baseinfo.pop3_pwd
        self.pop3_proxy_port = index.pop3_proxy_port
        self.title = index.title
        self.file = index.file
        self.attach_path = index.attach_path
        self.context = index.context
        self.ftp_proxy_port = index.ftp_proxy_port
        self.ftp_user = index.ftp_user
        self.ftp_pass = index.ftp_pass
        self.case2_downremotePath = index.case2_downremotePath
        self.case2_downlocalPath = index.case2_downlocalPath

        clr_env.iso_setup_class(dut='FrontDut')
        clr_env.iso_setup_class(dut='BackDut')

    # @pytest.mark.skip(reseason="skip")
    @allure.feature('验证隔离下的邮件代理策略')
    def test_iso_tcp_basic_a1(self):

        # 下发配置
        fun.send(rbmExc, message.addsmtp_front['AddCustomAppPolicy'], FrontDomain, base_path)
        fun.send(rbmExc, message.addsmtp_back['AddCustomAppPolicy'], BackDomain, base_path)
        fun.wait_data('ps -ef |grep nginx', 'FrontDut', 'nginx: worker process')
        front_res1 = fun.nginx_worker('ps -ef |grep nginx', 'FrontDut', 'nginx: worker process',name='前置机nginx进程')
        assert front_res1 == 1
        fun.wait_data('ps -ef |grep nginx', 'BackDut', 'nginx: worker process')
        back_res1 = fun.nginx_worker('ps -ef |grep nginx', 'BackDut', 'nginx: worker process', name='后置机nginx进程')
        assert back_res1 == 1
        fun.send(rbmExc, message.addpop3_front['AddCustomAppPolicy'], FrontDomain, base_path)
        fun.send(rbmExc, message.addpop3_back['AddCustomAppPolicy'], BackDomain, base_path)
        fun.wait_data('ps -ef |grep nginx', 'FrontDut', 'nginx: worker process')
        front_res2 = fun.nginx_worker('ps -ef |grep nginx', 'FrontDut', 'nginx: worker process', name='前置机nginx进程')
        assert front_res2 == 1
        fun.wait_data('ps -ef |grep nginx', 'BackDut', 'nginx: worker process')
        back_res2 = fun.nginx_worker('ps -ef |grep nginx', 'BackDut', 'nginx: worker process', name='后置机nginx进程')
        assert back_res2 == 1
        # 检查配置下发是否成功
        for key in self.case1_step1:
            re = fun.wait_data(self.case1_step1[key][0], 'FrontDut', self.case1_step1[key][1], '配置', 100)
            print(re)
            assert self.case1_step1[key][1] in re

        for key in self.case1_step11:
            re = fun.wait_data(self.case1_step11[key][0], 'FrontDut', self.case1_step11[key][1], '配置', 100)
            print(re)
            assert self.case1_step11[key][1] in re

        # 发送邮件，检测隔离代理是否生效
        result = send_smtp.post_email(self.mail_sender, self.mail_receivers, self.mail_cc, self.mail_bcc,
                                       self.mail_host, self.mail_port, self.mail_user, self.mail_pass,
                                       self.attach_path, self.file, self.title, self.context, 0, 0)
        print('隔离下的邮件代理结果为:{}'.format(result))
        assert result == 1

        # 接收邮件
        msg = recv_pop3.get_email(self.pop3_email, self.pop3_pwd, proxy_ip, self.pop3_proxy_port)
        print('pop3获取邮件返回的内容是：'.format(msg))
        mail_list = recv_pop3.print_info(msg)  # 解析
        print('接收邮件解析到的列表为{}'.format(mail_list))
        assert self.title, self.context in mail_list

        # 移除策略，清空环境
        fun.send(rbmExc, message.delsmtp_front['DelCustomAppPolicy'], FrontDomain, base_path)
        fun.send(rbmExc, message.delsmtp_back['DelCustomAppPolicy'], BackDomain, base_path)
        fun.wait_data('ps -ef |grep nginx', 'FrontDut', 'nginx: worker process')
        fdel_res1 = fun.nginx_worker('ps -ef |grep nginx', 'FrontDut', 'nginx: worker process',name='前置机nginx进程')
        assert fdel_res1 == 1
        fun.wait_data('ps -ef |grep nginx', 'BackDut', 'nginx: worker process')
        bdel_res1 = fun.nginx_worker('ps -ef |grep nginx', 'BackDut', 'nginx: worker process',name='后置机nginx进程')
        assert bdel_res1 == 1
        fun.send(rbmExc, message.delpop3_front['DelCustomAppPolicy'], FrontDomain, base_path)
        fun.send(rbmExc, message.delpop3_back['DelCustomAppPolicy'], BackDomain, base_path)
        fun.wait_data('ps -ef |grep nginx', 'FrontDut', 'nginx: worker process')
        fdel_res2 = fun.nginx_worker('ps -ef |grep nginx', 'FrontDut', 'nginx: worker process',name='前置机nginx进程')
        assert fdel_res2 == 1
        fun.wait_data('ps -ef |grep nginx', 'BackDut', 'nginx: worker process')
        bdel_res2 = fun.nginx_worker('ps -ef |grep nginx', 'BackDut', 'nginx: worker process',name='后置机nginx进程')
        assert bdel_res2 == 1
        # 检查策略移除是否成功
        for key in self.case1_step1:
            re = fun.wait_data(self.case1_step1[key][0], 'FrontDut', self.case1_step1[key][1], '配置', 100,flag='不存在')
            print(re)
            assert self.case1_step1[key][1] not in re


    # @pytest.mark.skip(reseason="skip")
    @allure.feature('验证隔离下的ftp传输策略')
    def test_iso_tcp_basic_a2(self):

        # 下发配置
        fun.send(rbmExc, message.addftp_front['AddCustomAppPolicy'], FrontDomain, base_path)
        fun.send(rbmExc, message.addftp_back['AddCustomAppPolicy'], BackDomain, base_path)
        fun.wait_data('ps -ef |grep nginx', 'FrontDut', 'nginx: worker process')
        front_res = fun.nginx_worker('ps -ef |grep nginx', 'FrontDut', 'nginx: worker process',name='前置机nginx进程')
        assert front_res == 1
        fun.wait_data('ps -ef |grep nginx', 'BackDut', 'nginx: worker process')
        back_res = fun.nginx_worker('ps -ef |grep nginx', 'BackDut', 'nginx: worker process',name='后置机nginx进程')
        assert back_res == 1
        # 检查配置下发是否成功
        for key in self.case2_step1:
            re = fun.wait_data(self.case2_step1[key][0], 'FrontDut', self.case2_step1[key][1], '配置', 100)
            print(re)
            assert self.case2_step1[key][1] in re

        for key in self.case2_step11:
            re = fun.wait_data(self.case2_step11[key][0], 'FrontDut', self.case2_step11[key][1], '配置', 100)
            print(re)
            assert self.case2_step11[key][1] in re


        # 登录ftp服务器，下载文件
        fp = con_ftp.connect_ftp(proxy_ip, self.ftp_proxy_port, self.ftp_user, self.ftp_pass)
        print('欢迎语是：{}'.format(fp.getwelcome()))
        result = con_ftp.downFile(fp, self.case2_downremotePath, self.case2_downlocalPath)
        print('隔离下的ftp传输策略结果为:{}'.format(result))
        assert result == 1

        # 移除策略，清空环境
        fun.send(rbmExc, message.delftp_front['DelCustomAppPolicy'], FrontDomain, base_path)
        fun.send(rbmExc, message.delftp_back['DelCustomAppPolicy'], BackDomain, base_path)
        fun.wait_data('ps -ef |grep nginx', 'FrontDut', 'nginx: worker process')
        fdel_res = fun.nginx_worker('ps -ef |grep nginx', 'FrontDut', 'nginx: worker process',name='前置机nginx进程')
        assert fdel_res == 1
        fun.wait_data('ps -ef |grep nginx', 'BackDut', 'nginx: worker process')
        bdel_res = fun.nginx_worker('ps -ef |grep nginx', 'BackDut', 'nginx: worker process',name='后置机nginx进程')
        assert bdel_res == 1
        # 检查策略移除是否成功
        for key in self.case2_step1:
            re = fun.wait_data(self.case2_step1[key][0], 'FrontDut', self.case2_step1[key][1], '配置', 100, flag='不存在')
            print(re)
            assert self.case2_step1[key][1] not in re

    # @pytest.mark.skip(reseason="skip")
    @allure.feature('验证隔离下的tcp策略（http）')
    def test_iso_tcp_basic_a3(self):

        # 下发配置
        fun.send(rbmExc, message.addtcp_front['AddCustomAppPolicy'], FrontDomain, base_path)
        fun.send(rbmExc, message.addtcp_back['AddCustomAppPolicy'], BackDomain, base_path)
        fun.wait_data('ps -ef |grep nginx', 'FrontDut', 'nginx: worker process')
        front_res = fun.nginx_worker('ps -ef |grep nginx', 'FrontDut', 'nginx: worker process',name='前置机nginx进程')
        assert front_res == 1
        fun.wait_data('ps -ef |grep nginx', 'BackDut', 'nginx: worker process')
        back_res = fun.nginx_worker('ps -ef |grep nginx', 'BackDut', 'nginx: worker process',name='后置机nginx进程')
        assert back_res == 1
        # 检查配置下发是否成功
        for key in self.case3_step1:
            re = fun.wait_data(self.case3_step1[key][0], 'FrontDut', self.case3_step1[key][1], '配置', 100)
            print(re)
            assert self.case3_step1[key][1] in re

        for key in self.case3_step11:
            re = fun.wait_data(self.case3_step11[key][0], 'FrontDut', self.case3_step11[key][1], '配置', 100)
            print(re)
            assert self.case3_step11[key][1] in re

        # 发送get请求，验证隔离下的tcp策略（http）
        print('请求地址为{}'.format(http_url))
        content = http_check.http_get(http_url)
        print('验证隔离下的tcp策略（http）请求内容为：{}'.format(content))
        assert content == http_content

        # 移除策略，清空环境
        fun.send(rbmExc, message.deltcp_front['DelCustomAppPolicy'], FrontDomain, base_path)
        fun.send(rbmExc, message.deltcp_back['DelCustomAppPolicy'], BackDomain, base_path)
        fun.wait_data('ps -ef |grep nginx', 'FrontDut', 'nginx: worker process')
        fdel_res = fun.nginx_worker('ps -ef |grep nginx', 'FrontDut', 'nginx: worker process',name='前置机nginx进程')
        assert fdel_res == 1
        fun.wait_data('ps -ef |grep nginx', 'BackDut', 'nginx: worker process')
        bdel_res = fun.nginx_worker('ps -ef |grep nginx', 'BackDut', 'nginx: worker process',name='后置机nginx进程')
        assert bdel_res == 1
        # 检查策略移除是否成功
        for key in self.case3_step1:
            re = fun.wait_data(self.case3_step1[key][0], 'FrontDut', self.case3_step1[key][1], '配置', 100, flag='不存在')
            print(re)
            assert self.case3_step1[key][1] not in re

    # @pytest.mark.skip(reseason="skip")
    @allure.feature('验证隔离下的tcp策略（ssh、scp）下载文件')
    def test_iso_tcp_basic_a4(self):

        # 下发配置
        fun.send(rbmExc, message.addtcp_ssh_front['AddCustomAppPolicy'], FrontDomain, base_path)
        fun.send(rbmExc, message.addtcp_ssh_back['AddCustomAppPolicy'], BackDomain, base_path)
        fun.wait_data('ps -ef |grep nginx', 'FrontDut', 'nginx: worker process')
        front_res = fun.nginx_worker('ps -ef |grep nginx', 'FrontDut', 'nginx: worker process',name='前置机nginx进程')
        assert front_res == 1
        fun.wait_data('ps -ef |grep nginx', 'BackDut', 'nginx: worker process')
        back_res = fun.nginx_worker('ps -ef |grep nginx', 'BackDut', 'nginx: worker process',name='后置机nginx进程')
        assert back_res == 1
        # 检查配置下发是否成功
        for key in self.case4_step1:
            re = fun.wait_data(self.case4_step1[key][0], 'FrontDut', self.case4_step1[key][1], '配置', 100)
            print('re是{},self.case4_step1[key][1]是{}'.format(re,self.case4_step1[key][1]))
            assert self.case4_step1[key][1] in re

        for key in self.case4_step11:
            re = fun.wait_data(self.case4_step11[key][0], 'FrontDut', self.case4_step11[key][1], '配置', 100)
            print(re)
            assert self.case4_step11[key][1] in re

        #在server的/opt/pkt/路径下创建一个10M大小的文件10M.txt
        touch_file_cmd = ['cd /opt/pkt','dd if=/dev/zero of=10M.txt bs=1M count=10']
        fun.cmd(touch_file_cmd,'BG8010Server',list_flag=True)

        #检查服务端文件是否创建成功
        touch_file = fun.search('/opt/pkt', 'txt', 'BG8010Server')
        print('检查服务端/opt/pkt/目录下所有以txt结尾的文件列表为：{}'.format(touch_file))
        assert '10M.txt' in touch_file

        # 验证隔离下的tcp策略（ssh、scp）从客户端发送scp命令下载
        scp_cmd = f'sshpass -p {BG8010ServerPwd} scp -P {ssh_proxy_port} root@{proxy_ip}:/opt/pkt/10M.txt /opt/pkt/'
        print('scp下载的命令为：{}'.format(scp_cmd))
        fun.cmd(scp_cmd, 'BG8010Client')

        #检查文件是否下载成功到客户端
        touch_file = fun.search('/opt/pkt', 'txt', 'BG8010Client')
        print('检查客户端/opt/pkt/目录下所有以txt结尾的文件列表为：{}'.format(touch_file))
        assert '10M.txt' in touch_file

        #下载完成后，还原环境，清掉客户端下载的文件
        fun.cmd('rm -f /opt/pkt/10M.txt ', 'BG8010Client')
        check_file = fun.search('/opt/pkt', 'txt', 'BG8010Client')
        print('还原环境，10M.txt文件应该不在列表内，列表为{}'.format(check_file))

        # 移除策略，清空环境
        fun.send(rbmExc, message.deltcp_ssh_front['DelCustomAppPolicy'], FrontDomain, base_path)
        fun.send(rbmExc, message.deltcp_ssh_back['DelCustomAppPolicy'], BackDomain, base_path)
        fun.wait_data('ps -ef |grep nginx', 'FrontDut', 'nginx: worker process')
        fdel_res = fun.nginx_worker('ps -ef |grep nginx', 'FrontDut', 'nginx: worker process',name='前置机nginx进程')
        assert fdel_res == 1
        fun.wait_data('ps -ef |grep nginx', 'BackDut', 'nginx: worker process')
        bdel_res = fun.nginx_worker('ps -ef |grep nginx', 'BackDut', 'nginx: worker process',name='后置机nginx进程')
        assert bdel_res == 1
        # 检查策略移除是否成功
        for key in self.case4_step1:
            re = fun.wait_data(self.case4_step1[key][0], 'FrontDut', self.case4_step1[key][1], '配置', 100, flag='不存在')
            print(re)
            assert self.case4_step1[key][1] not in re

    # @pytest.mark.skip(reseason="skip")
    @allure.feature('验证隔离下的tcp策略（ssh、scp）上传文件')
    def test_iso_tcp_basic_a5(self):

        # 下发配置
        fun.send(rbmExc, message.addtcp_ssh_front['AddCustomAppPolicy'], FrontDomain, base_path)
        fun.send(rbmExc, message.addtcp_ssh_back['AddCustomAppPolicy'], BackDomain, base_path)
        fun.wait_data('ps -ef |grep nginx', 'FrontDut', 'nginx: worker process')
        front_res = fun.nginx_worker('ps -ef |grep nginx', 'FrontDut', 'nginx: worker process',name='前置机nginx进程')
        assert front_res == 1
        fun.wait_data('ps -ef |grep nginx', 'BackDut', 'nginx: worker process')
        back_res = fun.nginx_worker('ps -ef |grep nginx', 'BackDut', 'nginx: worker process', name='后置机nginx进程')
        assert back_res == 1
        # 检查配置下发是否成功
        for key in self.case5_step1:
            re = fun.wait_data(self.case5_step1[key][0], 'FrontDut', self.case5_step1[key][1], '配置', 100)
            print(re)
            assert self.case5_step1[key][1] in re

        for key in self.case5_step11:
            re = fun.wait_data(self.case5_step11[key][0], 'FrontDut', self.case5_step11[key][1], '配置', 100)
            print(re)
            assert self.case5_step11[key][1] in re

        # 在客户端的/opt/pkt/路径下创建一个10M大小的文件10M.pdf
        touch_file_cmd = ['cd /opt/pkt', 'dd if=/dev/zero of=10M.pdf bs=1M count=10']
        fun.cmd(touch_file_cmd, 'BG8010Client', list_flag=True)

        # 检查客户端文件是否创建成功
        touch_file = fun.search('/opt/pkt', 'pdf', 'BG8010Client')
        print('检查服务端/opt/pkt/目录下所有以pdf结尾的文件列表为：{}'.format(touch_file))
        assert '10M.pdf' in touch_file

        # 验证隔离下的tcp策略（ssh、scp）从客户端发送scp命令上传
        scp_cmd = f'sshpass -p {BG8010ServerPwd} scp -P {ssh_proxy_port} /opt/pkt/10M.pdf root@{proxy_ip}:/opt/pkt/'
        print('scp上传的命令为：{}'.format(scp_cmd))
        fun.cmd(scp_cmd, 'BG8010Client')

        # 检查文件是否上传成功到服务端
        touch_file = fun.search('/opt/pkt', 'pdf', 'BG8010Server')
        print('检查客户端/opt/pkt/目录下所有以pdf结尾的文件列表为：{}'.format(touch_file))
        assert '10M.pdf' in touch_file

        # 下载完成后，还原环境，清掉上传到服务端的文件
        fun.cmd('rm -f /opt/pkt/10M.pdf ', 'BG8010Server')
        check_file = fun.search('/opt/pkt', 'pdf', 'BG8010Server')
        print('还原环境，10M.pdf文件应该不在列表内，列表为{}'.format(check_file))

        # 移除策略，清空环境
        fun.send(rbmExc, message.deltcp_ssh_front['DelCustomAppPolicy'], FrontDomain, base_path)
        fun.send(rbmExc, message.deltcp_ssh_back['DelCustomAppPolicy'], BackDomain, base_path)
        fun.wait_data('ps -ef |grep nginx', 'FrontDut', 'nginx: worker process')
        fdel_res = fun.nginx_worker('ps -ef |grep nginx', 'FrontDut', 'nginx: worker process',name='前置机nginx进程')
        assert fdel_res == 1
        fun.wait_data('ps -ef |grep nginx', 'BackDut', 'nginx: worker process')
        bdel_res = fun.nginx_worker('ps -ef |grep nginx', 'BackDut', 'nginx: worker process',name='后置机nginx进程')
        assert bdel_res == 1
        # 检查策略移除是否成功
        for key in self.case5_step1:
            re = fun.wait_data(self.case5_step1[key][0], 'FrontDut', self.case5_step1[key][1], '配置', 100, flag='不存在')
            print(re)
            assert self.case5_step1[key][1] not in re


    def teardown_class(self):
        # 回收环境
        clr_env.iso_teardown_met('mail', base_path)
        clr_env.iso_teardown_met('ftp', base_path)
        clr_env.iso_teardown_met('tcp_http', base_path)
        clr_env.iso_teardown_met('ssh', base_path)
        clr_env.iso_setup_class(dut='FrontDut')
        clr_env.iso_setup_class(dut='BackDut')

        fun.rbm_close()
        fun.ssh_close('FrontDut')
        fun.ssh_close('BackDut')
