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
	from iso_customapp_scp import index
	from iso_customapp_scp import message
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
# from data_check import http_check


datatime = time.strftime('%Y-%m-%d %H:%M:%S',time.localtime(time.time()))

FrontDomain = baseinfo.BG8010FrontDomain
BackDomain = baseinfo.BG8010BackDomain
proxy_ip = baseinfo.BG8010FrontOpeIp
Lport = baseinfo.ssh_proxy_port
rbmExc = baseinfo.rbmExc
url = 'http://'+ index.app_ip
http_content = baseinfo.http_content
BG8010ServerPwd = baseinfo.BG8010ServerPwd
txt = index.txt

class Test_customapp_scp():

    def setup_method(self):
        fun.cmd("rm -f /opt/pkt/*txt", 'BG8010Client')
        fun.cmd("rm -f /opt/pkt/*txt", 'BG8010Server')
        re1 = fun.cmd("ls /opt/pkt/ |grep *txt", 'BG8010Client')
        re2 = fun.cmd("ls /opt/pkt/ |grep *txt", 'BG8010Server')
        print('客户端txt文件查询结果是:', re1)
        print('服务端txt文件查询结果是:', re2)

        clr_env.data_check_setup_met(dut='FrontDut')
        clr_env.data_check_setup_met(dut='BackDut')

    def teardown_method(self):
        clr_env.iso_teardown_met('app_scp', base_path)
        # print(1111111111)

        fun.cmd("rm -f /opt/pkt/*txt", 'BG8010Client')
        fun.cmd("rm -f /opt/pkt/*txt", 'BG8010Server')
        re1 = fun.cmd("ls /opt/pkt/ |grep *txt", 'BG8010Client')
        re2 = fun.cmd("ls /opt/pkt/ |grep *txt", 'BG8010Server')
        print('客户端txt文件查询结果是:', re1)
        print('服务端txt文件查询结果是:', re2)

        clr_env.data_check_setup_met(dut='FrontDut')
        clr_env.data_check_setup_met(dut='BackDut')

    def setup_class(self):
        # 获取参数
        fun.ssh_FrontDut.connect()
        fun.ssh_BackDut.connect()
        fun.ssh_BG8010Client.connect()
        fun.ssh_BG8010Server.connect()
        self.txt_file = index.txt_file
        self.case0_step1 = index.case0_step1
        self.case1_step1 = index.case1_step1
        self.case1_step2 = index.case1_step2
        self.case1_step3 = index.case1_step3
        self.case1_step4 = index.case1_step4
        self.case2_step1 = index.case2_step1
        self.case2_step2 = index.case2_step2
        self.case2_step3 = index.case2_step3
        clr_env.iso_setup_class(dut='FrontDut')
        clr_env.iso_setup_class(dut='BackDut')

    # @pytest.mark.skip(reseason="skip")
    @allure.feature('验证scp协议上传的定制应用通行策略')
    def test_customapp_scp_upload(self):

        # 下发配置
        fun.send(rbmExc, message.add_app_scp_upload_front['AddCustomAppPolicy'], FrontDomain, base_path)
        fun.send(rbmExc, message.add_app_scp_upload_back['AddCustomAppPolicy'], BackDomain, base_path)
        fun.wait_data('ps -ef |grep nginx', 'FrontDut', 'nginx: worker process')
        front_res1 = fun.nginx_worker('ps -ef |grep nginx', 'FrontDut', 'nginx: worker process', name='前置机nginx进程')
        assert front_res1 == 1
        fun.wait_data('ps -ef |grep nginx', 'BackDut', 'nginx: worker process')
        back_res1 = fun.nginx_worker('ps -ef |grep nginx', 'BackDut', 'nginx: worker process', name='后置机nginx进程')
        assert back_res1 == 1
        # 检查配置下发是否成功
        for key in self.case1_step1:
            re = fun.wait_data(self.case1_step1[key][0], 'FrontDut', self.case1_step1[key][1], '前置机配置', 100)
            assert self.case1_step1[key][1] in re

        for key in self.case1_step2:
            re = fun.wait_data(self.case1_step2[key][0], 'FrontDut', self.case1_step2[key][1], '前置机配置', 100)
            assert self.case1_step2[key][1] in re

        for key in self.case0_step1:
            re = fun.wait_data(self.case0_step1[key][0],'BackDut',self.case0_step1[key][1],'后置机配置',100)
            assert  self.case0_step1[key][1] in re

        #客户端创建文件100M.txt
        txt_cmd = f"dd if=/dev/zero of=/opt/pkt/{txt} bs=1M count=100"
        print('创建文件命令是:',txt_cmd)
        fun.cmd(txt_cmd, 'BG8010Client',thread=1)
        fun.wait_data(f"ls /opt/pkt/ |grep txt", 'BG8010Client', self.txt_file['step1'][0], '检查客户端文件是否创建成功', 300, flag='存在')
        txt_file = fun.search('/opt/pkt', 'txt', 'BG8010Client')
        print('客户端/opt/pkt/路径下创建文件查询结果是:',txt_file)
        assert txt in txt_file
        print('客户端创建文件成功')
        print("---------------------------------------------------------------------")

        # 发送请求，检测定制应用ssh协议通信策略是否生效
        scp_upload = f"sshpass -p {BG8010ServerPwd} scp -P {Lport} /opt/pkt/{txt} root@{proxy_ip}:/opt/pkt/"
        print('客户端发送的scp上传命令是:', scp_upload)
        fun.cmd(scp_upload, 'BG8010Client', thread=1)
        time.sleep(5)
        print("---------------------------------------------------------------------")

        #检查scp上传结果
        fun.wait_data("ls /opt/pkt/ | grep txt", 'BG8010Server', self.txt_file['step1'][0], '检查文件结果', 300, flag='存在')
        txt_file = fun.search('/opt/pkt', 'txt', 'BG8010Server')
        print('服务端/opt/pkt/路径下文件查询结果是:',txt_file)
        assert txt in txt_file
        print('scp上传文件成功')
        print("---------------------------------------------------------------------")

        # 文件查看audit日志
        fun.wait_data(f"grep -n {Lport} /usr/local/nginx/logs/audit.log |tail -1", 'FrontDut',self.case1_step3['step1'][0], '检查ssh日志结果', 300, flag='存在')
        for key in self.case1_step3:
            re = fun.cmd(f"grep -n {Lport} /usr/local/nginx/logs/audit.log |tail -1 ", 'FrontDut')
            print('re:', re)
            assert self.case1_step3[key][0] in re

        #移除策略
        fun.send(rbmExc, message.del_app_scp_front['DelCustomAppPolicy'], FrontDomain, base_path)
        fun.send(rbmExc, message.del_app_scp_back['DelCustomAppPolicy'], BackDomain, base_path)
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
    @allure.feature('验证scp协议下载的定制应用通行策略')
    def test_customapp_scp_download(self):

        # 下发配置
        fun.send(rbmExc, message.add_app_scp_download_front['AddCustomAppPolicy'], FrontDomain, base_path)
        fun.send(rbmExc, message.add_app_scp_download_back['AddCustomAppPolicy'], BackDomain, base_path)
        fun.wait_data('ps -ef |grep nginx', 'FrontDut', 'nginx: worker process')
        front_res1 = fun.nginx_worker('ps -ef |grep nginx', 'FrontDut', 'nginx: worker process',name= '前置机nginx进程')
        assert front_res1 == 1
        fun.wait_data('ps -ef |grep nginx', 'BackDut', 'nginx: worker process')
        back_res1 = fun.nginx_worker('ps -ef |grep nginx', 'BackDut', 'nginx: worker process', name='后置机nginx进程')
        assert back_res1 == 1
        # 检查配置下发是否成功
        for key in self.case2_step1:
            re = fun.wait_data(self.case2_step1[key][0], 'FrontDut', self.case2_step1[key][1], '前置机配置', 100)
            assert self.case2_step1[key][1] in re

        for key in self.case2_step2:
            re = fun.wait_data(self.case2_step2[key][0], 'FrontDut', self.case2_step2[key][1], '前置机配置', 100)
            assert self.case2_step2[key][1] in re

        for key in self.case0_step1:
            re = fun.wait_data(self.case0_step1[key][0],'BackDut',self.case0_step1[key][1],'后置机配置',100)
            assert  self.case0_step1[key][1] in re

        #服务端创建文件100M.txt
        txt_cmd = f"dd if=/dev/zero of=/opt/pkt/{txt} bs=1M count=100"
        print('创建文件命令是:',txt_cmd)
        fun.cmd(txt_cmd, 'BG8010Server',thread=1)
        fun.wait_data(f"ls /opt/pkt/ |grep txt", 'BG8010Server', self.txt_file['step1'][0], '检查服务端文件是否创建成功', 300, flag='存在')
        txt_file = fun.search('/opt/pkt', 'txt', 'BG8010Server')
        print('服务端/opt/pkt/路径下创建文件查询结果是:',txt_file)
        assert txt in txt_file
        print('服务端创建文件成功')
        print("---------------------------------------------------------------------")

        # 发送请求，检测定制应用ssh协议通信策略是否生效
        scp_download = f"sshpass -p {BG8010ServerPwd} scp -P {Lport} root@{proxy_ip}:/opt/pkt/{txt} /opt/pkt"
        print('客户端发送的scp下载命令是:', scp_download)
        fun.cmd(scp_download, 'BG8010Client', thread=1)
        print("---------------------------------------------------------------------")

        #检查scp下载结果
        fun.wait_data("ls /opt/pkt/ | grep txt", 'BG8010Client', self.txt_file['step1'][0], '检查文件结果', 300, flag='存在')
        txt_file = fun.search('/opt/pkt', 'txt', 'BG8010Client')
        print('客户端/opt/pkt/路径下文件查询结果是:',txt_file)
        assert txt in txt_file
        print('scp下载文件成功')
        print("---------------------------------------------------------------------")

        # 文件查看audit日志
        fun.wait_data(f"grep -n {Lport} /usr/local/nginx/logs/audit.log |tail -1", 'FrontDut',self.case2_step3['step1'][0], '检查ssh日志结果', 300, flag='存在')
        for key in self.case2_step3:
            re = fun.cmd(f"grep -n {Lport} /usr/local/nginx/logs/audit.log |tail -1 ", 'FrontDut')
            print('re:', re)
            assert self.case2_step3[key][0] in re

        #移除策略
        fun.send(rbmExc, message.del_app_scp_front['DelCustomAppPolicy'], FrontDomain, base_path)
        fun.send(rbmExc, message.del_app_scp_back['DelCustomAppPolicy'], BackDomain, base_path)
        fun.wait_data('ps -ef |grep nginx', 'FrontDut', 'nginx: worker process')
        front_res1 = fun.nginx_worker('ps -ef |grep nginx', 'FrontDut', 'nginx: worker process', name='前置机nginx进程')
        assert front_res1 == 1
        fun.wait_data('ps -ef |grep nginx', 'BackDut', 'nginx: worker process')
        back_res1 = fun.nginx_worker('ps -ef |grep nginx', 'BackDut', 'nginx: worker process', name='后置机nginx进程')
        assert back_res1 == 1

        # 检查配置移除是否成功
        for key in self.case2_step1:
            re = fun.wait_data(self.case2_step1[key][0], 'FrontDut', self.case2_step1[key][1], '前置机配置', 100 ,flag='不存在')
            assert self.case2_step1[key][1] not in re

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
