# encoding='utf-8'
try:
    import os, sys, pytest, allure, time
except Exception as err:
    print('导入CPython内置函数库失败!错误信息如下:')
    print(err)
    sys.exit(0)  # 避免程序继续运行造成的异常崩溃,友好退出程序

base_path = os.path.dirname(os.path.abspath(__file__))  # 获取当前项目文件夹
base_path = base_path.replace('\\', '/')
sys.path.insert(0, base_path)  # 将当前目录添加到系统环境变量,方便下面导入版本配置等文件
try:
    from case_selabel_cipso_scp import index
    import common.baseinfo as info
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
sys.path.append(os.getcwd())
# del sys.path[0]
# del sys.path[0]
from common import baseinfo
from common import clr_env
from common import fun

pcap_sip = baseinfo.clientOpeIp
pcap_dip = baseinfo.serverOpeIp
txt = index.txt


class Test_selabel_cipso_scp():

    def setup_method(self):
        clr_env.clear_met_acl()

    def teardown_method(self):
        clr_env.clear_met_acl()
        fun.pid_kill(self.cap_pcap1, 'python', 's')


    def setup_class(self):
        # 获取参数
        fun.ssh_gw.connect()
        fun.ssh_c.connect()
        fun.ssh_s.connect()
        self.clr_env = clr_env.clear_env
        # self.pre_env=index.pre_env
        # self.case1_step=index.case1_step
        self.pkt1_cfg = index.pkt1_cfg
        self.pkt2_cfg = index.pkt2_cfg
        self.cap_pcap1 = self.pkt1_cfg["capture"][3]
        self.cap_pcap2 = self.pkt2_cfg["capture"][3]
        self.cap_txt1 = self.pkt1_cfg["txt"][0]
        self.cap_txt2 = self.pkt2_cfg["txt"][0]
        self.read_1 = self.pkt1_cfg["read"][0]
        self.read_2 = self.pkt2_cfg["read"][0]

        clr_env.clear_env()

    # @pytest.mark.skip(reseason="skip")
    @allure.feature('验证标记系统tcp上传功能')
    def test_selabel_category_cipso_scp_upload(self):
        # 下发配置并检查结果
        # for key in self.case1_step:
        # 	fun.cmd(self.case1_step[key][0],'gw')
        # 	re = fun.cmd(self.case1_step[key][1],'gw')
        # 	assert self.case1_step[key][2] in re

        # 服务端抓取报文
        cap_iface, cap_filter, cap_num, cap_pcap = self.pkt1_cfg['capture'][0], self.pkt1_cfg['capture'][1], \
                                                   self.pkt1_cfg['capture'][2], self.pkt1_cfg['capture'][3]
        pre_cfg = fun.pkt_capture(cap_iface, cap_filter, cap_num, cap_pcap)
        print('pre_cfg:', pre_cfg)
        fun.cmd(pre_cfg, 's', thread=1)
        print('step wait')
        time.sleep(20)

        # 创建文件
        fun.cmd(f"dd if=/dev/zero of=/opt/pkt/{txt} bs=1M count=100", 'c')
        fun.wait_data(f"ls /opt/pkt/ |grep txt", 'c', self.pkt2_cfg['txt'][0], '检查服务端文件是否创建成功', 300, flag='存在')
        pcap_file = fun.search('/opt/pkt', 'txt', 'c')
        assert txt in pcap_file
        print('客户端创建文件成功')

        # 发送文件
        c_scp, c_dip = self.pkt1_cfg["scp"][0], self.pkt1_cfg["scp"][1]
        scp_cmd = fun.pkt_scp(c_scp, c_dip)
        print('scp_cmd:', scp_cmd)
        fun.cmd(scp_cmd, 'c', thread=1)

        # 检查报文是否存在
        fun.wait_data(f"ls /opt/pkt/ | grep pcap", 's', self.pkt1_cfg['capture'][3], '检查服务端抓包结果', 300, flag='存在')
        pcap_file = fun.search('/opt/pkt', 'pcap', 's')
        assert cap_pcap in pcap_file
        print('服务端抓到报文：{}'.format(self.read_1))

        # 检查文件是否存在
        fun.wait_data(f"ls /opt/pkt/ | grep txt", 's', self.pkt1_cfg['txt'][0], '检查文件结果', 300, flag='存在')
        pcap_file = fun.search('/opt/pkt', 'txt', 's')
        assert txt in pcap_file
        print('scp上传文件成功')

    # @pytest.mark.skip(reseason="skip")
    @allure.feature('验证标记系统tcp下载功能')
    def test_selabel_category_cipso_scp_download(self):
        # 服务端抓取报文

        cap_iface, cap_filter, cap_num, cap_pcap = self.pkt2_cfg['capture'][0], self.pkt2_cfg['capture'][1], \
                                                   self.pkt2_cfg['capture'][2], self.pkt2_cfg['capture'][3]
        pre_cfg = fun.pkt_capture(cap_iface, cap_filter, cap_num, cap_pcap)
        print('pre_cfg:', pre_cfg)
        fun.cmd(pre_cfg, 's', thread=1)
        print('step wait')
        time.sleep(20)

        # 创建文件
        fun.cmd(f"dd if=/dev/zero of={txt} bs=1M count=100", 's')
        fun.wait_data(f"ls /opt/pkt/ |grep txt", 's', self.pkt2_cfg['txt'][0], '检查服务端文件是否创建成功', 300, flag='存在')
        pcap_file = fun.search('/opt/pkt', 'txt', 's')
        assert txt in pcap_file
        print('服务端创建文件成功')

        # 下载文件
        scp_cmd = f"sshpass -p {info.serverPwd} scp -P 22 root@{info.serverIp}:/opt/pkt/{txt} /home/"
        print('scp_cmd:', scp_cmd)
        fun.cmd(scp_cmd, 'c', thread=1)

        # 检查报文是否存在
        fun.wait_data(f"ls /opt/pkt/ | grep pcap", 's', self.pkt2_cfg['capture'][3], '检查服务端抓包结果', 300, flag='存在')
        pcap_file = fun.search('/opt/pkt', 'pcap', 's')
        assert cap_pcap in pcap_file
        print('服务端抓到报文：{}'.format(self.read_2))

        # 检查文件是否存在
        fun.wait_data(f"ls /opt/pkt/ | grep txt", 'c', self.pkt2_cfg['txt'][0], '检查文件结果', 300, flag='存在')
        pcap_file = fun.search('/opt/pkt', 'txt', 'c')
        assert txt in pcap_file
        print('scp下载文件成功')

    def teardown_class(self):
        # 回收环境
        clr_env.clear_env()
        fun.ssh_gw.close()
        fun.ssh_c.close()
        fun.ssh_s.close()
