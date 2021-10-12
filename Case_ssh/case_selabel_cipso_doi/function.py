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
    from case_selabel_cipso_doi import index
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


class Test_selabel_cipso_doi():

    def setup_method(self):
        clr_env.clear_met_acl()

    def teardown_method(self):
        clr_env.clear_met_acl()

        fun.pid_kill(self.cap_pcap1, 'python', 's')
        fun.pid_kill(self.cap_pcap4, 'python', 's')

    def setup_class(self):
        # 获取参数
        fun.ssh_gw.connect()
        fun.ssh_c.connect()
        fun.ssh_s.connect()
        self.clr_env = clr_env.clear_env
        self.case1_step = index.case1_step
        self.case2_step = index.case2_step
        self.case3_step = index.case3_step
        self.case4_step = index.case4_step
        self.pkt1_cfg = index.pkt1_cfg
        self.pkt4_cfg = index.pkt4_cfg
        self.cap_pcap1 = self.pkt1_cfg["capture"][3]
        self.cap_pcap4 = self.pkt4_cfg["capture"][3]
        self.read_4 = self.pkt4_cfg["read"][0]

        clr_env.clear_env()

    # @pytest.mark.skip(reseason="skip")
    @allure.feature('测试doi字段不匹配的默认标记')
    def test_selabel_cipso_doi_unmatch(self):

        # 下发配置并检查结果
        for key in self.case1_step:
            fun.cmd(self.case1_step[key][0], 'gw')
            re = fun.cmd(self.case1_step[key][1], 'gw')
            assert self.case1_step[key][2] in re

        # 服务端抓取报文
        cap_iface, cap_filter, cap_num, cap_pcap = self.pkt1_cfg['capture'][0], self.pkt1_cfg['capture'][1], \
                                                   self.pkt1_cfg['capture'][2], self.pkt1_cfg['capture'][3]
        pre_cfg = fun.pkt_capture(cap_iface, cap_filter, cap_num, cap_pcap)
        print('pre_cfg:', pre_cfg)
        fun.cmd(pre_cfg, 's', thread=1)
        print('step wait')
        time.sleep(20)

        # 发送报文
        c_iface, c_num, c_pcap = self.pkt1_cfg["send"][0], self.pkt1_cfg["send"][1], self.pkt1_cfg["send"][2]
        send_cmd = fun.pkt_send(c_iface, c_num, c_pcap)
        print('send_cmd:', send_cmd)
        fun.cmd(send_cmd, 'c')

        # 检查报文是否存在
        pcap_file = fun.search('/opt/pkt', 'pcap', 's')
        assert cap_pcap not in pcap_file
        print('报文doi字段不匹配，服务端未抓到报文test_selabel_cipso_doi_unmatch.pcap')

    # @pytest.mark.skip(reseason="skip")
    @allure.feature('验证添加标记字段doi的左边界0、-1、1')
    def test_selabel_cipso_doi_left(self):

        # 下发配置并检查结果
        for key in self.case2_step:
            fun.cmd(self.case2_step[key][0], 'gw')
            re = fun.cmd(self.case2_step[key][1], 'gw')
            assert self.case2_step[key][2] in re
            print('doi为0、-1时无法添加,doi为1时可以添加')

    # @pytest.mark.skip(reseason="skip")
    @allure.feature('验证添加标记字段doi的右边界4294967295')
    def test_selabel_cipso_doi_right(self):

        # 下发配置并检查结果
        for key in self.case3_step:
            fun.cmd(self.case3_step[key][0], 'gw')
            re = fun.cmd(self.case3_step[key][1], 'gw')
            assert self.case3_step[key][2] in re
            print('doi为4294967295时添加成功')

    # @pytest.mark.skip(reseason="skip")
    @allure.feature('测试doi字段匹配时的默认标记')
    def test_selabel_cipso_doi_match(self):

        # 下发配置并检查结果
        for key in self.case4_step:
            fun.cmd(self.case4_step[key][0], 'gw')
            re = fun.cmd(self.case4_step[key][1], 'gw')
            assert self.case4_step[key][2] in re

        # 服务端抓取报文
        cap_iface, cap_filter, cap_num, cap_pcap = self.pkt4_cfg['capture'][0], self.pkt4_cfg['capture'][1], \
                                                   self.pkt4_cfg['capture'][2], self.pkt4_cfg['capture'][3]
        pre_cfg = fun.pkt_capture(cap_iface, cap_filter, cap_num, cap_pcap)
        print('pre_cfg:', pre_cfg)
        fun.cmd(pre_cfg, 's', thread=1)
        print('step wait')
        time.sleep(20)

        # 发送报文
        c_iface, c_num, c_pcap = self.pkt4_cfg["send"][0], self.pkt4_cfg["send"][1], self.pkt4_cfg["send"][2]
        send_cmd = fun.pkt_send(c_iface, c_num, c_pcap)
        print('send_cmd:', send_cmd)
        fun.cmd(send_cmd, 'c')

        # 检查报文是否存在
        # fun.wait_data(f"ls /opt/pkt/ | grep pcap", 'gw', self.pkt4_cfg['capture'][3], '检查服务端抓包结果', 300, flag='存在')
        pcap_file = fun.search('/opt/pkt', 'pcap', 's')
        assert cap_pcap in pcap_file
        print('服务端抓到报文：{}'.format(self.read_4))

        # 读包
        read_name, read_id = self.pkt4_cfg["read"][0], self.pkt4_cfg["read"][1]
        read_cmd = fun.pkt_read(read_name, read_id)
        print('read_cmd:', read_cmd)
        read_re = fun.cmd(read_cmd, 's')
        print('read_re:', read_re)
        # 获取期望结果
        exp = self.pkt4_cfg["expect"][0]
        assert exp == read_re

    def teardown_class(self):
        # 回收环境
        clr_env.clear_env()
        fun.ssh_gw.close()
        fun.ssh_c.close()
        fun.ssh_s.close()
