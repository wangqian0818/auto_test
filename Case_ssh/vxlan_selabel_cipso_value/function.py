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
    from vxlan_selabel_cipso_value import index
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


class Test_selabel_vxlan_value():

    def setup_method(self):
        clr_env.clear_met_acl()

    def teardown_method(self):
        clr_env.clear_met_acl()

        fun.pid_kill(self.cap_pcap1)
        fun.pid_kill(self.cap_pcap2)
        fun.pid_kill(self.cap_pcap3)
        fun.pid_kill(self.cap_pcap4)
        fun.pid_kill(self.cap_pcap5)
        fun.pid_kill(self.cap_pcap6)
        fun.pid_kill(self.cap_pcap7)
        fun.pid_kill(self.cap_pcap8)

    def setup_class(self):
        # 获取参数

        fun.ssh_gw.connect()
        fun.ssh_c.connect()
        fun.ssh_s.connect()
        self.clr_env = clr_env.clear_env
        # self.pre_env=index.pre_env
        self.case1_step = index.case1_step
        self.case2_step = index.case2_step
        self.case3_step = index.case3_step
        self.case4_step = index.case4_step
        self.case5_step = index.case5_step
        self.case6_step = index.case6_step
        self.case7_step = index.case7_step
        self.case8_step = index.case8_step
        self.pkt1_cfg = index.pkt1_cfg
        self.pkt2_cfg = index.pkt2_cfg
        self.pkt3_cfg = index.pkt3_cfg
        self.pkt4_cfg = index.pkt4_cfg
        self.pkt5_cfg = index.pkt5_cfg
        self.pkt6_cfg = index.pkt6_cfg
        self.pkt7_cfg = index.pkt7_cfg
        self.pkt8_cfg = index.pkt8_cfg
        self.cap_pcap1 = self.pkt1_cfg["capture"][3]
        self.cap_pcap2 = self.pkt2_cfg["capture"][3]
        self.cap_pcap3 = self.pkt3_cfg["capture"][3]
        self.cap_pcap4 = self.pkt4_cfg["capture"][3]
        self.cap_pcap5 = self.pkt5_cfg["capture"][3]
        self.cap_pcap6 = self.pkt6_cfg["capture"][3]
        self.cap_pcap7 = self.pkt7_cfg["capture"][3]
        self.cap_pcap8 = self.pkt8_cfg["capture"][3]

        clr_env.clear_env()

    # @pytest.mark.skip(reseason="skip")
    @allure.feature('验证value(即协议字段category)的右边界')
    def test_selabel_category_vxlan_value_right(self):

        # 下发配置并检查结果
        for key in self.case1_step:
            fun.cmd(self.case1_step[key][0], 'gw')
            re = fun.cmd(self.case1_step[key][1], 'gw')
            assert self.case1_step[key][2] in re

        # 服务端抓取报文
        cap_iface, cap_filter, cap_num, cap_pcap = self.pkt1_cfg['capture'][0], self.pkt1_cfg['capture'][1], \
                                                   self.pkt1_cfg['capture'][2], self.pkt1_cfg['capture'][3]
        pre_cfg = fun.pkt_capture(cap_iface, cap_filter, cap_num, cap_pcap)
        fun.cmd(pre_cfg, 's', thread=1)
        print('step wait')
        time.sleep(20)

        # 发送报文
        c_iface, c_num, c_pcap = self.pkt1_cfg["send"][0], self.pkt1_cfg["send"][1], self.pkt1_cfg["send"][2]
        send_cmd = fun.pkt_send(c_iface, c_num, c_pcap)
        fun.cmd(send_cmd, 'c')

        # 检查报文是否存在
        pcap_file = fun.search('/opt/pkt', 'pcap', 's')
        assert cap_pcap in pcap_file

        # 读包
        read_name, read_id = self.pkt1_cfg["read"][0], self.pkt1_cfg["read"][1]
        read_cmd = fun.vxlan_read(read_name, read_id)
        print(read_cmd)
        read_re = fun.cmd(read_cmd, 's')
        print('read_re: ', read_re)
        # 获取期望结果
        exp = self.pkt1_cfg["expect"][0]
        assert exp == read_re

    # @pytest.mark.skip(reseason="skip")
    @allure.feature('验证value(即协议字段category)的左边界')
    def test_selabel_category_vxlan_value_left(self):

        # 下发配置并检查结果
        for key in self.case2_step:
            fun.cmd(self.case2_step[key][0], 'gw')
            re = fun.cmd(self.case2_step[key][1], 'gw')
            assert self.case2_step[key][2] in re

        # 服务端抓取报文
        cap_iface, cap_filter, cap_num, cap_pcap = self.pkt2_cfg['capture'][0], self.pkt2_cfg['capture'][1], \
                                                   self.pkt2_cfg['capture'][2], self.pkt2_cfg['capture'][3]
        pre_cfg = fun.pkt_capture(cap_iface, cap_filter, cap_num, cap_pcap)
        fun.cmd(pre_cfg, 's', thread=1)
        print('step wait')
        time.sleep(20)

        # 发送报文
        c_iface, c_num, c_pcap = self.pkt2_cfg["send"][0], self.pkt2_cfg["send"][1], self.pkt2_cfg["send"][2]
        send_cmd = fun.pkt_send(c_iface, c_num, c_pcap)
        fun.cmd(send_cmd, 'c')

        # 检查报文是否存在
        pcap_file = fun.search('/opt/pkt', 'pcap', 's')
        assert cap_pcap in pcap_file

        # 读包
        read_name, read_id = self.pkt2_cfg["read"][0], self.pkt2_cfg["read"][1]
        read_cmd = fun.vxlan_read(read_name, read_id)
        print(read_cmd)
        read_re = fun.cmd(read_cmd, 's')
        print('read_re: ', read_re)
        # 获取期望结果
        exp = self.pkt2_cfg["expect"][0]
        assert exp == read_re

    # @pytest.mark.skip(reseason="skip")
    @allure.feature('验证value(即协议字段category范围为64-191)')
    def test_selabel_category_vxlan_value_range1(self):

        # 下发配置并检查结果
        for key in self.case3_step:
            fun.cmd(self.case3_step[key][0], 'gw')
            re = fun.cmd(self.case3_step[key][1], 'gw')
            assert self.case3_step[key][2] in re

        # 服务端抓取报文
        cap_iface, cap_filter, cap_num, cap_pcap = self.pkt3_cfg['capture'][0], self.pkt3_cfg['capture'][1], \
                                                   self.pkt3_cfg['capture'][2], self.pkt3_cfg['capture'][3]
        pre_cfg = fun.pkt_capture(cap_iface, cap_filter, cap_num, cap_pcap)
        fun.cmd(pre_cfg, 's', thread=1)
        print('step wait')
        time.sleep(20)

        # 发送报文
        c_iface, c_num, c_pcap = self.pkt3_cfg["send"][0], self.pkt3_cfg["send"][1], self.pkt3_cfg["send"][2]
        send_cmd = fun.pkt_send(c_iface, c_num, c_pcap)
        fun.cmd(send_cmd, 'c')

        # 检查报文是否存在
        pcap_file = fun.search('/opt/pkt', 'pcap', 's')
        assert cap_pcap in pcap_file

        # 读包
        read_name, read_id = self.pkt3_cfg["read"][0], self.pkt3_cfg["read"][1]
        read_cmd = fun.vxlan_read(read_name, read_id)
        print(read_cmd)
        read_re = fun.cmd(read_cmd, 's')
        print('read_re: ', read_re)
        # 获取期望结果
        exp = self.pkt3_cfg["expect"][0]
        assert exp == read_re

    # @pytest.mark.skip(reseason="skip")
    @allure.feature('验证value(即协议字段category范围为64-127,192-239)')
    def test_selabel_category_vxlan_value_range2(self):

        # 下发配置并检查结果
        for key in self.case4_step:
            fun.cmd(self.case4_step[key][0], 'gw')
            re = fun.cmd(self.case4_step[key][1], 'gw')
            assert self.case4_step[key][2] in re

        # 服务端抓取报文
        cap_iface, cap_filter, cap_num, cap_pcap = self.pkt4_cfg['capture'][0], self.pkt4_cfg['capture'][1], \
                                                   self.pkt4_cfg['capture'][2], self.pkt4_cfg['capture'][3]
        pre_cfg = fun.pkt_capture(cap_iface, cap_filter, cap_num, cap_pcap)
        fun.cmd(pre_cfg, 's', thread=1)
        print('step wait')
        time.sleep(20)

        # 发送报文
        c_iface, c_num, c_pcap = self.pkt4_cfg["send"][0], self.pkt4_cfg["send"][1], self.pkt4_cfg["send"][2]
        send_cmd = fun.pkt_send(c_iface, c_num, c_pcap)
        fun.cmd(send_cmd, 'c')

        # 检查报文是否存在
        pcap_file = fun.search('/opt/pkt', 'pcap', 's')
        assert cap_pcap in pcap_file

        # 读包
        read_name, read_id = self.pkt4_cfg["read"][0], self.pkt4_cfg["read"][1]
        read_cmd = fun.vxlan_read(read_name, read_id)
        print(read_cmd)
        read_re = fun.cmd(read_cmd, 's')
        print('read_re: ', read_re)
        # 获取期望结果
        exp = self.pkt4_cfg["expect"][0]
        assert exp == read_re

    # @pytest.mark.skip(reseason="skip")
    @allure.feature('验证value(即协议字段category范围为0-31,67,128-143,192,193)')
    def test_selabel_category_vxlan_value_range3(self):

        # 下发配置并检查结果
        for key in self.case5_step:
            fun.cmd(self.case5_step[key][0], 'gw')
            re = fun.cmd(self.case5_step[key][1], 'gw')
            assert self.case5_step[key][2] in re

        # 服务端抓取报文
        cap_iface, cap_filter, cap_num, cap_pcap = self.pkt5_cfg['capture'][0], self.pkt5_cfg['capture'][1], \
                                                   self.pkt5_cfg['capture'][2], self.pkt5_cfg['capture'][3]
        pre_cfg = fun.pkt_capture(cap_iface, cap_filter, cap_num, cap_pcap)
        fun.cmd(pre_cfg, 's', thread=1)
        print('step wait')
        time.sleep(20)

        # 发送报文
        c_iface, c_num, c_pcap = self.pkt5_cfg["send"][0], self.pkt5_cfg["send"][1], self.pkt5_cfg["send"][2]
        send_cmd = fun.pkt_send(c_iface, c_num, c_pcap)
        fun.cmd(send_cmd, 'c')

        # 检查报文是否存在
        pcap_file = fun.search('/opt/pkt', 'pcap', 's')
        assert cap_pcap in pcap_file

        # 读包
        read_name, read_id = self.pkt5_cfg["read"][0], self.pkt5_cfg["read"][1]
        read_cmd = fun.vxlan_read(read_name, read_id)
        print(read_cmd)
        read_re = fun.cmd(read_cmd, 's')
        print('read_re: ', read_re)
        # 获取期望结果
        exp = self.pkt5_cfg["expect"][0]
        assert exp == read_re

    # @pytest.mark.skip(reseason="skip")
    @allure.feature('验证value(即协议字段category范围为0 2 67  128 129 192 193 194 195 196 197 198 199)')
    def test_selabel_category_vxlan_value_range4(self):

        # 下发配置并检查结果
        for key in self.case6_step:
            fun.cmd(self.case6_step[key][0], 'gw')
            re = fun.cmd(self.case6_step[key][1], 'gw')
            assert self.case6_step[key][2] in re

        # 服务端抓取报文
        cap_iface, cap_filter, cap_num, cap_pcap = self.pkt6_cfg['capture'][0], self.pkt6_cfg['capture'][1], \
                                                   self.pkt6_cfg['capture'][2], self.pkt6_cfg['capture'][3]
        pre_cfg = fun.pkt_capture(cap_iface, cap_filter, cap_num, cap_pcap)
        fun.cmd(pre_cfg, 's', thread=1)
        print('step wait')
        time.sleep(20)

        # 发送报文
        c_iface, c_num, c_pcap = self.pkt6_cfg["send"][0], self.pkt6_cfg["send"][1], self.pkt6_cfg["send"][2]
        send_cmd = fun.pkt_send(c_iface, c_num, c_pcap)
        fun.cmd(send_cmd, 'c')

        # 检查报文是否存在
        pcap_file = fun.search('/opt/pkt', 'pcap', 's')
        assert cap_pcap in pcap_file

        # 读包
        read_name, read_id = self.pkt6_cfg["read"][0], self.pkt6_cfg["read"][1]
        read_cmd = fun.vxlan_read(read_name, read_id)
        print(read_cmd)
        read_re = fun.cmd(read_cmd, 's')
        print('read_re: ', read_re)
        # 获取期望结果
        exp = self.pkt6_cfg["expect"][0]
        assert exp == read_re

    # @pytest.mark.skip(reseason="skip")
    @allure.feature('验证value(即协议字段category范围为0-191)')
    def test_selabel_category_vxlan_value_range5(self):

        # 下发配置并检查结果
        for key in self.case7_step:
            fun.cmd(self.case7_step[key][0], 'gw')
            re = fun.cmd(self.case7_step[key][1], 'gw')
            assert self.case7_step[key][2] in re

        # 服务端抓取报文
        cap_iface, cap_filter, cap_num, cap_pcap = self.pkt7_cfg['capture'][0], self.pkt7_cfg['capture'][1], \
                                                   self.pkt7_cfg['capture'][2], self.pkt7_cfg['capture'][3]
        pre_cfg = fun.pkt_capture(cap_iface, cap_filter, cap_num, cap_pcap)
        fun.cmd(pre_cfg, 's', thread=1)
        print('step wait')
        time.sleep(20)

        # 发送报文
        c_iface, c_num, c_pcap = self.pkt7_cfg["send"][0], self.pkt7_cfg["send"][1], self.pkt7_cfg["send"][2]
        send_cmd = fun.pkt_send(c_iface, c_num, c_pcap)
        fun.cmd(send_cmd, 'c')

        # 检查报文是否存在
        pcap_file = fun.search('/opt/pkt', 'pcap', 's')
        assert cap_pcap in pcap_file

        # 读包
        read_name, read_id = self.pkt7_cfg["read"][0], self.pkt7_cfg["read"][1]
        read_cmd = fun.vxlan_read(read_name, read_id)
        print(read_cmd)
        read_re = fun.cmd(read_cmd, 's')
        print('read_re: ', read_re)
        # 获取期望结果
        exp = self.pkt7_cfg["expect"][0]
        assert exp == read_re

    # @pytest.mark.skip(reseason="skip")
    @allure.feature('验证value(即协议字段category范围为192-239)')
    def test_selabel_category_vxlan_value_range6(self):

        # 下发配置并检查结果
        for key in self.case8_step:
            fun.cmd(self.case8_step[key][0], 'gw')
            re = fun.cmd(self.case8_step[key][1], 'gw')
            assert self.case8_step[key][2] in re

        # 服务端抓取报文
        cap_iface, cap_filter, cap_num, cap_pcap = self.pkt8_cfg['capture'][0], self.pkt8_cfg['capture'][1], \
                                                   self.pkt8_cfg['capture'][2], self.pkt8_cfg['capture'][3]
        pre_cfg = fun.pkt_capture(cap_iface, cap_filter, cap_num, cap_pcap)
        fun.cmd(pre_cfg, 's', thread=1)
        print('step wait')
        time.sleep(20)

        # 发送报文
        c_iface, c_num, c_pcap = self.pkt8_cfg["send"][0], self.pkt8_cfg["send"][1], self.pkt8_cfg["send"][2]
        send_cmd = fun.pkt_send(c_iface, c_num, c_pcap)
        fun.cmd(send_cmd, 'c')

        # 检查报文是否存在
        pcap_file = fun.search('/opt/pkt', 'pcap', 's')
        assert cap_pcap in pcap_file

        # 读包
        read_name, read_id = self.pkt8_cfg["read"][0], self.pkt8_cfg["read"][1]
        read_cmd = fun.vxlan_read(read_name, read_id)
        print(read_cmd)
        read_re = fun.cmd(read_cmd, 's')
        print('read_re: ', read_re)
        # 获取期望结果
        exp = self.pkt8_cfg["expect"][0]
        assert exp == read_re

    def teardown_class(self):
        # 回收环境
        clr_env.clear_env()
        fun.ssh_gw.close()
        fun.ssh_c.close()
        fun.ssh_s.close()
