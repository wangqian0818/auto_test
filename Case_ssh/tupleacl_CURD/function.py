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
    from tupleacl_CURD import index
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
from common import clr_env
from common import fun


# del sys.path[0]

class Test_acl_CURD():

    def setup_method(self):
        clr_env.clear_met_acl()

    def teardown_method(self):
        clr_env.clear_met_acl()
        fun.pid_kill(self.cap_pcap)

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
        self.case5_step = index.case5_step
        self.pkt_cfg = index.pkt_cfg
        self.cap_pcap = self.pkt_cfg["capture"][3]

        clr_env.clear_env()

    # @pytest.mark.skip(reseason="skip")
    @allure.feature('测试删除一条不存在的acl策略')
    def test_acl_CURD_a1(self):

        # 下发配置并检查结果
        for key in self.case1_step:
            fun.cmd(self.case1_step[key][0], 'gw')
            re = fun.cmd(self.case1_step[key][1], 'gw')
            assert self.case1_step[key][2] in re

    # @pytest.mark.skip(reseason="skip")
    @allure.feature('测试删除一条存在的acl策略')
    def test_acl_CURD_a2(self):

        # 下发配置并检查结果
        for key in self.case2_step:
            fun.cmd(self.case2_step[key][0], 'gw')
            re = fun.cmd(self.case2_step[key][1], 'gw')
            assert self.case2_step[key][2] in re

    # @pytest.mark.skip(reseason="skip")
    @allure.feature('验证ACL策略能否重复添加')
    def test_acl_CURD_a3(self):

        # 下发配置并检查结果
        for key in self.case3_step:
            fun.cmd(self.case3_step[key][0], 'gw')
            re = fun.cmd(self.case3_step[key][1], 'gw')
            assert self.case3_step[key][2] in re

    # @pytest.mark.skip(reseason="skip")
    @allure.feature('验证acl策略的批量删除')
    def test_acl_CURD_a4(self):
        # 下发配置并检查结果
        for key in self.case4_step:
            fun.cmd(self.case4_step[key][0], 'gw')
            print('self.case4_step[key][0]: ', self.case4_step[key][0])
            re = fun.cmd(self.case4_step[key][1], 'gw')
            print('self.case4_step[key][1]: ', self.case4_step[key][1])
            print('re: ', re)
            assert self.case4_step[key][2] in re

    # @pytest.mark.skip(reseason="skip")
    @allure.feature('验证ACL策略的添加和查询')
    def test_acl_CURD_a5(self):

        # 初始化
        cap_iface, cap_filter, cap_num, cap_pcap = self.pkt_cfg["capture"][0], self.pkt_cfg["capture"][1], \
                                                   self.pkt_cfg["capture"][2], self.pkt_cfg["capture"][3]
        c_iface, c_num, c_pcap = self.pkt_cfg["send"][0], self.pkt_cfg["send"][1], self.pkt_cfg["send"][2]
        read_name, read_id = self.pkt_cfg["read"][0], self.pkt_cfg["read"][1]

        # 下发配置并检查结果
        for key in self.case5_step:
            fun.cmd(self.case5_step[key][0], 'gw')
            re = fun.cmd(self.case5_step[key][1], 'gw')
            assert self.case5_step[key][2] in re

        # 服务端抓取报文
        pre_cfg = fun.pkt_capture(cap_iface, cap_filter, cap_num, cap_pcap)
        print('sniff_cmd: ', pre_cfg)
        fun.cmd(pre_cfg, 's', thread=1)
        print('step wait')
        time.sleep(20)

        # 发送报文
        send_cmd = fun.pkt_send(c_iface, c_num, c_pcap)
        print('send_cmd: ', send_cmd)
        fun.cmd(send_cmd, 'c')

        # 检查报文是否存在
        pcap_file = fun.search('/opt/pkt', 'pcap', 's')
        print('pcap_file: ', pcap_file)
        assert cap_pcap in pcap_file

        # 读包
        read_cmd = fun.pkt_read(read_name, read_id)
        print('read_cmd: ', read_cmd)
        read_re = fun.cmd(read_cmd, 's')
        print('read_re: ', read_re)

        # 获取期望结果
        exp = self.pkt_cfg["expect"][0]
        print('exp: ', exp)
        assert exp == read_re

    def teardown_class(self):
        # 回收环境
        clr_env.clear_env()
        fun.ssh_gw.close()
        fun.ssh_c.close()
        fun.ssh_s.close()
