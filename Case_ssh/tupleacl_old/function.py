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
    from tupleacl_old import index
except Exception as err:
    print(
        '导入基础函数库失败!请检查相关文件是否存在.\n文件位于: ' + str(base_path) + '/common/ 目录下.\n分别为:pcap.py  rabbitmq.py  ssh.py\n错误信息如下:')
    print(err)
    sys.exit(0)  # 避免程序继续运行造成的异常崩溃,友好退出程序
else:
    del sys.path[0]  # 及时删除导入的环境变量,避免重复导入造成的异常错误
sys.path.append(os.getcwd())
from common import baseinfo
from common import clr_env
from common import fun

pcap_sip = baseinfo.clientOpeIp
pcap_dip = baseinfo.serverOpeIp


class Test_acl_old():

    def setup_method(self):
        clr_env.clear_met_acl()

    def teardown_method(self):
        clr_env.clear_met_acl()

        # 判断抓包程序是否停止，如果进程还在则停止
        fun.pid_kill(self.cap_pcap1)

    def setup_class(self):
        # 获取参数
        fun.ssh_gw.connect()
        fun.ssh_c.connect()
        fun.ssh_s.connect()
        self.clr_env = clr_env.clear_env
        self.case1_step1 = index.case1_step1
        self.pkt1_cfg = index.pkt1_cfg
        self.cap_pcap1 = self.pkt1_cfg["capture"][3]

        clr_env.clear_env()

    @allure.feature('验证match为交集时，对报文的处理原则')
    def test_acl_old_a1(self):

        # 初始化
        cap_iface, cap_filter, cap_num, cap_pcap = self.pkt1_cfg["capture"][0], self.pkt1_cfg["capture"][1], \
                                                   self.pkt1_cfg["capture"][2], self.pkt1_cfg["capture"][3]
        c_iface, c_num, c_pcap = self.pkt1_cfg["send"][0], self.pkt1_cfg["send"][1], self.pkt1_cfg["send"][2]
        read_name, read_id = self.pkt1_cfg["read"][0], self.pkt1_cfg["read"][1]

        # 下发配置并检查结果
        for key in self.case1_step1:
            fun.cmd(self.case1_step1[key][0], 'gw')
            re = fun.cmd(self.case1_step1[key][1], 'gw')
            assert self.case1_step1[key][2] in re

        # 服务端抓取报文
        pre_cfg = fun.pkt_capture(cap_iface, cap_filter, cap_num, cap_pcap)
        print('pre_cfg: ', pre_cfg)
        fun.cmd(pre_cfg, 's', thread=1)
        print('step wait')
        time.sleep(20)

        # 发送报文
        send_cmd = fun.pkt_send(c_iface, c_num, c_pcap)
        print('send_cmd: ', send_cmd)
        fun.cmd(send_cmd, 'c')

        # 检查报文是否存在
        pcap_file = fun.search('/opt/pkt', 'pcap', 's')
        print('cap_pcap: ', cap_pcap)
        assert cap_pcap in pcap_file

        # 读包
        read_cmd = fun.pkt_read(read_name, read_id)
        read_re = fun.cmd(read_cmd, 's')
        print('read_re: ', read_re)

        # 获取期望结果
        exp = self.pkt1_cfg["expect"][0]
        print('exp: ', exp)
        assert exp == read_re

        print('等待60s的老化时间')
        time.sleep(70)

        # 下发配置并检查结果
        for key in self.case1_step1:
            re = fun.cmd(self.case1_step1[key][1], 'gw')
            assert self.case1_step1[key][2] not in re

    def teardown_class(self):
        # 回收环境
        clr_env.clear_env()
        fun.ssh_gw.close()
        fun.ssh_c.close()
        fun.ssh_s.close()
