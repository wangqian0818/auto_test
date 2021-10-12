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
    from qos_type_udp import index
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
qos_port = baseinfo.qos_port


class Test_qos_type_udp():

    def setup_method(self):
        clr_env.clear_met_acl()

    def teardown_method(self):
        clr_env.clear_met_acl()
        fun.iperf_kill()

    def setup_class(self):
        # 获取参数
        fun.ssh_gw.connect()
        fun.ssh_c.connect()
        fun.ssh_s.connect()
        self.clr_env = clr_env.clear_env
        self.case1_step = index.case1_step
        self.case2_step = index.case2_step

        clr_env.clear_env()

    # @pytest.mark.skip(reseason="skip")
    @allure.feature(' 验证qos限速类型为UDP时的限速功能')
    def test_qos_type_udp_a1(self):

        # 下发配置并检查结果
        for key in self.case1_step:
            fun.cmd(self.case1_step[key][0], 'gw')
            re = fun.cmd(self.case1_step[key][1], 'gw')
            assert self.case1_step[key][2] in re

        # 服务端占用端口
        fun.cmd(f'iperf3 -s -p {qos_port} --logfile s.txt', 's', thread=1)
        time.sleep(5)

        # 发送报文
        c_cmd = fun.cmd(f'iperf3 -c {pcap_dip} -p {qos_port} -i 1 -u -t 5 -b 30M -P 5', 'c')
        print(c_cmd)

        # 检查速率是否正确
        s_txt = fun.cmd('cat s.txt', 's')
        s_speed = fun.qos_speed('qos_type_udp_a1.txt', s_txt, qbucket='s')
        assert 19.0 <= float(s_speed) <= 20.0

    # @pytest.mark.skip(reseason="skip")
    @allure.feature('验证qos限速类型为UDP时对其他流量的限速情况')
    def test_qos_type_udp_a2(self):

        # 下发配置并检查结果
        for key in self.case2_step:
            fun.cmd(self.case2_step[key][0], 'gw')
            re = fun.cmd(self.case2_step[key][1], 'gw')
            assert self.case2_step[key][2] in re

        # 服务端占用端口
        fun.cmd(f'iperf3 -s -p {qos_port} --logfile s.txt', 's', thread=1)
        time.sleep(5)

        # 发送报文
        c_cmd = fun.cmd(f'iperf3 -c {pcap_dip} -p {qos_port} -i 1 -t 5 -b 30M -P 5', 'c')
        print(c_cmd)

        # 检查速率是否正确
        s_txt = fun.cmd('cat s.txt', 's')
        speed_list = fun.qos_speed('qos_type_udp_a2.txt', s_txt)
        for i in speed_list:
            print(i)
            assert 29.0 <= float(i) <= 30.0

    def teardown_class(self):
        # 回收环境
        clr_env.clear_env()
        fun.ssh_gw.close()
        fun.ssh_c.close()
        fun.ssh_s.close()
