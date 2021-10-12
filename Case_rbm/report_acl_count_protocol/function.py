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
    from report_acl_count_protocol import index
    from report_acl_count_protocol import message
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

pcap_dip = '"' + baseinfo.serverOpeIp + '"'
ReportAclCount = '"ReportAclCount"'
domain_rmb = baseinfo.rbmDomain
Exc_rmb = baseinfo.rbmExc
qos_port = baseinfo.qos_port
protocol_tcp = '"Protocol":"6"'
protocol_udp = '"Protocol":"17"'
protocol_icmp = '"Protocol":"1"'


class Test_report_acl_count():
    def setup_method(self):
        clr_env.data_check_setup_met()

    def teardown_method(self):
        clr_env.clear_env()

        fun.pid_kill(self.cap_pcap1, 'pyhton', 's')
        fun.pid_kill(self.cap_pcap2, 'pyhton', 's')
        fun.pid_kill(self.cap_pcap3, 'pyhton', 's')

    def setup_class(self):
        # 获取参数
        fun.ssh_gw.connect()
        # fun.rbm.connect()
        fun.ssh_c.connect()
        fun.ssh_s.connect()
        self.clr_env = clr_env.clear_env
        self.case1_step1 = index.case1_step1
        self.case1_step2 = index.case1_step2
        self.case1_step3 = index.case1_step3
        self.case1_step4 = index.case1_step4
        self.case1_step5 = index.case1_step5
        self.case1_step6 = index.case1_step6
        self.case2_step1 = index.case2_step1
        self.case2_step2 = index.case2_step2
        self.case2_step3 = index.case2_step3
        self.case2_step4 = index.case2_step4
        self.case2_step5 = index.case2_step5
        self.case3_step1 = index.case3_step1
        self.case3_step2 = index.case3_step2
        self.case3_step3 = index.case3_step3
        self.case3_step4 = index.case3_step4
        self.case3_step5 = index.case3_step5
        self.pkt1_cfg = index.pkt1_cfg
        self.pkt2_cfg = index.pkt2_cfg
        self.pkt3_cfg = index.pkt3_cfg
        self.cap_pcap1 = self.pkt1_cfg["capture"][3]
        self.cap_pcap2 = self.pkt2_cfg["capture"][3]
        self.cap_pcap3 = self.pkt3_cfg["capture"][3]
        self.read_1 = self.pkt1_cfg["read"][0]
        self.read_2 = self.pkt2_cfg["read"][0]
        self.read_3 = self.pkt3_cfg["read"][0]

        clr_env.clear_env()

    # @pytest.mark.skip(reseason="skip")
    @allure.feature('acl命中统计测试---TCP协议')
    def test_report_acl_count_protocol_TCP(self):
        # 开启acl命中统计开关并检查结果
        fun.send(Exc_rmb, message.set_ReportAclCount_open['EnableAclCount'], domain_rmb, base_path)
        for key in self.case1_step1:
            print('ip:', baseinfo.gwManageIp)
            re = fun.cmd(self.case1_step1[key][0], 'gw')
            print('re:', re)
            assert self.case1_step1[key][1] in re

        # 下发acl策略并检查结果-----查询失败问题待调查
        fun.send(Exc_rmb, message.AddAclPolicy_HitCount['AddAclPolicy'], domain_rmb, base_path)
        # for key in self.case1_step2:
        # 	print('ip:',baseinfo.gwManageIp)
        # 	re = fun.cmd(self.case1_step2[key][0],'gw',thread=1)
        # 	print('key:',self.case1_step2[key][0])
        # 	print('re:',re)
        # 	assert self.case1_step2[key][1] in re

        # 服务端抓取报文
        cap_iface, cap_filter, cap_num, cap_pcap = self.pkt1_cfg['capture'][0], self.pkt1_cfg['capture'][1], \
                                                   self.pkt1_cfg['capture'][2], self.pkt1_cfg['capture'][3]
        pre_cfg = fun.pkt_capture(cap_iface, cap_filter, cap_num, cap_pcap)
        print('pre_cfg:', pre_cfg)
        fun.cmd(pre_cfg, 's', thread=1)
        print('step wait')
        time.sleep(20)

        # 客户端发送正常请求报文
        c_iface, c_num, c_pcap = self.pkt1_cfg["send"][0], self.pkt1_cfg["send"][1], self.pkt1_cfg["send"][2]
        send_cmd = fun.pkt_send(c_iface, c_num, c_pcap)
        print('send_cmd:', send_cmd)
        fun.cmd(send_cmd, 'c')
        print('tcpreplay命令发送成功')

        # jsac.agentjsac.info.log文件查看命中统计数
        fun.wait_data(
            f"grep -n '{protocol_tcp}' /var/log/jsac.agentjsac.info.log |grep '{pcap_dip}' |grep '{ReportAclCount}' |tail -1",
            'gw', self.case1_step3['step1'][0], '检查命中数', 300, flag='存在')
        for key in self.case1_step4:
            re = fun.cmd(
                f"grep -n '{protocol_tcp}' /var/log/jsac.agentjsac.info.log |grep '{pcap_dip}' |grep '{ReportAclCount}' |tail -1 ",
                'gw')
            print('re:', re)
            assert self.case1_step4[key][0] in re

        # 检查报文是否存在
        # fun.wait_data(f"ls /opt/pkt/ | grep pcap", 'gw', self.pkt1_cfg['capture'][3], '检查服务端抓包结果', 300, flag='存在')
        pcap_file = fun.search('/opt/pkt', 'pcap', 's')
        print('pcap_file:', pcap_file)
        assert cap_pcap in pcap_file
        print('服务端抓到报文：{}'.format(self.read_1))
        print('step wait')

        # 关闭acl命中统计开关并检查结果
        fun.send(Exc_rmb, message.set_ReportAclCount_close['EnableAclCount'], domain_rmb, base_path)
        for key in self.case1_step4:
            re = fun.cmd(self.case1_step5[key][0], 'gw')
            print('re:', re)
            assert self.case1_step5[key][1] in re

        # 移除掉acl策略并检查结果
        fun.send(Exc_rmb, message.DelAclPolicy_HitCount['DelAclPolicy'], domain_rmb, base_path)

    # for key in self.case1_step6:
    # 	re = fun.cmd(self.case1_step6[key][0],'gw')
    # 	print('re:',re)
    # 	assert self.case1_step6[key][1] in re

    # @pytest.mark.skip(reseason="skip")
    @allure.feature('acl命中统计测试---UDP协议')
    def test_report_acl_labelRejectPac_count_protocol_UDP(self):
        # 开启acl命中统计开关并检查结果
        fun.send(Exc_rmb, message.set_ReportAclCount_open['EnableAclCount'], domain_rmb, base_path)
        for key in self.case2_step1:
            print('ip:', baseinfo.gwManageIp)
            re = fun.cmd(self.case2_step1[key][0], 'gw')
            print('re:', re)
            assert self.case2_step1[key][1] in re

        # 下发acl策略并检查结果-----查询失败问题待调查
        fun.send(Exc_rmb, message.AddAclPolicy_labelRejectPac['AddAclPolicy'], domain_rmb, base_path)
        # for key in self.case2_step2:
        # 	print('ip:',baseinfo.gwManageIp)
        # 	re = fun.cmd(self.case2_step2[key][0],'gw',thread=1)
        # 	print('key:',self.case2_step2[key][0])
        # 	print('re:',re)
        # 	assert self.case2_step2[key][1] in re

        # 服务端抓取报文
        cap_iface, cap_filter, cap_num, cap_pcap = self.pkt2_cfg['capture'][0], self.pkt2_cfg['capture'][1], \
                                                   self.pkt2_cfg['capture'][2], self.pkt2_cfg['capture'][3]
        pre_cfg = fun.pkt_capture(cap_iface, cap_filter, cap_num, cap_pcap)
        print('pre_cfg:', pre_cfg)
        fun.cmd(pre_cfg, 's', thread=1)
        print('step wait')
        time.sleep(20)

        # 客户端发送正常请求报文
        c_iface, c_num, c_pcap = self.pkt2_cfg["send"][0], self.pkt2_cfg["send"][1], self.pkt2_cfg["send"][2]
        send_cmd = fun.pkt_send(c_iface, c_num, c_pcap)
        print('send_cmd:', send_cmd)
        fun.cmd(send_cmd, 'c')
        print('tcpreplay命令发送成功')

        # jsac.agentjsac.info.log文件查看命中统计数
        fun.wait_data(
            f"grep -n '{protocol_udp}' /var/log/jsac.agentjsac.info.log |grep '{pcap_dip}' |grep '{ReportAclCount}' |tail -1",
            'gw', self.case2_step3['step1'][0], '检查拒绝数', 300, flag='存在')
        fun.wait_data(
            f"grep -n '{protocol_udp}' /var/log/jsac.agentjsac.info.log |grep '{pcap_dip}' |grep '{ReportAclCount}' |tail -1",
            'gw', self.case2_step3['step2'][0], '检查拒绝数', 300, flag='存在')
        for key in self.case2_step3:
            re = fun.cmd(
                f"grep -n '{protocol_udp}' /var/log/jsac.agentjsac.info.log |grep '{pcap_dip}' |grep '{ReportAclCount}' |tail -1 ",
                'gw')
            print('re:', re)
            assert self.case2_step3['step1'][0] in re

        # 检查报文是否存在
        # fun.wait_data(f"ls /opt/pkt/ | grep pcap", 'gw', self.pkt2_cfg['capture'][3], '检查服务端抓包结果', 300, flag='存在')
        pcap_file = fun.search('/opt/pkt', 'pcap', 's')
        print('pcap_file:', pcap_file)
        assert cap_pcap in pcap_file
        print('服务端抓到报文：{}'.format(self.read_1))
        print('step wait')

        # 关闭acl命中统计开关并检查结果
        fun.send(Exc_rmb, message.set_ReportAclCount_close['EnableAclCount'], domain_rmb, base_path)
        for key in self.case2_step4:
            re = fun.cmd(self.case2_step4[key][0], 'gw')
            print('re:', re)
            assert self.case2_step4[key][1] in re

        # 移除掉acl策略并检查结果
        fun.send(Exc_rmb, message.DelAclPolicy_HitCount['DelAclPolicy'], domain_rmb, base_path)

    # for key in self.case2_step5:
    # 	re = fun.cmd(self.case2_step5[key][0], 'gw')
    # 	print('re:', re)
    # 	assert self.case2_step5[key][1] in re

    # @pytest.mark.skip(reseason="skip")
    @allure.feature('acl命中统计测试---ICMP协议')
    def test_report_acl_labelPassPac_count_protocol_ICMP(self):
        # 开启acl命中统计开关并检查结果
        fun.send(Exc_rmb, message.set_ReportAclCount_open['EnableAclCount'], domain_rmb, base_path)
        for key in self.case3_step1:
            print('ip:', baseinfo.gwManageIp)
            re = fun.cmd(self.case3_step1[key][0], 'gw')
            print('re:', re)
            assert self.case3_step1[key][1] in re

        # 下发acl策略并检查结果-----查询失败问题待调查
        fun.send(Exc_rmb, message.AddAclPolicy_labelPassPac['AddAclPolicy'], domain_rmb, base_path)
        # for key in self.case3_step2:
        # 	print('ip:',baseinfo.gwManageIp)
        # 	re = fun.cmd(self.case3_step2[key][0],'gw',thread=1)
        # 	print('key:',self.case3_step2[key][0])
        # 	print('re:',re)
        # 	assert self.case3_step2[key][1] in re

        # 服务端抓取报文
        cap_iface, cap_filter, cap_num, cap_pcap = self.pkt3_cfg['capture'][0], self.pkt3_cfg['capture'][1], \
                                                   self.pkt3_cfg['capture'][2], self.pkt3_cfg['capture'][3]
        pre_cfg = fun.pkt_capture(cap_iface, cap_filter, cap_num, cap_pcap)
        print('pre_cfg:', pre_cfg)
        fun.cmd(pre_cfg, 's', thread=1)
        print('step wait')
        time.sleep(20)

        # 客户端发送正常请求报文
        c_iface, c_num, c_pcap = self.pkt3_cfg["send"][0], self.pkt3_cfg["send"][1], self.pkt3_cfg["send"][2]
        send_cmd = fun.pkt_send(c_iface, c_num, c_pcap)
        print('send_cmd:', send_cmd)
        fun.cmd(send_cmd, 'c')
        print('tcpreplay命令发送成功')

        # jsac.agentjsac.info.log文件查看命中统计数
        fun.wait_data(
            f"grep -n '{protocol_icmp}' /var/log/jsac.agentjsac.info.log |grep '{pcap_dip}' |grep '{ReportAclCount}' |tail -1",
            'gw', self.case3_step3['step1'][0], '检查拒绝数', 300, flag='存在')
        fun.wait_data(
            f"grep -n '{protocol_icmp}' /var/log/jsac.agentjsac.info.log |grep '{pcap_dip}' |grep '{ReportAclCount}' |tail -1",
            'gw', self.case3_step3['step2'][0], '检查拒绝数', 300, flag='存在')
        for key in self.case3_step3:
            re = fun.cmd(
                f"grep -n '{protocol_icmp}' /var/log/jsac.agentjsac.info.log |grep '{pcap_dip}' |grep '{ReportAclCount}' |tail -1 ",
                'gw')
            print('re:', re)
            assert self.case3_step3['step1'][0] in re

        # 检查报文是否存在
        # fun.wait_data(f"ls /opt/pkt/ | grep pcap", 'gw', self.pkt3_cfg['capture'][3], '检查服务端抓包结果', 300, flag='存在')
        pcap_file = fun.search('/opt/pkt', 'pcap', 's')
        print('pcap_file:', pcap_file)
        assert cap_pcap in pcap_file
        print('服务端抓到报文：{}'.format(self.read_3))
        print('step wait')

        # 关闭acl命中统计开关并检查结果
        fun.send(Exc_rmb, message.set_ReportAclCount_close['EnableAclCount'], domain_rmb, base_path)
        for key in self.case3_step4:
            re = fun.cmd(self.case3_step4[key][0], 'gw')
            print('re:', re)
            assert self.case3_step4[key][1] in re

        # 移除掉acl策略并检查结果
        fun.send(Exc_rmb, message.DelAclPolicy_HitCount['DelAclPolicy'], domain_rmb, base_path)

    # for key in self.case3_step5:
    # 	re = fun.cmd(self.case3_step5[key][0], 'gw')
    # 	print('re:', re)
    # 	assert self.case3_step5[key][1] in re

    def teardown_class(self):
        # 回收环境
        clr_env.clear_env()
        fun.rbm_close()
        fun.ssh_close('gw')
