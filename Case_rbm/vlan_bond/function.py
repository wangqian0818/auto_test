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
    from vlan_bond import index
    from vlan_bond import message
    from common import fun
    import common.ssh_wq as c_ssh
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

# del sys.path[0]
# del sys.path[0]
from common import baseinfo
from common import clr_env
from common.rabbitmq import *
from data_check import http_check

datatime = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(time.time()))

rbmDomain = baseinfo.rbmDomain
rbmExc = baseinfo.rbmExc
vlanAOpeIp = baseinfo.vlanAOpeIp
vlanBOpeIp = baseinfo.vlanBOpeIp
gwInternetIp = baseinfo.gwInternetIp
vlanAPwd = baseinfo.vlanAPwd
vlanBPwd = baseinfo.vlanBPwd
gwPwd = baseinfo.gwPwd

class Test_vlan_bond():

    def setup_class(self):
        # 获取参数
        fun.ssh_gw.connect()
        fun.ssh_vlanA.connect()
        fun.ssh_vlanB.connect()
        self.clr_env = clr_env
        self.case1_step1 = index.case1_step1
        self.case1_step2 = index.case1_step2
        self.case1_step11 = index.case1_step11


        clr_env.clear_env()

    def setup_method(self):
        clr_env.clear_met_acl()

    def teardown_method(self):
        clr_env.clear_met_acl()


    @pytest.mark.skip(reseason="skip")
    @allure.feature('验证supervlan和链路聚合结合的测试(ping)')
    def test_vlan_bond_a1(self):

        # 开启switch开关并检查是否开启成功
        for key in self.case1_step1:
            fun.cmd(self.case1_step1[key][0], 'gw')
            re = fun.cmd(self.case1_step1[key][1], 'gw')
            assert self.case1_step1[key][2] in re
        # 下发vlan配置
        fun.send(rbmExc, message.setvlan['SetVlan'], rbmDomain, base_path)
        # 检查配置下发是否成功
        for key in self.case1_step2:
            re = fun.wait_data(self.case1_step2[key][0], 'gw', self.case1_step2[key][1], 'vlan', 100)
            assert self.case1_step2[key][1] in re

        # 测试从设备端ping vlanA设备正常
        resA_cmd = 'ping '+ vlanAOpeIp + ' -c 4'
        print('从设备端ping vlanA设备的命令是：{}'.format(resA_cmd))
        resA = fun.cmd(resA_cmd,'gw')
        print('从设备端ping vlanA的结果为：{}'.format(resA))
        assert '0% packet loss' in resA

        # 测试从vlanA ping设备正常
        dutA_cmd = 'ping ' + gwInternetIp + ' -c 4'
        print('从vlanA ping设备的命令是：{}'.format(dutA_cmd))
        dutA = fun.cmd(dutA_cmd, 'vlanA')
        print('从vlanA ping设备的结果为：{}'.format(dutA))
        assert '0% packet loss' in dutA

        # 测试从设备端ping vlanB设备正常
        resB_cmd = 'ping ' + vlanBOpeIp + ' -c 4'
        print('从设备端ping vlanB设备的命令是：{}'.format(resB_cmd))
        resB = fun.cmd(resB_cmd, 'gw')
        print('从设备端ping vlanB设备的结果为：{}'.format(resB))
        assert '0% packet loss' in resB

        # 测试从vlanB ping设备正常
        dutB_cmd = 'ping ' + gwInternetIp + ' -c 4'
        print('从vlanB ping设备的命令是：{}'.format(dutB_cmd))
        dutB = fun.cmd(dutB_cmd, 'vlanB')
        print('从vlanB ping设备的结果为：{}'.format(dutB))
        assert '0% packet loss' in dutB

        # 还原环境，移除vlan的配置，且关闭vlan的开关
        # 关闭switch开关并检查是否关闭成功
        for key in self.case1_step11:
            fun.cmd(self.case1_step11[key][0], 'gw')
            re = fun.cmd(self.case1_step11[key][1], 'gw')
            assert self.case1_step11[key][2] in re
        # 清空vlan配置
        fun.send(rbmExc, message.delvlan['SetVlan'], rbmDomain, base_path)
        # 检查配置下发是否成功
        for key in self.case1_step2:
            re = fun.wait_data(self.case1_step2[key][0], 'gw', self.case1_step2[key][1], 'vlan', 100,flag='不存在')
            assert self.case1_step2[key][1] not in re


    # @pytest.mark.skip(reseason="skip")
    @allure.feature(' 测试supervlan和bond结合的各种协议报文的连通性测试')
    def test_vlan_bond_a2(self):

        # 开启switch开关并检查是否开启成功
        for key in self.case1_step1:
            fun.cmd(self.case1_step1[key][0], 'gw')
            re = fun.cmd(self.case1_step1[key][1], 'gw')
            assert self.case1_step1[key][2] in re
        # 下发vlan配置
        fun.send(rbmExc, message.setvlan['SetVlan'], rbmDomain, base_path)
        # 检查配置下发是否成功
        for key in self.case1_step2:
            re = fun.wait_data(self.case1_step2[key][0], 'gw', self.case1_step2[key][1], 'vlan', 100)
            assert self.case1_step2[key][1] in re

        # 测试从设备端ping vlanA设备正常
        print('测试从设备端ping vlanA设备正常')
        resA_cmd = 'ping ' + vlanAOpeIp + ' -c 4'
        print('从设备端ping vlanA设备的命令是：{}'.format(resA_cmd))
        resA = fun.cmd(resA_cmd, 'gw')
        print('从设备端ping vlanA的结果为：{}'.format(resA))
        assert '0% packet loss' in resA

        # 测试从vlanB ping设备正常
        dutB_cmd = 'ping ' + gwInternetIp + ' -c 4'
        print('从vlanB ping设备的命令是：{}'.format(dutB_cmd))
        dutB = fun.cmd(dutB_cmd, 'vlanB')
        print('从vlanB ping设备的结果为：{}'.format(dutB))
        assert '0% packet loss' in dutB

        # 测试从vlanA scp传输文件到设备上，应该可以传输成功
        print('测试从vlanA scp传输文件到设备上，应该可以传输成功')
        # 在vlanA的/opt/pkt/路径下创建一个10M大小的文件10M.pdf
        touch_file_cmd = ['cd /opt/pkt', 'dd if=/dev/zero of=vlanA.pdf bs=1M count=10']
        fun.cmd(touch_file_cmd, 'vlanA', list_flag=True)
        # 检查设备文件是否创建成功
        touch_file = fun.search('/opt/pkt', 'pdf', 'vlanA')
        print('检查服务端/opt/pkt/目录下所有以pdf结尾的文件列表为：{}'.format(touch_file))
        assert 'vlanA.pdf' in touch_file
        # 验证从vlanA发送scp命令上传
        scp_cmd = f'sshpass -p {gwPwd} scp /opt/pkt/vlanA.pdf root@{gwInternetIp}:/opt/pkt/'
        print('从vlanA scp传输文件到设备为：{}'.format(scp_cmd))
        fun.cmd(scp_cmd, 'vlanA')
        # 检查文件是否上传成功到设备
        touch_file = fun.search('/opt/pkt', 'pdf', 'gw')
        print('检查客户端/opt/pkt/目录下所有以pdf结尾的文件列表为：{}'.format(touch_file))
        assert 'vlanA.pdf' in touch_file
        # 下载完成后，还原环境，清掉上传到设备的文件
        fun.cmd('rm -f /opt/pkt/vlanA.pdf ', 'gw')
        check_file = fun.search('/opt/pkt', 'pdf', 'gw')
        print('还原环境，vlanA.pdf文件应该不在列表内，列表为{}'.format(check_file))

        # 测试设备scp获取vlanB上的文件，应该可以传输成功
        print('测试设备scp获取vlanB上的文件，应该可以传输成功')
        # 在vlanB的/opt/pkt/路径下创建一个10M大小的文件vlanB.txt
        touch_file_cmd = ['cd /opt/pkt', 'dd if=/dev/zero of=vlanB.txt bs=1M count=10']
        fun.cmd(touch_file_cmd, 'vlanB', list_flag=True)
        # 检查vlanB文件是否创建成功
        touch_file = fun.search('/opt/pkt', 'txt', 'vlanB')
        print('检查服务端/opt/pkt/目录下所有以txt结尾的文件列表为：{}'.format(touch_file))
        assert 'vlanB.txt' in touch_file
        # 验证从设备端发送scp命令下载
        scp_cmd = f'sshpass -p {vlanBPwd} scp root@{vlanBOpeIp}:/opt/pkt/vlanB.txt /opt/pkt/'
        print('scp下载的命令为：{}'.format(scp_cmd))
        fun.cmd(scp_cmd, 'gw')
        # 检查文件是否下载成功到设备
        touch_file = fun.search('/opt/pkt', 'txt', 'gw')
        print('检查客户端/opt/pkt/目录下所有以txt结尾的文件列表为：{}'.format(touch_file))
        assert 'vlanB.txt' in touch_file
        # 下载完成后，还原环境，清掉从vlanB下载的文件
        fun.cmd('rm -f /opt/pkt/vlanB.txt ', 'gw')
        check_file = fun.search('/opt/pkt', 'txt', 'gw')
        print('还原环境，vlanB.txt文件应该不在列表内，列表为{}'.format(check_file))

        # 测试从vlanB往设备上发起http的get请求，应该可以请求成功
        print('测试从vlanB往设备上发起http的get请求，应该可以请求成功')
        # 在设备的/opt/pkt/路径下创建一个10M大小的文件gw.txt
        touch_file_cmd = ['cd /opt/pkt', 'dd if=/dev/zero of=gw.txt bs=1M count=10']
        fun.cmd(touch_file_cmd, 'gw', list_flag=True)
        # 检查gw文件是否创建成功
        touch_file = fun.search('/opt/pkt', 'txt', 'gw')
        print('检查设备/opt/pkt/目录下所有以txt结尾的文件列表为：{}'.format(touch_file))
        assert 'gw.txt' in touch_file
        # 在设备上开启端口占用服务
        port_listen_cmd = ['cd /opt/pkt', 'python3 -m http.server 8889']
        fun.cmd(port_listen_cmd, 'gw', thread=1, list_flag=True)
        # 从vlanB往设备发送get请求，验证vlan下的http协议
        vlanB_url = 'wget -P /opt/pkt/ http://' + gwInternetIp + ':8889/gw.txt'
        print('vlanB请求设备的请求地址为{}'.format(vlanB_url))
        resA = fun.cmd(vlanB_url, 'vlanB')
        print('设备wget请求vlanA.pdf文件的结果是{}：'.format(resA))
        # 检查文件是否下载成功到vlanB
        wget_file = fun.search('/opt/pkt', 'txt', 'gw')
        print('检查vlanB设备/opt/pkt/目录下所有以txt结尾的文件列表为：{}'.format(wget_file))
        assert 'gw.txt' in wget_file
        # 下载完成后，还原环境，清掉vlanB下载的文件
        fun.cmd('rm -f /opt/pkt/gw.txt ', 'vlanB')
        check_file = fun.search('/opt/pkt', 'txt', 'vlanB')
        print('还原环境，gw.txt文件应该不在vlanB设备的列表内，列表为{}'.format(check_file))

        # 测试从设备wget请求下载vlanA的vlanA.pdf文件，应该可以请求成功
        print('测试从设备wget请求下载vlanA的vlanA.pdf文件，应该可以请求成功')
        # 在vlanA上开启端口占用服务
        port_listen_cmd = ['cd /opt/pkt', 'python3 -m http.server 8889']
        fun.cmd(port_listen_cmd, 'vlanA', thread=1, list_flag=True)
        # 发送get请求，验证vlan下的http协议
        vlanA_url = 'wget -P /opt/pkt/ http://' + vlanAOpeIp + ':8889/vlanA.pdf'
        print('设备请求vlanA的请求地址为{}'.format(vlanA_url))
        fun.cmd(vlanA_url, 'gw')
        time.sleep(2)
        # 检查文件是否下载成功到设备
        vlanA_file = fun.search('/opt/pkt', 'pdf', 'gw')
        print('检查客户端/opt/pkt/目录下所有以pdf结尾的文件列表为：{}'.format(vlanA_file))
        assert 'vlanA.pdf' in vlanA_file
        # 下载完成后，还原环境，清掉从vlanA下载的文件
        fun.cmd('rm -f /opt/pkt/vlanA.pdf ', 'gw')
        check_file = fun.search('/opt/pkt', 'pdf', 'gw')
        print('还原环境，vlanA.pdf文件应该不在列表内，列表为{}'.format(check_file))

        # 还原环境，杀掉端口占用的进程，移除vlan的配置，且关闭vlan的开关
        fun.pid_kill('8889',process='python3',gw='vlanA')
        fun.pid_kill('8889', process='python3', gw='gw')
        # 关闭switch开关并检查是否关闭成功
        for key in self.case1_step11:
            fun.cmd(self.case1_step11[key][0], 'gw')
            re = fun.cmd(self.case1_step11[key][1], 'gw')
            assert self.case1_step11[key][2] in re
        # 清空vlan配置
        fun.send(rbmExc, message.delvlan['SetVlan'], rbmDomain, base_path)
        # 检查配置下发是否成功
        for key in self.case1_step2:
            re = fun.wait_data(self.case1_step2[key][0], 'gw', self.case1_step2[key][1], 'vlan', 100,flag='不存在')
            assert self.case1_step2[key][1] not in re


    def teardown_class(self):
        # 回收环境
        clr_env.clear_env()
        fun.pid_kill('8889', process='python3', gw='vlanA')
        fun.pid_kill('8889', process='python3', gw='gw')
        fun.send(rbmExc, message.delvlan['SetVlan'], rbmDomain, base_path)

        fun.rbm_close()
        fun.ssh_close('gw')
        fun.ssh_close('vlanA')
        fun.ssh_close('vlanB')
