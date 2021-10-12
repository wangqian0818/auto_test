# coding:utf-8
# 此文件的参数配置均与用例强相关，与执行环境无关
# 适用用例范围

from common import baseinfo

pcap_sip = baseinfo.clientOpeIp
pcap_dip = baseinfo.serverOpeIp
ciface = baseinfo.pcapSendIface
siface = baseinfo.pcapReadIface
strip = baseinfo.strip
card_id0 = baseinfo.gwCard0
dport = "2299"
sport = "2288"

SeLabelLevel_ACL_labelRejectPac = 1
SeLabelLevel_common = 14
SeLabelBitmap = '0x3,0x0,0x0,0x0'
QosThreshold_QosData = '1000,100'
QosThreshold_QosRate = '300,300'

c_num = 12
# 获取acl命中统计数HitCount"
hit_count = {"HitCount": c_num}
for key, value in hit_count.items():
    hitcount_num = '"' + key + '"' + ':' + '"' + str(value) + '"'


# 获取acl拒绝包统计数labelRejectPac
labelRejectPac = {"LabelRejectPac": c_num}
for key, value in labelRejectPac.items():
    labelRejectPac_num = '"' + key + '"' + ':' + str(value)
    # print(labelRejectPac_num)

# 获取acl允许包统计数labelPassPac
labelPassPac = {"LabelPassPac": c_num * 2}
for key, value in labelPassPac.items():
    labelPassPac_num = '"' + key + '"' + ':' + str(value)
    # print(labelPassPac_num)

# 获取acl单桶qos限量策略,上下行通过、丢弃包数统计QosPassUpPac\QosDropUpPac\QosPassDownPac\QosDropDownPac
qos = {"QosPassUpPac": c_num - 1}
for key, value in qos.items():
    qos_data = '"' + key + '"' + ':' + str(value)
    # print(qos_data)

# 获取acl单桶qos限速策略,上下行通过、丢弃包数统计QosPassUpPac\QosDropUpPac\QosPassDownPac\QosDropDownPac
qos = {"QosPassUpPac": 6}
for key, value in qos.items():
    qos_rate = '"' + key + '"' + ':' + str(value)
    # print(qos_rate)

# 报文发送,读取和预期结果
# 列表里面的命令依次为：
# 发送端：发送报文接口，发送报文数量，发送报文名称；
# 抓包：接口名称，过滤规则，抓包数量，报文命名（以用例名称.pcap命名）
# 报文读取：保存的报文名称，要读取的包的序号；这里读取的报文名称和上面抓包的保存报文名称应该一致
# 期望结果：预期结果（协议字段），是否有偏差（保留），偏差值（保留）

pkt1_cfg = {
    "send": [ciface, c_num, "0002_TCP_ETH_IPV4_TCP_p2299.pcap"],
    "capture": [siface, f"tcp and host {pcap_dip}", 1, "test_report_acl_count.pcap"],
    "read": ["test_report_acl_count.pcap", 0],
    "expect": [strip, 0, 0]
}
pkt2_cfg = {
    "send": [ciface, c_num, "0002_TCP_ETH_IPV4_TCP__16_14_p2299_0x3.pcap"],
    # "capture":[siface,f"tcp and host {pcap_dip}",1,"test_report_acl_labelRejectPac_count.pcap"],
    # "read":["test_report_acl_labelRejectPac_count.pcap",0],
    # "expect":[strip,0,0]
}
pkt3_cfg = {
    "send": [ciface, c_num, "0002_TCP_ETH_IPV4_TCP__16_14_p2299_0x3.pcap"],
    "capture": [siface, f"tcp and host {pcap_dip}", 1, "test_report_acl_labelPassPac_count.pcap"],
    "read": ["test_report_acl_labelPassPac_count", 0],
    "expect": [strip, 0, 0]
}
pkt4_cfg = {
    "send": [ciface, c_num, "0002_TCP_ETH_IPV4_TCP_p2299.pcap"],
    "capture": [siface, f"tcp and host {pcap_dip}", 1, "test_report_acl_QosData_updown_PassDrop_count.pcap"],
    "read": ["test_report_acl_QosData_updown_PassDrop_count", 0],
    "expect": [strip, 0, 0]
}
pkt5_cfg = {
    "send": [ciface, c_num, "0002_TCP_ETH_IPV4_TCP_p2299.pcap"],
    "capture": [siface, f"tcp and host {pcap_dip}", 1, "test_report_acl_QosRate_updown_PassDrop_count.pcap"],
    "read": ["test_report_acl_QosRate_updown_PassDrop_count", 0],
    "expect": [strip, 0, 0]
}
# 配置下发
# 列表里面的顺序依次为：配置命令，查询命令，预期结果
case1_step1={
    "step1": ['export cardid=0&&defconf --show',  'ipv4acl report: on' ]
}

case1_step2 = {
    "step1": ['export cardid=0&&tupleacl --get',  pcap_dip]
}

case1_step3 = {
    "step1":[hitcount_num]
}

case1_step4={
    "step1": ['export cardid=0&&defconf --show',  'ipv4acl report: off' ]
}

case1_step5 = {
    "step1": ['export cardid=0&&tupleacl --get', '<GET|DEL|ADD> 0 rules']
}




case2_step1 = {
    "step1": ['export cardid=0&&defconf --show','ipv4acl report: on']
}

case2_step2 = {
    "step1": ['export cardid=0&&tupleacl --get',  pcap_dip]
}

case2_step3 = {
    "step1": [labelRejectPac_num]
}

case2_step4={
    "step1": ['export cardid=0&&defconf --show',  'ipv4acl report: off' ]
}

case2_step5 = {
    "step1": ['export cardid=0&&tupleacl --get', '<GET|DEL|ADD> 0 rules']
}




case3_step1 = {
    "step1": ['export cardid=0&&defconf --show','ipv4acl report: on']
}

case3_step2 = {
    "step1": ['export cardid=0&&tupleacl --get',  pcap_dip]
}

case3_step3 = {
    "step1": [labelPassPac_num]
}

case3_step4={
    "step1": ['export cardid=0&&defconf --show',  'ipv4acl report: off' ]
}

case3_step5 = {
    "step1": ['export cardid=0&&tupleacl --get', '<GET|DEL|ADD> 0 rules']
}




case4_step1 = {
    "step1": ['export cardid=0&&defconf --show','ipv4acl report: on']
}

case4_step2 = {
    "step1": ['export cardid=0&&tupleacl --get',  pcap_dip]
}

case4_step3 = {
    "step1": [qos_data]
}

case4_step4={
    "step1": ['export cardid=0&&defconf --show',  'ipv4acl report: off' ]
}

case4_step5 = {
    "step1": ['export cardid=0&&tupleacl --get', '<GET|DEL|ADD> 0 rules']
}




case5_step1 = {
    "step1": ['export cardid=0&&defconf --show','ipv4acl report: on']
}

case5_step2 = {
    "step1": ['export cardid=0&&tupleacl --get',  pcap_dip]
}

case5_step3 = {
    "step1": [qos_rate]
}

case5_step4={
    "step1": ['export cardid=0&&defconf --show',  'ipv4acl report: off' ]
}

case5_step5 = {
    "step1": ['export cardid=0&&tupleacl --get', '<GET|DEL|ADD> 0 rules']
}