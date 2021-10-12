#coding:utf-8


#设置初始环境
#抓包：接口名称，过滤规则，抓包数量，报文命名（以用例名称.pcap命名）
pre_env={
"capture":["enp3s00","tcp",1,"test_a1.pcap"]
}


#配置下发
#列表里面的顺序依次为：配置命令，查询命令，预期结果
case_step={
"step1":["tupleacl --add --dp 8889 --action forward","tupleacl --query --dp 8889","8889"],
"step2":["tupleacl --add --dp 9999 --action forward","tupleacl --query --dp 9999","9999"]
}


#报文发送,读取和预期结果
#列表里面的命令依次为：
#发送端：发送报文接口，发送报文数量，发送报文名称；
#报文读取：保存的报文名称，要读取的包的序号；这里读取的报文名称和上面抓包的保存报文名称应该一致
#期望结果：预期结果（协议字段），是否有偏差（保留），偏差值（保留）
pkt_cfg={
"send":["enp3s00",1,"syn_16_14_3.pcap"],
"read":["test_a1.pcap",0],
"expect":["00",0,0]
}


