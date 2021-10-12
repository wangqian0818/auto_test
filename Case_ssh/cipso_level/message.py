from common import baseinfo
from cipso_level import index
import time
import json
datatime = time.strftime('%Y-%m-%d %H:%M:%S',time.localtime(time.time()))
cardid0=baseinfo.gwCard0
attack_port = index.attack_port
pcap_dip = baseinfo.serverOpeIp
pcap_sip = baseinfo.clientOpeIp

