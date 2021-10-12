from common import baseinfo
from firewall_ddos_attack import index
import time
import json
datatime = time.strftime('%Y-%m-%d %H:%M:%S',time.localtime(time.time()))
cardid0=baseinfo.gwCard0

setddos_open = {
"SetDdosEnable":{
"MethodName":"SetDdosEnable",
 "MessageTime":datatime,
 "Content":[{"Enable":1,"Cards":cardid0}]
}
}

setddos_close = {
"SetDdosEnable":{
"MethodName":"SetDdosEnable",
 "MessageTime":datatime,
 "Content":[{"Enable":0,"Cards":cardid0}]
}
}