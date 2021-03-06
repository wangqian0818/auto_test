'''
说明：根证书有效期Validity，若证书失效需替换
      Not Before: Jun 30 02:38:56 2020 GMT
      Not After : Jun 30 02:38:56 2023 GMT
'''
from common import baseinfo
import time
from verifymod_expired_cert import index


datatime = time.strftime('%Y-%m-%d %H:%M:%S',time.localtime(time.time()))
verifymod_ip = baseinfo.gwClientIp
verifymod_port = index.verifymod_port
expired_cert_md5 = index.expired_cert_md5
cert_md5 = index.cert_md5


verifymod_switch_start = {
"ManageAuthServer":{
"MethodName":"ManageAuthServer",
"MessageTime":datatime,
"Sender":"Centre0",
"Content":[{
    "AuthServerIp":verifymod_ip,
    "AuthServerPort":verifymod_port,
    "Enable":1}]
}
}

verifymod_switch_stop = {
"ManageAuthServer":{
"MethodName":"ManageAuthServer",
"MessageTime":datatime,
"Sender":"Centre0",
"Content":[{
    "AuthServerIp":"",
    "Enable":0}]
}
}


verifymod_expired_AddAuthCert = {
"AddAuthCert":{
"MethodName":"AddAuthCert",
"MessageTime":datatime,
"Sender":"Centre0",
"Content":[{
    "Bytes":"Q2VydGlmaWNhdGU6CiAgICBEYXRhOgogICAgICAgIFZlcnNpb246IDMgKDB4MikKICAgICAgICBTZXJpYWwgTnVtYmVyOgogICAgICAgICAgICBjODo3ZToyZTo1MzpjYzo1NDpkYzpmZAogICAgU2lnbmF0dXJlIEFsZ29yaXRobTogc2hhMjU2V2l0aFJTQUVuY3J5cHRpb24KICAgICAgICBJc3N1ZXI6IEM9Q04sIFNUPWFuaHVpLCBPPWp1c29udGVjaCwgT1U9dGVzdCwgQ049dGVzdC5jbi9lbWFpbEFkZHJlc3M9bWFkYW5kYW5AanVzb250ZWNoLmNvbQogICAgICAgIFZhbGlkaXR5CiAgICAgICAgICAgIE5vdCBCZWZvcmU6IEp1bCAgNSAxNjo1NjoyMCAyMDE1IEdNVAogICAgICAgICAgICBOb3QgQWZ0ZXIgOiBKdWwgIDQgMTY6NTY6MjAgMjAxNiBHTVQKICAgICAgICBTdWJqZWN0OiBDPUNOLCBTVD1hbmh1aSwgTz1qdXNvbnRlY2gsIE9VPXRlc3QsIENOPXRlc3QuY24vZW1haWxBZGRyZXNzPW1hZGFuZGFuQGp1c29udGVjaC5jb20KICAgICAgICBTdWJqZWN0IFB1YmxpYyBLZXkgSW5mbzoKICAgICAgICAgICAgUHVibGljIEtleSBBbGdvcml0aG06IHJzYUVuY3J5cHRpb24KICAgICAgICAgICAgICAgIFB1YmxpYy1LZXk6ICgyMDQ4IGJpdCkKICAgICAgICAgICAgICAgIE1vZHVsdXM6CiAgICAgICAgICAgICAgICAgICAgMDA6ZTY6NzM6MmU6NWE6ZmY6OWY6OWY6M2E6NzA6ZDI6NzM6ZjU6OGU6ODc6CiAgICAgICAgICAgICAgICAgICAgM2Y6MDc6MDA6Mzk6NTc6NzA6MmE6MTA6YTY6MjE6MTQ6MGM6NzY6MDY6YTg6CiAgICAgICAgICAgICAgICAgICAgZTk6ZWE6YWI6YTA6ZmM6MDA6YzU6M2U6OTU6ZDM6Yjc6Njk6NTg6OTE6ZDc6CiAgICAgICAgICAgICAgICAgICAgNjc6MmE6MTM6YmQ6YjQ6NTk6NmM6Yzc6ZWE6MWY6MGU6YTY6NjA6ZDg6NDg6CiAgICAgICAgICAgICAgICAgICAgNWM6MTc6ZmU6Y2U6MTk6NjU6MzY6Zjg6OGY6MmM6YzA6ZDI6YjY6YmM6OWI6CiAgICAgICAgICAgICAgICAgICAgMTE6MzI6NTY6M2U6MDQ6MTg6MDE6NTg6YTU6MGE6MGU6YTI6NzQ6Y2I6YjY6CiAgICAgICAgICAgICAgICAgICAgY2U6YzI6ZDg6OWE6Yzc6YWM6OTQ6MzM6Nzc6ZGI6ZTA6NDU6NGE6NGY6MWY6CiAgICAgICAgICAgICAgICAgICAgNmE6ODQ6YmY6MGU6Nzg6ZjE6MWU6ZDg6ZDQ6ZmY6M2Q6Yjk6NWI6NGY6ZDY6CiAgICAgICAgICAgICAgICAgICAgNTI6YjI6ZTg6MGQ6ZTM6Zjc6ZTY6YjE6ODI6OTA6NzE6NzI6ZjQ6ZTk6Njk6CiAgICAgICAgICAgICAgICAgICAgMjc6NGM6Nzg6YWI6NTA6ODE6ZWY6ZjI6NjA6MjA6MmQ6YTM6ZjI6Nzc6NzM6CiAgICAgICAgICAgICAgICAgICAgNWM6NzU6NDY6YTM6NmQ6NDQ6YzE6NTI6OWQ6M2Y6YWY6ZmM6OGE6Y2Q6Njk6CiAgICAgICAgICAgICAgICAgICAgMzM6NTM6MWI6ODU6ZTI6NGM6N2Y6OTM6Y2U6YWI6MzM6Yzk6MTY6Yzg6ZGM6CiAgICAgICAgICAgICAgICAgICAgZTQ6Mjc6NmI6NDI6MDI6YTQ6Zjk6NDU6Mjg6Njc6OWY6Y2I6OGY6MjE6OTg6CiAgICAgICAgICAgICAgICAgICAgNmY6M2U6ODM6MGI6ZGE6OTE6NmE6ZGI6MzI6NDA6ZGE6ZGE6YmI6YzY6NzU6CiAgICAgICAgICAgICAgICAgICAgMzU6NTQ6NWU6YmM6MTM6Yjc6MmQ6NGM6Yzc6YWE6MTY6MGM6MmQ6NmQ6N2Y6CiAgICAgICAgICAgICAgICAgICAgNjk6MWE6ZjU6NzY6Yzc6NzI6ZGI6YjQ6MDQ6NTc6NDU6ZDI6ZjQ6YTA6Yzk6CiAgICAgICAgICAgICAgICAgICAgNGM6OTE6ODE6OTg6OWU6NDQ6MjE6ZTU6ZWM6Mjc6MjI6MWM6Y2U6YmU6ZGE6CiAgICAgICAgICAgICAgICAgICAgMjQ6YzUKICAgICAgICAgICAgICAgIEV4cG9uZW50OiA2NTUzNyAoMHgxMDAwMSkKICAgICAgICBYNTA5djMgZXh0ZW5zaW9uczoKICAgICAgICAgICAgWDUwOXYzIEJhc2ljIENvbnN0cmFpbnRzOiAKICAgICAgICAgICAgICAgIENBOlRSVUUKICAgICAgICAgICAgTmV0c2NhcGUgQ29tbWVudDogCiAgICAgICAgICAgICAgICBPcGVuU1NMIEdlbmVyYXRlZCBDZXJ0aWZpY2F0ZQogICAgICAgICAgICBYNTA5djMgU3ViamVjdCBLZXkgSWRlbnRpZmllcjogCiAgICAgICAgICAgICAgICAxRTpCMTpEQjo0RDoyODo1MTpGMDpGNToxNzpDQzo5NTpDMjpEMTo2Qzo3Mzo2Rjo1Qzo3ODo4MTpGQgogICAgICAgICAgICBYNTA5djMgQXV0aG9yaXR5IEtleSBJZGVudGlmaWVyOiAKICAgICAgICAgICAgICAgIGtleWlkOjFFOkIxOkRCOjREOjI4OjUxOkYwOkY1OjE3OkNDOjk1OkMyOkQxOjZDOjczOjZGOjVDOjc4OjgxOkZCCgogICAgU2lnbmF0dXJlIEFsZ29yaXRobTogc2hhMjU2V2l0aFJTQUVuY3J5cHRpb24KICAgICAgICAgZDg6MDg6ZWE6MTA6YjI6ZWM6OTc6MGQ6NzM6NTU6YzU6N2Y6NGI6M2U6MTk6YjU6MjU6OTQ6CiAgICAgICAgIGM3OjhhOjhmOjQ5OmVhOmFmOmIzOjc3OjA0OjIwOjJkOjgzOjI1OmEwOmQ0OjEzOmJkOjZlOgogICAgICAgICA4YjoxYzpiMzpjNTphMDo3Yzo1MDoxNjpkMTo5MDpmNTplOTpiZDozMDo4ZTpmMzo4NDo5NDoKICAgICAgICAgODI6ZWY6MDk6Y2Y6ZjA6ZjY6NzU6MGQ6MGU6NWE6YTk6NGI6OGU6ZjA6YWI6OGU6MzM6NTI6CiAgICAgICAgIGRmOjc1OjllOjRhOmY4OjkzOmU5OmUxOjE4Ojc3Ojg0OjY1OmE5OjBiOjA5OjM1OmQ4OmEzOgogICAgICAgICAzMzplMTpiODpkZTo5ZDoxYzowMzo2NTo2ZDo4MzplODo4NDpjMDoyYjowMzo4MzozMzoyMDoKICAgICAgICAgNTM6YzM6OTI6NWI6MmI6NGY6ZDQ6YjQ6ODg6MzI6YmQ6YzA6MzI6Yjk6NTc6ZjI6Mjg6ZWM6CiAgICAgICAgIGFjOjEzOmQxOmRkOjFkOmNmOjI0OjY4OmU4OmIwOmQyOjM4OmFlOjdiOjViOmE5OjgxOmE0OgogICAgICAgICBlZjo3ZDo0ZDplNzo4ZToyZTpjZDo4MDo4ODpkMzoxZDplMDoxNzphNjpjOTphYzpkMzplMDoKICAgICAgICAgNjc6N2M6NTg6NzE6YWQ6MWE6NDA6OTI6ZTE6Nzg6YmM6NTI6Y2E6ZjE6MWI6M2Q6ODM6NDg6CiAgICAgICAgIDQ3Ojc0OjYxOjcxOmQ4OmU3OjdkOjliOjUzOmRkOjVjOmE1OmQwOjQ2OmFlOjFkOjA0OmE2OgogICAgICAgICBkYzplNDpiNToxNzo0YjowNTo1ODoxOTplZjo3Mzo2NzpjNjo2Yjo2ODpjZTo5NDowMjplNDoKICAgICAgICAgNWM6OGU6OGI6NWI6ODE6MTQ6MTQ6ZmM6NWM6MTY6NzI6OGY6ZDg6NTY6YTk6NTA6YWQ6MDk6CiAgICAgICAgIDQ0OjQ4OjVkOjA0OjU4OmJmOmY4OmRkOjlhOjQxOmJhOmVhOmUyOmE4OjQwOjRhOmM0OjQzOgogICAgICAgICAxMjo2MDo5MTpkNwotLS0tLUJFR0lOIENFUlRJRklDQVRFLS0tLS0KTUlJRDh6Q0NBdHVnQXdJQkFnSUpBTWgrTGxQTVZOejlNQTBHQ1NxR1NJYjNEUUVCQ3dVQU1Ia3hDekFKQmdOVgpCQVlUQWtOT01RNHdEQVlEVlFRSURBVmhibWgxYVRFU01CQUdBMVVFQ2d3SmFuVnpiMjUwWldOb01RMHdDd1lEClZRUUxEQVIwWlhOME1SQXdEZ1lEVlFRRERBZDBaWE4wTG1OdU1TVXdJd1lKS29aSWh2Y05BUWtCRmhadFlXUmgKYm1SaGJrQnFkWE52Ym5SbFkyZ3VZMjl0TUI0WERURTFNRGN3TlRFMk5UWXlNRm9YRFRFMk1EY3dOREUyTlRZeQpNRm93ZVRFTE1Ba0dBMVVFQmhNQ1EwNHhEakFNQmdOVkJBZ01CV0Z1YUhWcE1SSXdFQVlEVlFRS0RBbHFkWE52CmJuUmxZMmd4RFRBTEJnTlZCQXNNQkhSbGMzUXhFREFPQmdOVkJBTU1CM1JsYzNRdVkyNHhKVEFqQmdrcWhraUcKOXcwQkNRRVdGbTFoWkdGdVpHRnVRR3AxYzI5dWRHVmphQzVqYjIwd2dnRWlNQTBHQ1NxR1NJYjNEUUVCQVFVQQpBNElCRHdBd2dnRUtBb0lCQVFEbWN5NWEvNStmT25EU2MvV09oejhIQURsWGNDb1FwaUVVREhZR3FPbnFxNkQ4CkFNVStsZE8zYVZpUjEyY3FFNzIwV1d6SDZoOE9wbURZU0Z3WC9zNFpaVGI0anl6QTByYThteEV5Vmo0RUdBRlkKcFFvT29uVEx0czdDMkpySHJKUXpkOXZnUlVwUEgycUV2dzU0OFI3WTFQODl1VnRQMWxLeTZBM2o5K2F4Z3BCeApjdlRwYVNkTWVLdFFnZS95WUNBdG8vSjNjMXgxUnFOdFJNRlNuVCt2L0lyTmFUTlRHNFhpVEgrVHpxc3p5UmJJCjNPUW5hMElDcFBsRktHZWZ5NDhobUc4K2d3dmFrV3JiTWtEYTJydkdkVFZVWHJ3VHR5MU14Nm9XREMxdGYya2EKOVhiSGN0dTBCRmRGMHZTZ3lVeVJnWmllUkNIbDdDY2lITTYrMmlURkFnTUJBQUdqZmpCOE1Bd0dBMVVkRXdRRgpNQU1CQWY4d0xBWUpZSVpJQVliNFFnRU5CQjhXSFU5d1pXNVRVMHdnUjJWdVpYSmhkR1ZrSUVObGNuUnBabWxqCllYUmxNQjBHQTFVZERnUVdCQlFlc2R0TktGSHc5UmZNbGNMUmJITnZYSGlCK3pBZkJnTlZIU01FR0RBV2dCUWUKc2R0TktGSHc5UmZNbGNMUmJITnZYSGlCK3pBTkJna3Foa2lHOXcwQkFRc0ZBQU9DQVFFQTJBanFFTExzbHcxegpWY1YvU3o0WnRTV1V4NHFQU2VxdnMzY0VJQzJESmFEVUU3MXVpeHl6eGFCOFVCYlJrUFhwdlRDTzg0U1VndThKCnovRDJkUTBPV3FsTGp2Q3Jqak5TMzNXZVN2aVQ2ZUVZZDRSbHFRc0pOZGlqTStHNDNwMGNBMlZ0ZytpRXdDc0QKZ3pNZ1U4T1NXeXRQMUxTSU1yM0FNcmxYOGlqc3JCUFIzUjNQSkdqb3NOSTRybnRicVlHazczMU41NDR1ellDSQoweDNnRjZiSnJOUGdaM3hZY2EwYVFKTGhlTHhTeXZFYlBZTklSM1JoY2RqbmZadFQzVnlsMEVhdUhRU20zT1MxCkYwc0ZXQm52YzJmR2Eyak9sQUxrWEk2TFc0RVVGUHhjRm5LUDJGYXBVSzBKUkVoZEJGaS8rTjJhUWJycTRxaEEKU3NSREVtQ1Ixdz09Ci0tLS0tRU5EIENFUlRJRklDQVRFLS0tLS0K",
    "Md5":expired_cert_md5}]
}
}

verifymod_expired_DelAuthCert = {
"DelAuthCert":{
"MethodName":"DelAuthCert",
"MessageTime":datatime,
"Sender":"Centre0",
"Content":[{
    "Md5": expired_cert_md5}]
}
}


verifymod_AddAuthCert = {
"AddAuthCert":{
"MethodName":"AddAuthCert",
"MessageTime":datatime,
"Sender":"Centre0",
"Content":[{
    "Bytes":"Q2VydGlmaWNhdGU6CiAgICBEYXRhOgogICAgICAgIFZlcnNpb246IDMgKDB4MikKICAgICAgICBTZXJpYWwgTnVtYmVyOgogICAgICAgICAgICBjODo3ZToyZTo1MzpjYzo1NDpkYzpmNAogICAgU2lnbmF0dXJlIEFsZ29yaXRobTogc2hhMjU2V2l0aFJTQUVuY3J5cHRpb24KICAgICAgICBJc3N1ZXI6IEM9Q04sIFNUPWFuaHVpLCBPPWp1c29udGVjaCwgT1U9dGVzdCwgQ049dGVzdC5jbi9lbWFpbEFkZHJlc3M9bWFkYW5kYW5AanVzb250ZWNoLmNvbQogICAgICAgIFZhbGlkaXR5CiAgICAgICAgICAgIE5vdCBCZWZvcmU6IEp1biAzMCAwMjozODo1NiAyMDIwIEdNVAogICAgICAgICAgICBOb3QgQWZ0ZXIgOiBKdW4gMzAgMDI6Mzg6NTYgMjAyMyBHTVQKICAgICAgICBTdWJqZWN0OiBDPUNOLCBTVD1hbmh1aSwgTz1qdXNvbnRlY2gsIE9VPXRlc3QsIENOPXRlc3QuY24vZW1haWxBZGRyZXNzPW1hZGFuZGFuQGp1c29udGVjaC5jb20KICAgICAgICBTdWJqZWN0IFB1YmxpYyBLZXkgSW5mbzoKICAgICAgICAgICAgUHVibGljIEtleSBBbGdvcml0aG06IHJzYUVuY3J5cHRpb24KICAgICAgICAgICAgICAgIFB1YmxpYy1LZXk6ICgyMDQ4IGJpdCkKICAgICAgICAgICAgICAgIE1vZHVsdXM6CiAgICAgICAgICAgICAgICAgICAgMDA6ZTY6NzM6MmU6NWE6ZmY6OWY6OWY6M2E6NzA6ZDI6NzM6ZjU6OGU6ODc6CiAgICAgICAgICAgICAgICAgICAgM2Y6MDc6MDA6Mzk6NTc6NzA6MmE6MTA6YTY6MjE6MTQ6MGM6NzY6MDY6YTg6CiAgICAgICAgICAgICAgICAgICAgZTk6ZWE6YWI6YTA6ZmM6MDA6YzU6M2U6OTU6ZDM6Yjc6Njk6NTg6OTE6ZDc6CiAgICAgICAgICAgICAgICAgICAgNjc6MmE6MTM6YmQ6YjQ6NTk6NmM6Yzc6ZWE6MWY6MGU6YTY6NjA6ZDg6NDg6CiAgICAgICAgICAgICAgICAgICAgNWM6MTc6ZmU6Y2U6MTk6NjU6MzY6Zjg6OGY6MmM6YzA6ZDI6YjY6YmM6OWI6CiAgICAgICAgICAgICAgICAgICAgMTE6MzI6NTY6M2U6MDQ6MTg6MDE6NTg6YTU6MGE6MGU6YTI6NzQ6Y2I6YjY6CiAgICAgICAgICAgICAgICAgICAgY2U6YzI6ZDg6OWE6Yzc6YWM6OTQ6MzM6Nzc6ZGI6ZTA6NDU6NGE6NGY6MWY6CiAgICAgICAgICAgICAgICAgICAgNmE6ODQ6YmY6MGU6Nzg6ZjE6MWU6ZDg6ZDQ6ZmY6M2Q6Yjk6NWI6NGY6ZDY6CiAgICAgICAgICAgICAgICAgICAgNTI6YjI6ZTg6MGQ6ZTM6Zjc6ZTY6YjE6ODI6OTA6NzE6NzI6ZjQ6ZTk6Njk6CiAgICAgICAgICAgICAgICAgICAgMjc6NGM6Nzg6YWI6NTA6ODE6ZWY6ZjI6NjA6MjA6MmQ6YTM6ZjI6Nzc6NzM6CiAgICAgICAgICAgICAgICAgICAgNWM6NzU6NDY6YTM6NmQ6NDQ6YzE6NTI6OWQ6M2Y6YWY6ZmM6OGE6Y2Q6Njk6CiAgICAgICAgICAgICAgICAgICAgMzM6NTM6MWI6ODU6ZTI6NGM6N2Y6OTM6Y2U6YWI6MzM6Yzk6MTY6Yzg6ZGM6CiAgICAgICAgICAgICAgICAgICAgZTQ6Mjc6NmI6NDI6MDI6YTQ6Zjk6NDU6Mjg6Njc6OWY6Y2I6OGY6MjE6OTg6CiAgICAgICAgICAgICAgICAgICAgNmY6M2U6ODM6MGI6ZGE6OTE6NmE6ZGI6MzI6NDA6ZGE6ZGE6YmI6YzY6NzU6CiAgICAgICAgICAgICAgICAgICAgMzU6NTQ6NWU6YmM6MTM6Yjc6MmQ6NGM6Yzc6YWE6MTY6MGM6MmQ6NmQ6N2Y6CiAgICAgICAgICAgICAgICAgICAgNjk6MWE6ZjU6NzY6Yzc6NzI6ZGI6YjQ6MDQ6NTc6NDU6ZDI6ZjQ6YTA6Yzk6CiAgICAgICAgICAgICAgICAgICAgNGM6OTE6ODE6OTg6OWU6NDQ6MjE6ZTU6ZWM6Mjc6MjI6MWM6Y2U6YmU6ZGE6CiAgICAgICAgICAgICAgICAgICAgMjQ6YzUKICAgICAgICAgICAgICAgIEV4cG9uZW50OiA2NTUzNyAoMHgxMDAwMSkKICAgICAgICBYNTA5djMgZXh0ZW5zaW9uczoKICAgICAgICAgICAgWDUwOXYzIFN1YmplY3QgS2V5IElkZW50aWZpZXI6IAogICAgICAgICAgICAgICAgMUU6QjE6REI6NEQ6Mjg6NTE6RjA6RjU6MTc6Q0M6OTU6QzI6RDE6NkM6NzM6NkY6NUM6Nzg6ODE6RkIKICAgICAgICAgICAgWDUwOXYzIEF1dGhvcml0eSBLZXkgSWRlbnRpZmllcjogCiAgICAgICAgICAgICAgICBrZXlpZDoxRTpCMTpEQjo0RDoyODo1MTpGMDpGNToxNzpDQzo5NTpDMjpEMTo2Qzo3Mzo2Rjo1Qzo3ODo4MTpGQgoKICAgICAgICAgICAgWDUwOXYzIEJhc2ljIENvbnN0cmFpbnRzOiAKICAgICAgICAgICAgICAgIENBOlRSVUUKICAgIFNpZ25hdHVyZSBBbGdvcml0aG06IHNoYTI1NldpdGhSU0FFbmNyeXB0aW9uCiAgICAgICAgIDRiOjkyOmNkOjViOjQ4OjcxOmZmOjcwOmYwOjBmOjFhOmY0OmY5OjRlOjcwOmYwOjg1OmI3OgogICAgICAgICBmOTpiYTpkMzplNTo2ZDo0ZTpmYzozNjpmODo4ZDpmMjpkODoyYjpkMjo1MDo0Yjo4ZjowYToKICAgICAgICAgYmQ6OGY6ZmQ6YzU6Yjg6NzU6MmY6ZDg6NTA6M2U6ZmQ6ZWM6ZGU6NzA6MmM6MGY6ZDM6MWI6CiAgICAgICAgIGZkOjZmOmNhOjMxOjBhOmEyOjZmOmVhOjQxOmUyOmRiOjU4OjczOjQyOjBkOjg4OjI0OjY2OgogICAgICAgICAzODo3ZDpmZjpkMDoyMzo3YjphNTozODo5NjpmMTpjYjowYjowNTozMTplZjpmYTpkOToxOToKICAgICAgICAgYjg6OTk6MmE6MGQ6ZGY6YmI6OGQ6ZDM6Njc6ZmU6MmE6NGY6YTA6MDg6YTY6ZmY6NjA6OGQ6CiAgICAgICAgIDEyOjM1OjM3OjZhOjM3OmE3OjNhOmNlOmU3Ojg1OjgzOjczOjM4OmM3OmM2OjMyOmMzOmZiOgogICAgICAgICA4YzplZjpkNjo5Mjo1MDpkNTphNjpjZjo1NDozZDo4NDo0YjoyYjo5YTo4ZTo2MDo5NjoyMToKICAgICAgICAgNzE6ODk6ZjU6ZDY6ZmI6NGY6NWM6M2Q6OGU6Zjg6NTg6MDk6NGU6ZjI6NTM6ZTQ6ODE6Yjc6CiAgICAgICAgIDAwOjNiOjljOmUwOjEwOjM0Ojk3OmVlOjU0OmVkOmZhOjgzOjQ1OjUyOmI5OmI1OjA0OjNlOgogICAgICAgICA0Yzo5ZTpiYjphYzowMToxYzo5ZTo3MTo5ZDowYzo5YTo3Yzo0MTo0NzoyZToyOToxZDo3NjoKICAgICAgICAgY2M6MjE6YWE6Y2Q6OTI6Yzc6ODY6YmU6ZDc6ODQ6M2I6N2Y6YWM6YTI6ODE6ODE6YzQ6MTQ6CiAgICAgICAgIGUxOmRiOjMwOjUyOjgxOjc1OjNjOjIzOjZjOmE2OmJjOjcwOjJiOjJiOmRjOmIzOjU4OmY5OgogICAgICAgICA5MzplMjpjMDo5Zjo3NjowNjowOToyYjoyYTpmMzpiNzowZjo1MTo4ZDozYTpkNzo0MzozZToKICAgICAgICAgOGQ6NTA6MDA6ZmMKLS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSUR4VENDQXEyZ0F3SUJBZ0lKQU1oK0xsUE1WTnowTUEwR0NTcUdTSWIzRFFFQkN3VUFNSGt4Q3pBSkJnTlYKQkFZVEFrTk9NUTR3REFZRFZRUUlEQVZoYm1oMWFURVNNQkFHQTFVRUNnd0phblZ6YjI1MFpXTm9NUTB3Q3dZRApWUVFMREFSMFpYTjBNUkF3RGdZRFZRUUREQWQwWlhOMExtTnVNU1V3SXdZSktvWklodmNOQVFrQkZoWnRZV1JoCmJtUmhia0JxZFhOdmJuUmxZMmd1WTI5dE1CNFhEVEl3TURZek1EQXlNemcxTmxvWERUSXpNRFl6TURBeU16ZzEKTmxvd2VURUxNQWtHQTFVRUJoTUNRMDR4RGpBTUJnTlZCQWdNQldGdWFIVnBNUkl3RUFZRFZRUUtEQWxxZFhOdgpiblJsWTJneERUQUxCZ05WQkFzTUJIUmxjM1F4RURBT0JnTlZCQU1NQjNSbGMzUXVZMjR4SlRBakJna3Foa2lHCjl3MEJDUUVXRm0xaFpHRnVaR0Z1UUdwMWMyOXVkR1ZqYUM1amIyMHdnZ0VpTUEwR0NTcUdTSWIzRFFFQkFRVUEKQTRJQkR3QXdnZ0VLQW9JQkFRRG1jeTVhLzUrZk9uRFNjL1dPaHo4SEFEbFhjQ29RcGlFVURIWUdxT25xcTZEOApBTVUrbGRPM2FWaVIxMmNxRTcyMFdXekg2aDhPcG1EWVNGd1gvczRaWlRiNGp5ekEwcmE4bXhFeVZqNEVHQUZZCnBRb09vblRMdHM3QzJKckhySlF6ZDl2Z1JVcFBIMnFFdnc1NDhSN1kxUDg5dVZ0UDFsS3k2QTNqOStheGdwQngKY3ZUcGFTZE1lS3RRZ2UveVlDQXRvL0ozYzF4MVJxTnRSTUZTblQrdi9Jck5hVE5URzRYaVRIK1R6cXN6eVJiSQozT1FuYTBJQ3BQbEZLR2VmeTQ4aG1HOCtnd3Zha1dyYk1rRGEycnZHZFRWVVhyd1R0eTFNeDZvV0RDMXRmMmthCjlYYkhjdHUwQkZkRjB2U2d5VXlSZ1ppZVJDSGw3Q2NpSE02KzJpVEZBZ01CQUFHalVEQk9NQjBHQTFVZERnUVcKQkJRZXNkdE5LRkh3OVJmTWxjTFJiSE52WEhpQit6QWZCZ05WSFNNRUdEQVdnQlFlc2R0TktGSHc5UmZNbGNMUgpiSE52WEhpQit6QU1CZ05WSFJNRUJUQURBUUgvTUEwR0NTcUdTSWIzRFFFQkN3VUFBNElCQVFCTGtzMWJTSEgvCmNQQVBHdlQ1VG5Ed2hiZjV1dFBsYlU3OE52aU44dGdyMGxCTGp3cTlqLzNGdUhVdjJGQSsvZXplY0N3UDB4djkKYjhveENxSnY2a0hpMjFoelFnMklKR1k0ZmYvUUkzdWxPSmJ4eXdzRk1lLzYyUm00bVNvTjM3dU4wMmYrS2srZwpDS2IvWUkwU05UZHFONmM2enVlRmczTTR4OFl5dy91TTc5YVNVTldtejFROWhFc3JtbzVnbGlGeGlmWFcrMDljClBZNzRXQWxPOGxQa2diY0FPNXpnRURTWDdsVHQrb05GVXJtMUJENU1ucnVzQVJ5ZWNaME1tbnhCUnk0cEhYYk0KSWFyTmtzZUd2dGVFTzMrc29vR0J4QlRoMnpCU2dYVThJMnltdkhBcks5eXpXUG1UNHNDZmRnWUpLeXJ6dHc5UgpqVHJYUXo2TlVBRDgKLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo=",
    "Md5":cert_md5}]
}
}

verifymod_DelAuthCert = {
"DelAuthCert":{
"MethodName":"DelAuthCert",
"MessageTime":datatime,
"Sender":"Centre0",
"Content":[{
    "Md5": cert_md5}]
}
}

