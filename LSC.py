import requests
import jxmlease
import datetime
import time
import os
import sys
import csv

def request_maker(query):
  payload = query
  response = requests.request("POST", url, headers=headers, data=payload, verify=False)
  response = response.text.encode('utf8')
  root = jxmlease.parse(response)
  return root

def security_level():
  payload = "<soapenv:Envelope xmlns:soapenv=\"http://schemas.xmlsoap.org/soap/envelope/\" xmlns:ns=\"http://www.cisco.com/AXL/API/11.5\">\r\n   <soapenv:Header/>\r\n   <soapenv:Body>\r\n      <ns:executeSQLQuery sequence=\"?\">\r\n         <sql>\r\n         select paramname,paramvalue from processconfig where paramname='ClusterSecurityMode'\r\n         </sql>\r\n      </ns:executeSQLQuery>\r\n   </soapenv:Body>\r\n</soapenv:Envelope>"
  root = request_maker(payload)
  final_output = root['soapenv:Envelope']['soapenv:Body']['ns:executeSQLQueryResponse']['return']['row']
  if final_output['paramvalue'] == '0':
    file1.write("\nCluster Security Mode : Non secure \n")
  else:
    file1.write("\nCluster Security Mode : Mixed Mode\n ")

def lsc_checker():
  #This function checks the LSC validity of the IP phones
  payload = "<soapenv:Envelope xmlns:soapenv=\"http://schemas.xmlsoap.org/soap/envelope/\" xmlns:ns=\"http://www.cisco.com/AXL/API/11.5\">\r\n   <soapenv:Header/>\r\n   <soapenv:Body>\r\n      <ns:executeSQLQuery sequence=\"?\">\r\n         <sql>\r\n         select name,lscvaliduntil from device where lscissuername IS NOT NULL\r\n         </sql>\r\n      </ns:executeSQLQuery>\r\n   </soapenv:Body>\r\n</soapenv:Envelope>"
  root = request_maker(payload)
  final_output = root['soapenv:Envelope']['soapenv:Body']['ns:executeSQLQueryResponse']['return']['row']
  file1.write("\nLSC Status of the Phones is stored in file LSC_Status.txt")
  LSC_Status = open("LSC_Status.txt", "w")
  for i in final_output:
    i['lscvaliduntil'] = str(datetime.datetime.fromtimestamp(int(i['lscvaliduntil'])))
    LSC_Status.write("MAC Address: " + i['name'] + "\tLSC Valid Till: " +  i['lscvaliduntil'] + "\n")
  LSC_Status.close()

def EM_checker():
  #This function checks the number of devices which has extenstion mobility enabled.
  payload_count = "<soapenv:Envelope xmlns:soapenv=\"http://schemas.xmlsoap.org/soap/envelope/\" xmlns:ns=\"http://www.cisco.com/AXL/API/11.5\">\r\n   <soapenv:Header/>\r\n   <soapenv:Body>\r\n      <ns:executeSQLQuery sequence=\"?\">\r\n         <sql>\r\n        select count(*) from extensionmobilitydynamic\r\n         </sql>\r\n      </ns:executeSQLQuery>\r\n   </soapenv:Body>\r\n</soapenv:Envelope>"
  payload_devices = "<soapenv:Envelope xmlns:soapenv=\"http://schemas.xmlsoap.org/soap/envelope/\" xmlns:ns=\"http://www.cisco.com/AXL/API/11.5\">\r\n   <soapenv:Header/>\r\n   <soapenv:Body>\r\n      <ns:executeSQLQuery sequence=\"?\">\r\n         <sql>\r\n        select dv.name from extensionmobilitydynamic emd inner join device dv on emd.fkdevice = dv.pkid\r\n         </sql>\r\n      </ns:executeSQLQuery>\r\n   </soapenv:Body>\r\n</soapenv:Envelope>"
  root_count = request_maker(payload_count)
  root_devices = request_maker(payload_devices)
  final_count = root_count['soapenv:Envelope']['soapenv:Body']['ns:executeSQLQueryResponse']['return']['row']['count']
  file1.write(f'\n\nNumber of devices with Extension Mobility Enabled  : {final_count}\n')
  file1.write(f'All the Devices with Extension Mobility Enabled are stored in EM_devices.txt\n\n')
  final_devices = root_devices['soapenv:Envelope']['soapenv:Body']['ns:executeSQLQueryResponse']['return']['row']
  EM_Devices = open("EM_Devices.txt", "w")
  for i in final_devices:
    EM_Devices.write("\n" + i['name'])
  EM_Devices.close()


def user_info():
  # This function checks the user primary Ext and IPCC Extension
  payload_pri = "<soapenv:Envelope xmlns:soapenv=\"http://schemas.xmlsoap.org/soap/envelope/\" xmlns:ns=\"http://www.cisco.com/AXL/API/11.5\">\r\n   <soapenv:Header/>\r\n   <soapenv:Body>\r\n      <ns:executeSQLQuery sequence=\"?\">\r\n         <sql>\r\n         select eu.userid, np.dnorpattern as PrimaryLine from EndUserNumPlanMap as eunpm inner join enduser as eu on eu.pkid = eunpm.fkenduser inner join numplan as np on np.pkid = eunpm.fknumplan where eunpm.tkdnusage = '1' order by eu.userid\r\n         </sql>\r\n      </ns:executeSQLQuery>\r\n   </soapenv:Body>\r\n</soapenv:Envelope>"
  payload_ipcc = "<soapenv:Envelope xmlns:soapenv=\"http://schemas.xmlsoap.org/soap/envelope/\" xmlns:ns=\"http://www.cisco.com/AXL/API/11.5\">\r\n   <soapenv:Header/>\r\n   <soapenv:Body>\r\n      <ns:executeSQLQuery sequence=\"?\">\r\n         <sql>\r\n        select eu.userid, np.dnorpattern as PrimaryLine from EndUserNumPlanMap as eunpm inner join enduser as eu on eu.pkid = eunpm.fkenduser inner join numplan as np on np.pkid = eunpm.fknumplan where eunpm.tkdnusage = '2' order by eu.userid\r\n         </sql>\r\n      </ns:executeSQLQuery>\r\n   </soapenv:Body>\r\n</soapenv:Envelope>"
  root_pri = request_maker(payload_pri)
  root_ipcc = request_maker(payload_ipcc)
  final_output_pri = root_pri['soapenv:Envelope']['soapenv:Body']['ns:executeSQLQueryResponse']['return']['row']
  final_output_ipcc = root_ipcc['soapenv:Envelope']['soapenv:Body']['ns:executeSQLQueryResponse']['return']['row']

  file1.write("Number of users with primary Extension: " + str(len(final_output_pri)))
  file1.write("\nAll the users and their primary Ext details are stored in file Pri_Ext_user.txt")
  Pri_Ext_user = open("Pri_Ext_user.txt", "w")
  for i in final_output_pri:
    Pri_Ext_user.write("\nUser ID : " + i['userid'] + "\t\tPrimary Line: " + i['primaryline'])

  Pri_Ext_user.close()

  file1.write("\n\nNumber of users with IPCC Extension: " + str(len(final_output_ipcc)))
  file1.write("\nAll the users and their IPCC Ext details are stored in file IPCC_Ext_user.txt")
  IPCC_Ext_user = open("IPCC_Ext_user.txt", "w")
  for i in final_output_ipcc:
    IPCC_Ext_user.write("\nUser ID : " + i['userid'] + "\t\tIPCC Line: " + i['primaryline'])
  IPCC_Ext_user.close()


url = "https://10.106.88.226:8443/axl/"
headers = {
  'Authorization': 'Basic YXhsdXNlcjpjaXNjbw=='
}
file1= open("output.txt", "w")
file1.write("\t\tPlease check the output Below \n\n")
file1.close()
file1 = open("output.txt", "a")
security_level()
lsc_checker()
EM_checker()
user_info()
file1.close()

#comment1231






