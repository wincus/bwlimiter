#!/usr/bin/env python

import os, re, sys
from subprocess import Popen, PIPE, call

class Config:
	pass

c = Config()
c.max = 73400320
c.com = "iptables -L tcpost -nvx  -t mangle"
c.iptablesoutcmd = "iptables %s tcout -t mangle -d %s -j MARK --set-mark %s"
c.iptablesforwardcmd = "iptables %s tcfor -t mangle -s ! 10.0.0.0/255.0.0.0 -d %s -j MARK --set-mark %s"
c.pattern = "^\s+(?P<packets>\d+)\s+(?P<bytes>\d+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+0x(?P<hex>\w+)/0xff.*"
c.bytes = "bytes"
c.hex = "hex"
c.net = "192.168.10."
c.excluded = ["192.168.10.254"]
c.blocked = []
c.excludefile = "/var/local/ips-excluidas"
c.excludetempfile = "/var/local/ips-excluidas-temporales"
c.blockedfile = "/var/local/ips-bloqueadas"
c.agot = "0xfe"
c.dono = True
c.log = "/var/log/bw-limiter.log"
c.debug = True

logfile = open(c.log, "a")

if os.path.isfile(c.excludefile):
	fd = open(c.excludefile,"r")
	for line in fd.readlines():
		if len(line.strip()) > 11 and  not line.strip() in c.excluded:
			c.excluded.append(line.strip())	
			c.debug and logfile.write("added %s to excluidos\n" % line.strip())
	fd.close()

if os.path.isfile(c.excludetempfile):
	fd = open(c.excludetempfile,"r")
	for line in fd.readlines():
		if len(line.strip()) > 11 and not line.strip() in c.excluded:
			c.excluded.append(line.strip())	
			c.debug and logfile.write("added %s to excluidos\n" % line.strip())
	fd.close()

if os.path.isfile(c.blockedfile):
	fd = open(c.blockedfile,"r")
	for line in fd.readlines():
		if len(line.strip()) > 11 and not line.strip() in c.blocked:
			c.blocked.append(line.strip())	
			c.debug and logfile.write("added %s to blocked\n" % line.strip())
	fd.close()

# desbloquear
for ipblocked in c.blocked:
	if ipblocked in c.excluded:
		iphex = hex(int(ipblocked.split(".")[3]))	
		if c.debug:
			logfile.write(c.iptablesoutcmd  % ("-D", ipblocked,c.agot))
			logfile.write(c.iptablesforwardcmd % ("-D", ipblocked,c.agot))
			logfile.write(c.iptablesoutcmd  % ("-A", ipblocked,iphex))
			logfile.write(c.iptablesforwardcmd  % ("-A", ipblocked,iphex))
		else:
			ret = call(c.iptablesoutcmd % ("-D", ipblocked,c.agot), shell=True)
			ret = call(c.iptablesforwardcmd % ("-D", ipblocked,c.agot), shell=True)
			ret = call(c.iptablesoutcmd % ("-A", ipblocked,iphex), shell=True)
			ret = call(c.iptablesforwardcmd % ("-A", ipblocked,iphex), shell=True)
			
		logfile.write("La ip %s ha sido liberada por encontrarse en la lista de excluidas\n" % ipblocked)
		sys.stdout.write("La ip %s ha sido liberada por encontrarse en la lista de excluidas\n" % ipblocked)

for ipblocked in c.blocked:		
	if ipblocked in c.excluded:
		c.blocked.remove(ipblocked)

# bloquear
ret = Popen(c.com, shell=True, stdout=PIPE)
data = ret.stdout.readlines()

for line in data:
	regexp = re.match(c.pattern, line)
	if regexp and int(regexp.group(c.bytes)) > c.max:
		q = int(regexp.group(c.bytes))
		ip = c.net+str(int(str(regexp.group(c.hex)),16)).strip()
		iphex = "0x" + regexp.group(c.hex)
		if not ip in c.excluded and not ip in c.blocked:
			if c.debug:
				logfile.write(c.iptablesoutcmd % ("-D", ip,iphex))
				logfile.write(c.iptablesforwardcmd  % ("-D", ip,iphex))
				logfile.write(c.iptablesoutcmd  % ("-A", ip,c.agot))
				logfile.write(c.iptablesforwardcmd % ("-A", ip,c.agot))
			else:
				ret = call(c.iptablesoutcmd % ("-D", ip,iphex), shell=True)
				ret = call(c.iptablesforwardcmd % ("-D", ip,iphex), shell=True)
				ret = call(c.iptablesoutcmd % ("-A", ip,c.agot), shell=True)
				ret = call(c.iptablesforwardcmd % ("-A", ip,c.agot), shell=True)
			
			c.blocked.append(ip)
			logfile.write("La ip %s ha sido bloqueada por trafico excesivo (%s bytes)\n" % (ip,str(q)))
			sys.stdout.write("La ip %s ha sido bloqueada por trafico excesivo (%s bytes)\n" % (ip,str(q)))
			
fd = open(c.blockedfile, "w")
for ip in c.blocked:
	fd.write(ip + "\n")

fd.close()
logfile.close()
sys.exit(0)
