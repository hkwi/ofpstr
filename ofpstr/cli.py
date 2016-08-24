#!python
import socket
import struct
import argparse
import re
import struct
import itertools
from . import ofp4

class Eparam(Exception):
	pass

class Result(Exception):
	pass

def msgs(sock):
	while True:
		h = sock.recv(8)
		hi = struct.unpack("!BBHI", h)
		if hi[2] > 8:
			yield h+sock.recv(hi[2]-8)
		else:
			yield h

ofpfc = ("add-flow", "mod-flow", "mod-flow-strict", "del-flow", "del-flow-strict")
ofpgc = ("add-group", "mod-group", "del-group")

def ofctl():
	argp = argparse.ArgumentParser(description="ofpstr ofctl cli")
	argp.add_argument("switch", help="tcp:127.0.0.1:6633 or unix:/var/run/openvswitch/br0.mgmt")
	argp.add_argument("command", help=", ".join(itertools.chain(["dump-flows", "dump-groups"], ofpfc, ofpgc)))
	argp.add_argument("args", nargs="*", help="dump-flows takes nothing, add-flow takes a flow rule")

	opts = argp.parse_args()
	sw = re.match(r"(tcp:(\d+.\d+.\d+.\d+):(\d+)|unix:(.*))", opts.switch)
	if not sw:
		raise Eparam("switch arg format error {0}".format(opts.switch))
	
	if sw.group(0).startswith("tcp:"):
		s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		s.connect((sw.group(2), int(sw.group(3))))
	elif sw.group(0).startswith("unix:"):
		s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
		s.connect(sw.group(4))
	
	s.send(struct.pack("!BBHI", 4, 0, 8, 1))
	if opts.command == "dump-flows":
		s.send(ofp4.text2mpflow("", type=18, xid=2))
		for msg in msgs(s):
			if len(msg) < 16:
				continue
			mphdr = struct.unpack_from("!BBHIHH4x", msg)
			if mphdr[1] != 19 or mphdr[4] != 1: # OFPT_MULTIPART_REPLY, OFPMP_FLOW
				continue
			
			print ofp4.mpflow2text(msg)
			
			if mphdr[5]==0:
				break
	elif opts.command == "dump-groups":
		s.send(ofp4.text2mpgroupdesc("", type=18, xid=2))
		for msg in msgs(s):
			if len(msg) < 16:
				continue
			mphdr = struct.unpack_from("!BBHIHH4x", msg)
			if mphdr[1] != 19 or mphdr[4] != 7: # OFPT_MULTIPART_REPLY, OFPMP_GROUP_DESC
				continue
			
			print ofp4.mpgroupdesc2text(msg)
			
			if mphdr[5]==0:
				break
	elif opts.command in ofpfc:
		x = ofp4.str2mod(" ".join(opts.args),
			command = ofpfc.index(opts.command),
			xid=2)
		s.send(x)
		s.send(struct.pack("!BBHI", 4, 20, 8, 3)) # Barrier
		for msg in msgs(s):
			hdr = struct.unpack_from("!BBHI", msg)
			if hdr[1] == 1 and hdr[2] == 2:
				raise Result("failed")
			elif hdr[1] == 21 and hdr[3] == 3:
				break
	elif opts.command in ofpgc:
		x = ofp4.str2group(" ".join(opts.args),
			command = ofpgc.index(opts.command),
			xid=2)
		s.send(x)
		s.send(struct.pack("!BBHI", 4, 20, 8, 3)) # Barrier
		for msg in msgs(s):
			hdr = struct.unpack_from("!BBHI", msg)
			if hdr[1] == 1 and hdr[2] == 2:
				raise Result("failed")
			elif hdr[1] == 21 and hdr[3] == 3:
				break
	else:
		raise Eparam("unknown command")

if __name__=="__main__":
	ofctl()
