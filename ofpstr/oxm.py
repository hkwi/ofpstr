import struct
import re
import socket
import binascii

from .util import get_token, parseInt, parseFloat, ofpp, int2bytes

try:
	L0 = long(0)
except:
	L0 = 0
	long = int

try:
	strtypes = (str, unicode)
except:
	strtypes = (str,)

OFPXMC_NXM_0 = 0x0000
OFPXMC_NXM_1 = 0x0001
OFPXMC_OPENFLOW_BASIC = 0x8000
OFPXMC_PACKET_REGS = 0x8001
OFPXMC_EXPERIMENTER = 0xFFFF

ofb_names = '''in_port
	in_phy_port
	metadata
	eth_dst
	eth_src
	eth_type
	vlan_vid
	vlan_pcp
	ip_dscp
	ip_ecn
	ip_proto
	ipv4_src
	ipv4_dst
	tcp_src
	tcp_dst
	udp_src
	udp_dst
	sctp_src
	sctp_dst
	icmpv4_type
	icmpv4_code
	arp_op
	arp_spa
	arp_tpa
	arp_sha
	arp_tha
	ipv6_src
	ipv6_dst
	ipv6_flabel
	icmpv6_type
	icmpv6_code
	ipv6_nd_target
	ipv6_nd_sll
	ipv6_nd_tll
	mpls_label
	mpls_tc
	mpls_bos
	pbb_isid
	tunnel_id
	ipv6_exthdr
	_
	pbb_uca
	tcp_flags
	actset_output
	packet_type'''.split()
for (i,n) in enumerate(ofb_names):
	if n != "_":
		globals()["OXM_OF_{:s}".format(n.upper())] = i

class nxm_of(int):
	def __hash__(self):
		return hash((0, int(self)))

nxm0_names = '''in_port
	eth_dst
	eth_src
	eth_type
	vlan_tci
	ip_tos
	ip_proto
	ip_src
	ip_dst
	tcp_src
	tcp_dst
	udp_src
	udp_dst
	icmp_type
	icmp_code
	arp_op
	arp_spa
	arp_tpa'''.split()
for (i, n) in enumerate(nxm0_names):
	if n != "_":
		globals()["NXM_OF_{:s}".format(n.upper())] = nxm_of(i)

class nxm_nx(int):
	def __hash__(self):
		return hash((1, int(self)))

nxm1_names = '''reg0
	reg1
	reg2
	reg3
	reg4
	reg5
	reg6
	reg7
	_ _ _ _ _ _ _ _
	tun_id
	arp_sha
	arp_tha
	ipv6_src
	ipv6_dst
	icmpv6_type
	icmpv6_code
	nd_target
	nd_sll
	nd_tll
	ip_frag
	ipv6_label
	ip_ecn
	ip_ttl
	_
	tun_ipv4_src
	tun_ipv4_dst
	pkt_mark
	tcp_flags
	dp_hash
	recirc_id
	conj_id
	tun_gbp_id
	tun_gbp_flags'''.split()
for (i, n) in enumerate(nxm1_names):
	if n != "_":
		globals()["NXM_NX_{:s}".format(n.upper())] = nxm_nx(i)
assert NXM_NX_TUN_GBP_FLAGS==39

STRATOS_EXPERIMENTER_ID = 0xFF00E04D

STRATOS_OXM_FIELD_BASIC = 0
STRATOS_OXM_FIELD_RADIOTAP = 1

class stratos(int):
	def __hash__(self):
		return hash((OFPXMC_EXPERIMENTER, STRATOS_EXPERIMENTER_ID, int(self)))

stratos_names = '''_ _
	dot11
	dot11_frame_ctrl
	dot11_addr1
	dot11_addr2
	dot11_addr3
	dot11_addr4
	dot11_ssid
	dot11_action_category
	dot11_public_action
	dot11_tag
	dot11_tag_vendor
	_ _ _
	tsft
	flags
	rate
	channel
	fhss
	dbm_antsignal
	dbm_antnoise
	lock_quality
	tx_attenuation
	db_tx_attenuation
	dbm_tx_power
	antenna
	db_antsignal
	db_antnoise
	rx_flags
	tx_flags
	rts_retries
	data_retries
	_
	mcs
	ampdu_status
	vht'''.split()
for (i,n) in enumerate(stratos_names):
	if n != "_":
		if i < 16:
			vname = "STROXM_BASIC_{:s}".format(n.upper())
		else:
			vname = "STROXM_RADIOTAP_{:s}".format(n.upper())
		globals()[vname] = stratos(i)
assert STROXM_RADIOTAP_VHT == 37


_bin2str = {}
_str2bin = {}


def header(field, value_length, mask):
	length = value_length
	field_HM = field<<1
	if mask:
		field_HM += 1
		length *= 2
	if isinstance(field, stratos):
		length += 4
	
	if length > 0xff:
		length = 0xff
	
	if isinstance(field, stratos):
		return struct.pack("!HBBI", OFPXMC_EXPERIMENTER, field_HM, length, STRATOS_EXPERIMENTER_ID)
	elif isinstance(field, nxm_of):
		return struct.pack("!HBB", OFPXMC_NXM_0, field_HM, length)
	elif isinstance(field, nxm_nx):
		return struct.pack("!HBB", OFPXMC_NXM_1, field_HM, length)
	else:
		return struct.pack("!HBB", OFPXMC_OPENFLOW_BASIC, field_HM, length)


def uint_bin2str(fmt):
	def bin2str(payload, has_mask):
		if payload is None:
			return fmt.split("=")[0]
		
		l = len(payload)
		if has_mask:
			value = L0
			mask = L0
			
			split = l//2
			for v in struct.unpack_from("!{:d}B".format(split), payload):
				value = (value << 8) + v
			for v in struct.unpack_from("!{:d}B".format(len(payload)-split), payload, split):
				mask = (mask << 8) + v
			
			return fmt.format(value, mask)
		else:
			value = L0
			for c in struct.unpack("!{:d}B".format(len(payload)), payload):
				value = (value << 8) + c
			
			return fmt.split("/", 2)[0].format(value)
	
	return bin2str


def uint_str2bin(field, size):
	def str2bin(unparsed):
		rlen = 0
		has_mask = False
		payload = b""
		if isinstance(unparsed, strtypes):
			num,rlen = parseInt(unparsed)
			payload += int2bytes([(num>>(8*s))&0xff for s in reversed(range(size))])
			
			if unparsed[rlen:].startswith("/"):
				has_mask = True
				num,e = parseInt(unparsed[rlen+1:])
				payload += int2bytes([(num>>(8*s))&0xff for s in reversed(range(size))])
				rlen += 1 + e
		elif unparsed:
			has_mask = True
		
		return header(field, size, has_mask)+payload, rlen
	
	return str2bin


def port_bin2str(name, fmt="!I"):
	size = struct.calcsize(fmt)
	mask = (1<<size*8) - 1
	def bin2str(payload, has_mask):
		if payload is None:
			return name
		
		assert not has_mask, "{:s} does not take mask".format(name)
		assert len(payload) == size, repr(payload)
		num = struct.unpack_from(fmt, payload)[0]
		for p,port in ofpp.items():
			if p&mask == num:
				return "{:s}={:s}".format(name, port)
		return "{:s}={:d}".format(name, num)
	
	return bin2str


def port_str2bin(field, fmt="!I"):
	size = struct.calcsize(fmt)
	mask = (1<<size*8) - 1
	def str2bin(unparsed):
		rlen = 0
		payload = b""
		if isinstance(unparsed, strtypes):
			for (v,name) in ofpp.items():
				for nm in (name.lower(), name.upper()):
					if unparsed.startswith(nm):
						rlen = len(name)
						payload = struct.pack(fmt, v&mask)
						break
			if not payload:
				num, rlen = parseInt(unparsed)
				payload = struct.pack(fmt, num)
		
		return header(field, size, False)+payload, rlen
	
	return str2bin


def mac_bin2str(name):
	def bin2str(payload, has_mask):
		if payload is None:
			return name
		
		value = ":".join(map("{:02x}".format, struct.unpack("!6B", payload[:6])))
		if has_mask:
			assert len(payload) == 12
			return "{:s}={:s}/{:s}".format(name, value, ":".join(map("{:02x}".format, struct.unpack("!6B", payload[6:]))))
		else:
			assert len(payload) == 6
			return "{:s}={:s}".format(name, value)
	
	return bin2str


def mac_str2bin(field):
	def scan(txt):
		for r,l in (("([0-9A-Fa-f]{12})", 12),
				(".".join(["([0-9A-Fa-f]{4})"]*3), 14),
				(":".join(["([0-9A-Fa-f]{2})"]*6), 17),
				("-".join(["([0-9A-Fa-f]{2})"]*6), 17)):
			m = re.match("^"+r, txt)
			if m:
				return "".join(m.groups()), l
		
		raise ValueError("mac format error {:s}".format(txt))
	
	def str2bin(unparsed):
		rlen = 0
		payload = b""
		has_mask = False
		if isinstance(unparsed, strtypes):
			value, rlen = scan(unparsed)
			if unparsed[rlen:].startswith("/"):
				mask, l = scan(unparsed[rlen+1:])
				rlen += 1+l
				payload = binascii.a2b_hex(value+mask)
				has_mask = True
			else:
				payload = binascii.a2b_hex(value)
		elif unparsed:
			has_mask = True
		
		return header(field, 6, has_mask)+payload, rlen
	
	return str2bin


def ipv4_bin2str(name):
	def bin2str(payload, has_mask):
		if payload is None:
			return name
		
		value = socket.inet_ntoa(payload[:4])
		if has_mask:
			assert len(payload) == 8
			return "{:s}={:s}/{:s}".format(name, value,  socket.inet_ntoa(payload[4:]))
		else:
			assert len(payload) == 4
			return "{:s}={:s}".format(name, value)
	
	return bin2str


def ipv4_str2bin(field):
	def str2bin(unparsed):
		rlen = 0
		payload = b""
		has_mask = False
		if isinstance(unparsed, strtypes):
			h, txt, unparsed = get_token(unparsed)
			vm = txt.split("/", 1)
			payload = socket.inet_aton(vm[0])
			if len(vm) > 1:
				has_mask = True
				try:
					mask = socket.inet_aton(vm[1])
				except ValueError:
					mask_len = int(vm[1])
					mask = struct.pack("!I", 0xFFFFFFFF<<(32-mask_len))
				
				payload += mask
			rlen = len(h)+len(txt)
		elif unparsed:
			has_mask = True
		
		return header(field, 4, has_mask)+payload, rlen
	
	return str2bin


def ipv6_bin2str(name):
	def bin2str(payload, has_mask):
		if payload is None:
			return name
		
		value = socket.inet_ntop(socket.AF_INET6, payload[:16])
		if has_mask:
			assert len(payload) == 32
			return "{:s}={:s}/{:s}".format(name, value,  socket.inet_ntop(socket.AF_INET6, payload[16:]))
		else:
			assert len(payload) == 16
			return "{:s}={:s}".format(name, value)
	
	return bin2str


def ipv6_str2bin(field):
	def str2bin(unparsed):
		rlen = 0
		payload = b""
		has_mask = False
		if isinstance(unparsed, strtypes):
			h,txt,unparsed = get_token(unparsed)
			rlen = len(h)+len(txt)
			vm = txt.split("/", 1)
			payload = socket.inet_pton(socket.AF_INET6, vm[0])
			if len(vm) > 1:
				has_mask = True
				try:
					mask = socket.inet_pton(socket.AF_INET6, vm[1])
				except:
					mask_len = int(vm[1])
					mask_int = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF<<(128-int(mask_len))
					mask = struct.pack("!QQ", mask_int>>64, mask_int&0xFFFFFFFFFFFFFFFF)
				
				payload += mask
		elif unparsed:
			has_mask = True
		
		return header(field, 16, has_mask)+payload, rlen
	
	return str2bin


def pkt_bin2str(payload, has_mask):
	if payload is None:
		return "packet_type"
	
	assert not has_mask
	assert len(payload) == 4
	return "packet_type={:#x}:{:#x}".format(*struct.unpack("!HH", payload))


def pkt_str2bin(unparsed):
	rlen = 0
	payload = b""
	if isinstance(unparsed, strtypes):
		ns, l = parseInt(unparsed)
		assert unparsed[l] == ":"
		ns_type, l2 = parseInt(unparsed[l+1:])
		
		rlen = l+l2+1
		payload = struct.pack("!HH", ns, ns_type)
	
	return header(OXM_OF_PACKET_TYPE, 4, False)+payload, rlen


def hex_bin2str(name):
	def bin2str(payload, has_mask):
		if payload is None:
			return name
		
		if has_mask:
			split = len(payload)//2
			return "{:s}={:s}/{:s}".format(name,
				binascii.b2a_hex(payload[:split]).decode("UTF-8"),
				binascii.b2a_hex(payload[split:]).decode("UTF-8"))
		else:
			return "{:s}={:s}".format(name,
				binascii.b2a_hex(payload).decode("UTF-8"))
	
	return bin2str


def hex_str2bin(field):
	def str2bin(unparsed):
		rlen = 0
		payload = b""
		has_mask = False
		length = 0xff
		if isinstance(unparsed, strtypes):
			h, txt, unparsed = get_token(unparsed)
			rlen = len(h)+len(txt)
			vm = txt.split("/", 1)
			payload = binascii.a2b_hex(vm[0])
			length = len(payload)
			if len(vm) > 1:
				has_mask = True
				mask = binascii.a2b_hex(vm[1])
				pad = b"\0" * abs(len(mask)-len(payload))
				if len(payload) < len(mask):
					length = len(mask)
					payload = payload+pad+mask
				else:
					payload = payload+mask+pad
		elif unparsed:
			has_mask = True
		
		return header(field, length, has_mask)+payload, rlen
	
	return str2bin


def ssid_bin2str(payload, has_mask):
	if payload is None:
		return "dot11_ssid"
	
	if has_mask:
		split = len(payload)//2
		name = bytearray(payload[:split])
		while name[-1] == 0:
			name = name[:-1]
		name = bytes(name)
		
		return "dot11_ssid={:s}/{:s}".format(
			binascii.b2a_qp(name).decode("UTF-8"),
			binascii.b2a_hex(payload[split:]).decode("UTF-8"))
	else:
		return "dot11_ssid={:s}".format(binascii.b2a_qp(payload).decode("UTF-8"))


def ssid_str2bin(unparsed):
	rlen = 0
	payload = b""
	has_mask = False
	length = 0xff
	if isinstance(unparsed, strtypes):
		h, txt, unparsed = get_token(unparsed)
		rlen = len(h) + len(txt)
		vm = txt.split("/")
		payload = binascii.a2b_qp(vm[0])
		length = len(payload)
		if len(vm) > 1:
			has_mask = True
			mask = binascii.a2b_hex(vm[1])
			pad = b"\0" * abs(len(payload)-len(mask))
			if len(payload) < len(mask):
				length = len(mask)
				payload += pad + mask
			else:
				payload += mask + pad
	elif unparsed:
		has_mask = True
	
	return header(STROXM_BASIC_DOT11_SSID, length, has_mask)+payload, rlen


def le_bin2str(fmt):
	def bin2str(payload, has_mask):
		if payload is None:
			return fmt.split("=")[0]
		
		l = len(payload)
		if has_mask:
			value = L0
			mask = L0
			
			split = l//2
			for i,v in enumerate(struct.unpack_from("!{:d}B".format(split), payload)):
				value += v<<(8*i)
			for i,v in enumerate(struct.unpack_from("!{:d}B".format(len(payload)-split), payload, split)):
				mask += v<<(8*i)
			
			return fmt.format(value, mask)
		else:
			value = L0
			for i,c in enumerate(struct.unpack("!{:d}B".format(len(payload)), payload)):
				value += c<<(8*i)
			
			return fmt.split("/", 2)[0].format(value)
	
	return bin2str


def le_str2bin(field, size):
	def str2bin(unparsed):
		rlen = 0
		payload = b""
		has_mask = False
		if isinstance(unparsed, strtypes):
			num,rlen = parseInt(unparsed)
			payload += int2bytes([0xFF & (num>>(8*s)) for s in range(size)])
			
			if unparsed[rlen:].startswith("/"):
				has_mask = True
				num,e = parseInt(unparsed[rlen+1:])
				rlen += 1 + e
				for s in range(size):
					payload += chr(0xFF & (num>>(8*s)))
		elif unparsed:
			has_mask = True
		
		return header(field, size, has_mask)+payload, rlen
	
	return str2bin


def rate_bin2str(payload, has_mask):
	if payload is None:
		return "radiotap_rate"
	
	assert not has_mask
	rate = struct.unpack_from("!B", payload)[0]
	if rate < 2:
		return "radiotap_rate={:.1f}K".format(rate*500.0)
	else:
		return "radiotap_rate={:.1f}M".format(float(rate)/2.0)


def rate_str2bin(unparsed):
	rlen = 0
	payload = b""
	has_mask = False
	if isinstance(unparsed, strtypes):
		num, rlen = parseFloat(unparsed)
		if unparsed[rlen] == "K":
			rate = num / 500
			rlen += 1
		elif unparsed[rlen] == "M":
			rate = num * 2
			rlen += 1
		else:
			raise ValueError("rate unit error")
		
		payload = struct.pack("!B", int(rate))
	
	return header(STROXM_RADIOTAP_RATE, 1, False)+payload, rlen


def ch_bin2str(payload, has_mask):
	if payload is None:
		return "radiotap_channel"
	
	if has_mask:
		assert len(payload) == 8
		v = struct.unpack("!HHHH", payload)
		if v[2] == 0:
			return "radiotap_channel={:d}:{:#06x}/:{:#06x}".format(
				v[0], v[1], v[3])
		else:
			return "radiotap_channel={:d}:{:#06x}/{:#06x}:{:#06x}".format(*v)
	else:
		assert len(payload) == 4
		v = struct.unpack("!HH", payload)
		return "radiotap_channel={:d}:{:#06x}".format(*v)


def ch_str2bin(unparsed):
	rlen = 0
	payload = b""
	has_mask = False
	
	if isinstance(unparsed, strtypes):
		v1,l = parseInt(unparsed)
		assert unparsed[l] == ":"
		v2,l2 = parseInt(unparsed[l+1:])
		payload = struct.pack("!HH", v1, v2)
		rlen = l+1+l2
		
		if unparsed[rlen:].startswith("/"):
			has_mask = True
			if unparsed[rlen+1:].startswith(":"):
				m1 = l3 = 0
			else:
				m1,l3 = parseInt(unparsed[rlen+1:])
			
			if unparsed[rlen+1+l3:].startswith(":"):
				m2,l4 = parseInt(unparsed[rlen+1+l3+1:])
				rlen += 1 + l3 + 1 + l4
			else:
				m2 = 0
				rlen += 1 + l3
			
			payload += struct.pack("!HH", m1, m2)
	elif unparsed:
		has_mask = True
	
	return header(STROXM_RADIOTAP_CHANNEL, 4, has_mask)+payload, rlen


def comp_bin2str(name, packs, fmts):
	def collect(data):
		ret = []
		for n,fmt in zip(struct.unpack_from(packs, data), fmts):
			if n == 0:
				ret.append("")
			else:
				ret.append(fmt.format(n))
		return ":".join(ret)
	
	def bin2str(payload, has_mask):
		if payload is None:
			return name
		
		ret = "{:s}={:s}".format(name, collect(payload))
		if has_mask:
			ret += "/"
			ret += collect(payload[struct.calcsize(packs):])
		
		return ret

	return bin2str


def comp_str2bin(field, packs):
	def collect(txt):
		ps = []
		for t in txt.split(":"):
			v = l = 0
			if len(t):
				v, l = parseInt(t)
				assert len(t) == l
			ps.append(v)
		
		return struct.pack(packs, *ps)
	
	def str2bin(unparsed):
		rlen = 0
		payload = b""
		has_mask = False
		
		if isinstance(unparsed, strtypes):
			h,txt,unparsed = get_token(unparsed)
			rlen = len(h) + len(txt)
			vm = txt.split("/", 1)
			payload = collect(vm[0])
			if len(vm) > 1:
				has_mask = True
				payload += collect(vm[1])
		elif unparsed:
			has_mask = True
		
		return header(field, struct.calcsize(packs), has_mask)+payload, rlen
	
	return str2bin


def vht_bin2str(payload, has_mask):
	name = "radiotap_vht"
	if payload is None:
		return name
	
	packs = "<HBB4BBBH"
	def collect(data):
		ns = struct.unpack_from(packs, data)
		
		ret = ""
		args = []
		if ns[0]>0:
			ret += "{:#06x}".format(ns[0])
		ret += ":"
		if ns[1]>0:
			ret += "{:#04x}".format(ns[1])
		ret += ":{:d}:".format(ns[2])
		if sum(ns[3:7])!=0:
			ret += "{:02x}{:02x}{:02x}{:02x}".format(*ns[3:7])
		ret += ":"
		if ns[7]>0:
			ret += "{:#04x}".format(ns[7])
		ret += ":{:d}:{:#06x}".format(ns[8], ns[9])
		return ret
	
	ret = "{:s}={:s}".format(name, collect(payload))
	if has_mask:
		ret += "/"
		ret += collect(payload[struct.calcsize(packs):])
	
	return ret


def vht_str2bin(unparsed):
	packs = "<HBB4BBBH"
	def collect(txt):
		ps = []
		for i, t in enumerate(txt.split(":")):
			if i == 3:
				ps.extend(bytearray(binascii.a2b_hex(t)))
			else:
				v = l = 0
				if len(t):
					v, l = parseInt(t)
				ps.append(v)
		
		return struct.pack(packs, *ps)
	
	rlen = 0
	payload = b""
	has_mask = False
	if isinstance(unparsed, strtypes):
		h,txt,unparsed = get_token(unparsed)
		rlen = len(h) + len(txt)
		vm = txt.split("/", 1)
		payload = collect(vm[0])
		if len(vm) > 1:
			has_mask = True
			payload += collect(vm[1])
	elif unparsed:
		has_mask = True
	
	return header(STROXM_RADIOTAP_VHT, struct.calcsize(packs), has_mask)+payload, rlen


def s8_bin2str(name):
	def bin2str(payload, has_mask):
		if payload is None:
			return name
		
		assert not has_mask
		return "{:s}={:d}".format(name, struct.unpack("<b", payload)[0])
	
	return bin2str


def s8_str2bin(field):
	def str2bin(unparsed):
		rlen = 0
		payload = b""
		if isinstance(unparsed, strtypes):
			num,rlen = parseInt(unparsed)
			payload = struct.pack("<b", num)
		
		return header(field, 1, False)+payload, rlen
	
	return str2bin


_bin2str[OXM_OF_IN_PORT] = port_bin2str("in_port")
_str2bin["in_port"] = port_str2bin(OXM_OF_IN_PORT)

_bin2str[OXM_OF_IN_PHY_PORT] = port_bin2str("in_phy_port")
_str2bin["in_phy_port"] = port_str2bin(OXM_OF_IN_PHY_PORT)

_bin2str[OXM_OF_METADATA] = uint_bin2str("metadata={:#x}/{:#x}")
_str2bin["metadata"] = uint_str2bin(OXM_OF_METADATA, 8)

_bin2str[OXM_OF_ETH_DST] = mac_bin2str("eth_dst")
_str2bin["eth_dst"] = mac_str2bin(OXM_OF_ETH_DST)

_bin2str[OXM_OF_ETH_SRC] = mac_bin2str("eth_src")
_str2bin["eth_src"] = mac_str2bin(OXM_OF_ETH_SRC)

_bin2str[OXM_OF_ETH_TYPE] = uint_bin2str("eth_type={:#04x}")
_str2bin["eth_type"] = uint_str2bin(OXM_OF_ETH_TYPE, 2)

_bin2str[OXM_OF_VLAN_VID] = uint_bin2str("vlan_vid={:#x}/{:#x}")
_str2bin["vlan_vid"] = uint_str2bin(OXM_OF_VLAN_VID, 2)

_bin2str[OXM_OF_VLAN_PCP] = uint_bin2str("vlan_pcp={:d}")
_str2bin["vlan_pcp"] = uint_str2bin(OXM_OF_VLAN_PCP, 1)

_bin2str[OXM_OF_IP_DSCP] = uint_bin2str("ip_dscp={:#x}")
_str2bin["ip_dscp"] = uint_str2bin(OXM_OF_IP_DSCP, 1)

_bin2str[OXM_OF_IP_ECN] = uint_bin2str("ip_ecn={:#x}")
_str2bin["ip_ecn"] = uint_str2bin(OXM_OF_IP_ECN, 1)

_bin2str[OXM_OF_IP_PROTO] = uint_bin2str("ip_proto={:d}")
_str2bin["ip_proto"] = uint_str2bin(OXM_OF_IP_PROTO, 1)

_bin2str[OXM_OF_IPV4_SRC] = ipv4_bin2str("ipv4_src")
_str2bin["ipv4_src"] = ipv4_str2bin(OXM_OF_IPV4_SRC)

_bin2str[OXM_OF_IPV4_DST] = ipv4_bin2str("ipv4_dst")
_str2bin["ipv4_dst"] = ipv4_str2bin(OXM_OF_IPV4_DST)

_bin2str[OXM_OF_TCP_SRC] = uint_bin2str("tcp_src={:d}")
_str2bin["tcp_src"] = uint_str2bin(OXM_OF_TCP_SRC, 2)

_bin2str[OXM_OF_TCP_DST] = uint_bin2str("tcp_dst={:d}")
_str2bin["tcp_dst"] = uint_str2bin(OXM_OF_TCP_DST, 2)

_bin2str[OXM_OF_UDP_SRC] = uint_bin2str("udp_src={:d}")
_str2bin["udp_src"] = uint_str2bin(OXM_OF_UDP_SRC, 2)

_bin2str[OXM_OF_UDP_DST] = uint_bin2str("udp_dst={:d}")
_str2bin["udp_dst"] = uint_str2bin(OXM_OF_UDP_DST, 2)

_bin2str[OXM_OF_SCTP_SRC] = uint_bin2str("sctp_src={:d}")
_str2bin["sctp_src"] = uint_str2bin(OXM_OF_SCTP_SRC, 2)

_bin2str[OXM_OF_SCTP_DST] = uint_bin2str("sctp_dst={:d}")
_str2bin["sctp_dst"] = uint_str2bin(OXM_OF_SCTP_DST, 2)

_bin2str[OXM_OF_ICMPV4_TYPE] = uint_bin2str("icmpv4_type={:d}")
_str2bin["icmpv4_type"] = uint_str2bin(OXM_OF_ICMPV4_TYPE, 1)

_bin2str[OXM_OF_ICMPV4_CODE] = uint_bin2str("icmpv4_code={:d}")
_str2bin["icmpv4_code"] = uint_str2bin(OXM_OF_ICMPV4_CODE, 1)

_bin2str[OXM_OF_ARP_OP] = uint_bin2str("arp_op={:#d}")
_str2bin["arp_op"] = uint_str2bin(OXM_OF_ARP_OP, 2)

_bin2str[OXM_OF_ARP_SPA] = ipv4_bin2str("arp_spa")
_str2bin["arp_spa"] = ipv4_str2bin(OXM_OF_ARP_SPA)

_bin2str[OXM_OF_ARP_TPA] = ipv4_bin2str("arp_tpa")
_str2bin["arp_tpa"] = ipv4_str2bin(OXM_OF_ARP_TPA)

_bin2str[OXM_OF_ARP_SHA] = mac_bin2str("arp_sha")
_str2bin["arp_sha"] = mac_str2bin(OXM_OF_ARP_SHA)

_bin2str[OXM_OF_ARP_THA] = mac_bin2str("arp_tha")
_str2bin["arp_tha"] = mac_str2bin(OXM_OF_ARP_THA)

_bin2str[OXM_OF_IPV6_SRC] = ipv6_bin2str("ipv6_src")
_str2bin["ipv6_src"] = ipv6_str2bin(OXM_OF_IPV6_SRC)

_bin2str[OXM_OF_IPV6_DST] = ipv6_bin2str("ipv6_dst")
_str2bin["ipv6_dst"] = ipv6_str2bin(OXM_OF_IPV6_DST)

_bin2str[OXM_OF_IPV6_FLABEL] = uint_bin2str("ipv6_flabel={:#x}/{:#x}")
_str2bin["ipv6_flabel"] = uint_str2bin(OXM_OF_IPV6_FLABEL, 4)

_bin2str[OXM_OF_ICMPV6_TYPE] = uint_bin2str("icmpv6_type={:d}")
_str2bin["icmpv6_type"] = uint_str2bin(OXM_OF_ICMPV6_TYPE, 1)

_bin2str[OXM_OF_ICMPV6_CODE] = uint_bin2str("icmpv6_code={:d}")
_str2bin["icmpv6_code"] = uint_str2bin(OXM_OF_ICMPV6_CODE, 1)

_bin2str[OXM_OF_IPV6_ND_TARGET] = ipv6_bin2str("ipv6_nd_target")
_str2bin["ipv6_nd_target"] = ipv6_str2bin(OXM_OF_IPV6_ND_TARGET)

_bin2str[OXM_OF_IPV6_ND_SLL] = mac_bin2str("ipv6_nd_sll")
_str2bin["ipv6_nd_sll"] = mac_str2bin(OXM_OF_IPV6_ND_SLL)

_bin2str[OXM_OF_IPV6_ND_TLL] = mac_bin2str("ipv6_nd_tll")
_str2bin["ipv6_nd_tll"] = mac_str2bin(OXM_OF_IPV6_ND_TLL)

_bin2str[OXM_OF_MPLS_LABEL] = uint_bin2str("mpls_label={:#x}/{:#x}")
_str2bin["mpls_label"] = uint_str2bin(OXM_OF_MPLS_LABEL, 4)

_bin2str[OXM_OF_MPLS_TC] = uint_bin2str("mpls_tc={:d}")
_str2bin["mpls_tc"] = uint_str2bin(OXM_OF_MPLS_TC, 1)

_bin2str[OXM_OF_MPLS_BOS] = uint_bin2str("mpls_bos={:d}")
_str2bin["mpls_bos"] = uint_str2bin(OXM_OF_MPLS_BOS, 1)

_bin2str[OXM_OF_PBB_ISID] = uint_bin2str("pbb_isid={:#x}/{:#x}")
_str2bin["pbb_isid"] = uint_str2bin(OXM_OF_PBB_ISID, 3)

_bin2str[OXM_OF_TUNNEL_ID] = uint_bin2str("tunnel_id={:#x}/{:#x}")
_str2bin["tunnel_id"] = uint_str2bin(OXM_OF_TUNNEL_ID, 8)

_bin2str[OXM_OF_IPV6_EXTHDR] = uint_bin2str("ipv6_exthdr={:#x}/{:#x}")
_str2bin["ipv6_exthdr"] = uint_str2bin(OXM_OF_IPV6_EXTHDR, 2)

_bin2str[OXM_OF_PBB_UCA] = uint_bin2str("pbb_uca={:d}")
_str2bin["pbb_uca"] = uint_str2bin(OXM_OF_PBB_UCA, 1)

_bin2str[OXM_OF_TCP_FLAGS] = uint_bin2str("tcp_flags={:#04x}/{:#04x}")
_str2bin["tcp_flags"] = uint_str2bin(OXM_OF_TCP_FLAGS, 2)

_bin2str[OXM_OF_ACTSET_OUTPUT] = port_bin2str("actset_output")
_str2bin["actset_output"] = port_str2bin(OXM_OF_ACTSET_OUTPUT)

_bin2str[OXM_OF_PACKET_TYPE] = pkt_bin2str
_str2bin["packet_type"] = pkt_str2bin

_bin2str[NXM_OF_IN_PORT] = port_bin2str("nxm_in_port", fmt="!H")
_str2bin["nxm_in_port"] = port_str2bin(NXM_OF_IN_PORT, fmt="!H")

_bin2str[NXM_OF_ETH_DST] = mac_bin2str("nxm_eth_dst")
_str2bin["nxm_eth_dst"] = mac_str2bin(NXM_OF_ETH_DST)

_bin2str[NXM_OF_ETH_SRC] = mac_bin2str("nxm_eth_src")
_str2bin["nxm_eth_src"] = mac_str2bin(NXM_OF_ETH_SRC)

_bin2str[NXM_OF_ETH_TYPE] = uint_bin2str("nxm_eth_type={:#06x}/{:#06x}")
_str2bin["nxm_eth_type"] = uint_str2bin(NXM_OF_ETH_TYPE, 2)

_bin2str[NXM_OF_VLAN_TCI] = uint_bin2str("nxm_vlan_tci={:#x}/{:#06x}")
_str2bin["nxm_vlan_tci"] = uint_str2bin(NXM_OF_VLAN_TCI, 2)

_bin2str[NXM_OF_IP_TOS] = uint_bin2str("nxm_ip_tos={:#x}/{:#x}")
_str2bin["nxm_ip_tos"] = uint_str2bin(NXM_OF_IP_TOS, 1)

_bin2str[NXM_OF_IP_PROTO] = uint_bin2str("nxm_ip_proto={:d}/{:d}")
_str2bin["nxm_ip_proto"] = uint_str2bin(NXM_OF_IP_PROTO, 1)

_bin2str[NXM_OF_IP_SRC] = ipv4_bin2str("nxm_ip_src")
_str2bin["nxm_ip_src"] = ipv4_str2bin(NXM_OF_IP_SRC)

_bin2str[NXM_OF_IP_DST] = ipv4_bin2str("nxm_ip_dst")
_str2bin["nxm_ip_dst"] = ipv4_str2bin(NXM_OF_IP_DST)

_bin2str[NXM_OF_TCP_SRC] = uint_bin2str("nxm_tcp_src={:d}/{:d}")
_str2bin["nxm_tcp_src"] = uint_str2bin(NXM_OF_TCP_SRC, 2)

_bin2str[NXM_OF_TCP_DST] = uint_bin2str("nxm_tcp_dst={:d}/{:d}")
_str2bin["nxm_tcp_dst"] = uint_str2bin(NXM_OF_TCP_DST, 2)

_bin2str[NXM_OF_UDP_SRC] = uint_bin2str("nxm_udp_src={:d}/{:d}")
_str2bin["nxm_udp_src"] = uint_str2bin(NXM_OF_UDP_SRC, 2)

_bin2str[NXM_OF_UDP_DST] = uint_bin2str("nxm_udp_dst={:d}/{:d}")
_str2bin["nxm_udp_dst"] = uint_str2bin(NXM_OF_UDP_DST, 2)

_bin2str[NXM_OF_ICMP_TYPE] = uint_bin2str("nxm_icmp_type={:d}/{:d}")
_str2bin["nxm_icmp_type"] = uint_str2bin(NXM_OF_ICMP_TYPE, 1)

_bin2str[NXM_OF_ICMP_CODE] = uint_bin2str("nxm_icmp_code={:d}/{:d}")
_str2bin["nxm_icmp_code"] = uint_str2bin(NXM_OF_ICMP_CODE, 1)

_bin2str[NXM_OF_ARP_OP] = uint_bin2str("nxm_arp_op={:#d}/{:#d}")
_str2bin["nxm_arp_op"] = uint_str2bin(NXM_OF_ARP_OP, 2)

_bin2str[NXM_OF_ARP_SPA] = ipv4_bin2str("nxm_arp_spa")
_str2bin["nxm_arp_spa"] = ipv4_str2bin(NXM_OF_ARP_SPA)

_bin2str[NXM_OF_ARP_TPA] = ipv4_bin2str("nxm_arp_tpa")
_str2bin["nxm_arp_tpa"] = ipv4_str2bin(NXM_OF_ARP_TPA)

_bin2str[NXM_NX_REG0] = uint_bin2str("nxm_reg0={:#x}/{:#x}")
_str2bin["nxm_reg0"] = uint_str2bin(NXM_NX_REG0, 4)

_bin2str[NXM_NX_REG1] = uint_bin2str("nxm_reg1={:#x}/{:#x}")
_str2bin["nxm_reg1"] = uint_str2bin(NXM_NX_REG1, 4)

_bin2str[NXM_NX_REG2] = uint_bin2str("nxm_reg2={:#x}/{:#x}")
_str2bin["nxm_reg2"] = uint_str2bin(NXM_NX_REG2, 4)

_bin2str[NXM_NX_REG3] = uint_bin2str("nxm_reg3={:#x}/{:#x}")
_str2bin["nxm_reg3"] = uint_str2bin(NXM_NX_REG3, 4)

_bin2str[NXM_NX_REG4] = uint_bin2str("nxm_reg4={:#x}/{:#x}")
_str2bin["nxm_reg4"] = uint_str2bin(NXM_NX_REG4, 4)

_bin2str[NXM_NX_REG5] = uint_bin2str("nxm_reg5={:#x}/{:#x}")
_str2bin["nxm_reg5"] = uint_str2bin(NXM_NX_REG5, 4)

_bin2str[NXM_NX_REG6] = uint_bin2str("nxm_reg6={:#x}/{:#x}")
_str2bin["nxm_reg6"] = uint_str2bin(NXM_NX_REG6, 4)

_bin2str[NXM_NX_REG7] = uint_bin2str("nxm_reg7={:#x}/{:#x}")
_str2bin["nxm_reg7"] = uint_str2bin(NXM_NX_REG7, 4)

_bin2str[NXM_NX_TUN_ID] = uint_bin2str("nxm_tun_id={:#x}/{:#x}")
_str2bin["nxm_tun_id"] = uint_str2bin(NXM_NX_TUN_ID, 8)

_bin2str[NXM_NX_ARP_SHA] = mac_bin2str("nxm_arp_sha")
_str2bin["nxm_arp_sha"] = mac_str2bin(NXM_NX_ARP_SHA)

_bin2str[NXM_NX_ARP_THA] = mac_bin2str("nxm_arp_tha")
_str2bin["nxm_arp_tha"] = mac_str2bin(NXM_NX_ARP_THA)

_bin2str[NXM_NX_IPV6_SRC] = ipv6_bin2str("nxm_ipv6_src")
_str2bin["nxm_ipv6_src"] = ipv6_str2bin(NXM_NX_IPV6_SRC)

_bin2str[NXM_NX_IPV6_DST] = ipv6_bin2str("nxm_ipv6_dst")
_str2bin["nxm_ipv6_dst"] = ipv6_str2bin(NXM_NX_IPV6_DST)

_bin2str[NXM_NX_ICMPV6_TYPE] = uint_bin2str("nxm_icmpv6_type={:d}/{:d}")
_str2bin["nxm_icmpv6_type"] = uint_str2bin(NXM_NX_ICMPV6_TYPE, 1)

_bin2str[NXM_NX_ICMPV6_CODE] = uint_bin2str("nxm_icmpv6_code={:d}/{:d}")
_str2bin["nxm_icmpv6_code"] = uint_str2bin(NXM_NX_ICMPV6_CODE, 1)

_bin2str[NXM_NX_ND_TARGET] = ipv6_bin2str("nxm_nd_target")
_str2bin["nxm_nd_target"] = ipv6_str2bin(NXM_NX_ND_TARGET)

_bin2str[NXM_NX_ND_SLL] = mac_bin2str("nxm_nd_sll")
_str2bin["nxm_nd_sll"] = mac_str2bin(NXM_NX_ND_SLL)

_bin2str[NXM_NX_ND_TLL] = mac_bin2str("nxm_nd_tll")
_str2bin["nxm_nd_tll"] = mac_str2bin(NXM_NX_ND_TLL)

_bin2str[NXM_NX_IP_FRAG] = uint_bin2str("nxm_icmp_type={:d}/{:d}")
_str2bin["nxm_ip_frag"] = uint_str2bin(NXM_NX_IP_FRAG, 1)

_bin2str[NXM_NX_IPV6_LABEL] = uint_bin2str("nxm_ipv6_label={:#x}/{:#x}")
_str2bin["nxm_ipv6_label"] = uint_str2bin(NXM_NX_IPV6_LABEL, 4)

_bin2str[NXM_NX_IP_ECN] = uint_bin2str("nxm_ip_ecn={:#x}/{:#x}")
_str2bin["nxm_ip_ecn"] = uint_str2bin(NXM_NX_IP_ECN, 1)

_bin2str[NXM_NX_IP_TTL] = uint_bin2str("nxm_ip_ttl={:d}/{:d}")
_str2bin["nxm_ip_ttl"] = uint_str2bin(NXM_NX_IP_TTL, 1)

_bin2str[NXM_NX_TUN_IPV4_SRC] = ipv4_bin2str("nxm_tun_ipv4_src")
_str2bin["nxm_tun_ipv4_src"] = ipv4_str2bin(NXM_NX_TUN_IPV4_SRC)

_bin2str[NXM_NX_TUN_IPV4_DST] = ipv4_bin2str("nxm_tun_ipv4_dst")
_str2bin["nxm_tun_ipv4_dst"] = ipv4_str2bin(NXM_NX_TUN_IPV4_DST)

_bin2str[NXM_NX_PKT_MARK] = uint_bin2str("nxm_pkt_mark={:#x}/{:#x}")
_str2bin["nxm_pkt_mark"] = uint_str2bin(NXM_NX_PKT_MARK, 4)

_bin2str[NXM_NX_TCP_FLAGS] = uint_bin2str("nxm_tcp_flags={:#06x}/{:#06x}")
_str2bin["nxm_tcp_flags"] = uint_str2bin(NXM_NX_TCP_FLAGS, 2)

_bin2str[NXM_NX_DP_HASH] = uint_bin2str("nxm_dp_hash={:#010x}/{:#010x}")
_str2bin["nxm_dp_hash"] = uint_str2bin(NXM_NX_DP_HASH, 4)

_bin2str[NXM_NX_RECIRC_ID] = uint_bin2str("nxm_recirc_id={:#010x}/{:#010x}")
_str2bin["nxm_recirc_id"] = uint_str2bin(NXM_NX_RECIRC_ID, 4)

_bin2str[NXM_NX_CONJ_ID] = uint_bin2str("nxm_conj_id={:#010x}/{:#010x}")
_str2bin["nxm_conj_id"] = uint_str2bin(NXM_NX_CONJ_ID, 4)

_bin2str[NXM_NX_TUN_GBP_ID] = uint_bin2str("nxm_tun_gbp_id={:#06x}/{:#06x}")
_str2bin["nxm_tun_gbp_id"] = uint_str2bin(NXM_NX_TUN_GBP_ID, 2)

_bin2str[NXM_NX_TUN_GBP_FLAGS] = uint_bin2str("nxm_tun_gbp_flags={:#x}/{:#x}")
_str2bin["nxm_tun_gbp_flags"] = uint_str2bin(NXM_NX_TUN_GBP_FLAGS, 1)

_bin2str[STROXM_BASIC_DOT11] = uint_bin2str("dot11={:d}")
_str2bin["dot11"] = uint_str2bin(STROXM_BASIC_DOT11, 1)

_bin2str[STROXM_BASIC_DOT11_FRAME_CTRL] = hex_bin2str("dot11_frame_ctrl")
_str2bin["dot11_frame_ctrl"] = hex_str2bin(STROXM_BASIC_DOT11_FRAME_CTRL)

_bin2str[STROXM_BASIC_DOT11_ADDR1] = mac_bin2str("dot11_addr1")
_str2bin["dot11_addr1"] = mac_str2bin(STROXM_BASIC_DOT11_ADDR1)

_bin2str[STROXM_BASIC_DOT11_ADDR2] = mac_bin2str("dot11_addr2")
_str2bin["dot11_addr2"] = mac_str2bin(STROXM_BASIC_DOT11_ADDR2)

_bin2str[STROXM_BASIC_DOT11_ADDR3] = mac_bin2str("dot11_addr3")
_str2bin["dot11_addr3"] = mac_str2bin(STROXM_BASIC_DOT11_ADDR3)

_bin2str[STROXM_BASIC_DOT11_ADDR4] = mac_bin2str("dot11_addr4")
_str2bin["dot11_addr4"] = mac_str2bin(STROXM_BASIC_DOT11_ADDR4)

_bin2str[STROXM_BASIC_DOT11_SSID] = ssid_bin2str
_str2bin["dot11_ssid"] = ssid_str2bin

_bin2str[STROXM_BASIC_DOT11_ACTION_CATEGORY] = hex_bin2str("dot11_action_category")
_str2bin["dot11_action_category"] = hex_str2bin(STROXM_BASIC_DOT11_ACTION_CATEGORY)

_bin2str[STROXM_BASIC_DOT11_PUBLIC_ACTION] = uint_bin2str("dot11_public_action={:d}")
_str2bin["dot11_public_action"] = uint_str2bin(STROXM_BASIC_DOT11_PUBLIC_ACTION, 1)

_bin2str[STROXM_BASIC_DOT11_TAG] = uint_bin2str("dot11_tag={:d}")
_str2bin["dot11_tag"] = uint_str2bin(STROXM_BASIC_DOT11_TAG, 1)

_bin2str[STROXM_BASIC_DOT11_TAG_VENDOR] = hex_bin2str("dot11_tag_vendor")
_str2bin["dot11_tag_vendor"] = hex_str2bin(STROXM_BASIC_DOT11_TAG_VENDOR)

_bin2str[STROXM_RADIOTAP_TSFT] = le_bin2str("radiotap_tsft={:d}")
_str2bin["radiotap_tsft"] = le_str2bin(STROXM_RADIOTAP_TSFT, 8)

_bin2str[STROXM_RADIOTAP_FLAGS] = le_bin2str("radiotap_flags={:#04x}/{:#04x}")
_str2bin["radiotap_flags"] = le_str2bin(STROXM_RADIOTAP_FLAGS, 1)

_bin2str[STROXM_RADIOTAP_RATE] = rate_bin2str
_str2bin["radiotap_rate"] = rate_str2bin

_bin2str[STROXM_RADIOTAP_CHANNEL] = ch_bin2str
_str2bin["radiotap_channel"] = ch_str2bin

_bin2str[STROXM_RADIOTAP_FHSS] = hex_bin2str("radiotap_fhss")
_str2bin["radiotap_fhss"] = hex_str2bin(STROXM_RADIOTAP_FHSS)

_bin2str[STROXM_RADIOTAP_DBM_ANTSIGNAL] = s8_bin2str("radiotap_dbm_antsignal")
_str2bin["radiotap_dbm_antsignal"] = s8_str2bin(STROXM_RADIOTAP_DBM_ANTSIGNAL)

_bin2str[STROXM_RADIOTAP_DBM_ANTNOISE] = s8_bin2str("radiotap_dbm_antnoise")
_str2bin["radiotap_dbm_antnoise"] = s8_str2bin(STROXM_RADIOTAP_DBM_ANTNOISE)

_bin2str[STROXM_RADIOTAP_LOCK_QUALITY] = le_bin2str("radiotap_lock_quality={:d}")
_str2bin["radiotap_lock_quality"] = le_str2bin(STROXM_RADIOTAP_LOCK_QUALITY, 2)

_bin2str[STROXM_RADIOTAP_TX_ATTENUATION] = le_bin2str("radiotap_tx_attenuation={:d}")
_str2bin["radiotap_tx_attenuation"] = le_str2bin(STROXM_RADIOTAP_TX_ATTENUATION, 2)

_bin2str[STROXM_RADIOTAP_DB_TX_ATTENUATION] = le_bin2str("radiotap_db_tx_attenuation={:d}")
_str2bin["radiotap_db_tx_attenuation"] = le_str2bin(STROXM_RADIOTAP_DB_TX_ATTENUATION, 2)

_bin2str[STROXM_RADIOTAP_DBM_TX_POWER] = s8_bin2str("radiotap_dbm_tx_power")
_str2bin["radiotap_dbm_tx_power"] = s8_str2bin(STROXM_RADIOTAP_DBM_TX_POWER)

_bin2str[STROXM_RADIOTAP_ANTENNA] = le_bin2str("radiotap_antenna={:d}")
_str2bin["radiotap_antenna"] = le_str2bin(STROXM_RADIOTAP_ANTENNA, 1)

_bin2str[STROXM_RADIOTAP_DB_ANTSIGNAL] = le_bin2str("radiotap_db_antsignal={:d}")
_str2bin["radiotap_db_antsignal"] = le_str2bin(STROXM_RADIOTAP_DB_ANTSIGNAL, 1)

_bin2str[STROXM_RADIOTAP_DB_ANTNOISE] = le_bin2str("radiotap_db_antnoise={:d}")
_str2bin["radiotap_db_antnoise"] = le_str2bin(STROXM_RADIOTAP_DB_ANTNOISE, 1)

_bin2str[STROXM_RADIOTAP_RX_FLAGS] = le_bin2str("radiotap_rx_flags={:#06x}")
_str2bin["radiotap_rx_flags"] = le_str2bin(STROXM_RADIOTAP_RX_FLAGS, 2)

_bin2str[STROXM_RADIOTAP_TX_FLAGS] = le_bin2str("radiotap_tx_flags={:#06x}")
_str2bin["radiotap_tx_flags"] = le_str2bin(STROXM_RADIOTAP_TX_FLAGS, 2)

_bin2str[STROXM_RADIOTAP_RTS_RETRIES] = le_bin2str("radiotap_rts_retries={:d}")
_str2bin["radiotap_rts_retries"] = le_str2bin(STROXM_RADIOTAP_RTS_RETRIES, 1)

_bin2str[STROXM_RADIOTAP_DATA_RETRIES] = le_bin2str("radiotap_data_retries={:d}")
_str2bin["radiotap_data_retries"] = le_str2bin(STROXM_RADIOTAP_DATA_RETRIES, 1)

_bin2str[STROXM_RADIOTAP_MCS] = comp_bin2str("radiotap_mcs", "<3B", "{:#04x} {:d} {:d}".split())
_str2bin["radiotap_mcs"] = comp_str2bin(STROXM_RADIOTAP_MCS, "<3B")

_bin2str[STROXM_RADIOTAP_AMPDU_STATUS] = comp_bin2str("radiotap_ampdu_status", "<IHBB", "{:#010x} {:#06x} {:#04x} {:#02x}".split())
_str2bin["radiotap_ampdu_status"] = comp_str2bin(STROXM_RADIOTAP_AMPDU_STATUS, "<IHBB")

_bin2str[STROXM_RADIOTAP_VHT] = vht_bin2str
_str2bin["radiotap_vht"] = vht_str2bin


def oxm2str(msg, loop=True):
	tokens = []
	while len(msg) >= 4:
		(kls,f1,l) = struct.unpack_from("!HBB", msg)
		if kls == OFPXMC_EXPERIMENTER:
			exp = struct.unpack_from("!I", msg, 4)[0]
			if exp == STRATOS_EXPERIMENTER_ID:
				tokens.append(_bin2str[stratos(f1>>1)](msg[8:4+l], (f1&1)==1))
			else:
				tokens.append("?") # unknown experimenter id
		elif kls == OFPXMC_OPENFLOW_BASIC:
			tokens.append(_bin2str[f1>>1](msg[4:4+l], (f1&1)==1))
		elif kls == OFPXMC_NXM_0:
			tokens.append(_bin2str[nxm_of(f1>>1)](msg[4:4+l], (f1&1)==1))
		elif kls == OFPXMC_NXM_1:
			tokens.append(_bin2str[nxm_nx(f1>>1)](msg[4:4+l], (f1&1)==1))
		else:
			tokens.append("?") # unknown oxm class {:x}".format(kls)
		
		if loop:
			msg = msg[4+l:]
		else:
			break
	
	return ",".join(tokens)

def oxmid2str(msg, loop=True):
	tokens = []
	while len(msg) >= 4:
		rlen = 4
		(kls,f1,l) = struct.unpack_from("!HBB", msg)
		if kls == OFPXMC_EXPERIMENTER:
			rlen = 8
			exp = struct.unpack_from("!I", msg, 4)[0]
			if exp == STRATOS_EXPERIMENTER_ID:
				tokens.append(_bin2str[stratos(f1>>1)](None, (f1&1)==1))
			else:
				tokens.append("?") # unknown experimenter id
		elif kls == OFPXMC_OPENFLOW_BASIC:
			tokens.append(_bin2str[f1>>1](None, (f1&1)==1))
		elif kls == OFPXMC_NXM_0:
			tokens.append(_bin2str[nxm_of(f1>>1)](None, (f1&1)==1))
		elif kls == OFPXMC_NXM_1:
			tokens.append(_bin2str[nxm_nx(f1>>1)](None, (f1&1)==1))
		else:
			tokens.append("?") # unknown oxm class {:x}".format(kls)
		
		if loop:
			msg = msg[rlen:]
		else:
			break
	
	return ",".join(tokens)


def str2oxm(unparsed, loop=True):
	total = len(unparsed)
	msg = b""
	while unparsed:
		head,name,unparsed = get_token(unparsed)
		op,payload,unparsed = get_token(unparsed)
		assert head.find("=") < 0 and op.find("=") >= 0
		bin,length = _str2bin[name](payload)
		if not length:
			break
		
		assert length == len(payload), "{0} pos {1}".format(payload, length)
		msg += bin
		
		if not loop:
			break
	
	return msg, total - len(unparsed)


def str2oxmid(unparsed, loop=True, has_mask=True):
	ret = b""
	while unparsed:
		oxmid = None
		head,name,unparsed = get_token(unparsed)
		if name == "_":
			pass
		elif name in _str2bin:
			bin,length = _str2bin[name](has_mask)
			assert length == 0
			ret += bin
	
	return ret

