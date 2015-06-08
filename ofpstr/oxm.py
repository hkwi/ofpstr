import struct
import re
import socket
import binascii

from .util import get_value, get_unit, parseInt, parseFloat, ofpp

try:
	L0 = long(0)
except:
	L0 = 0
	long = int

OFPXMC_OPENFLOW_BASIC = 0x8000
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


STRATOS_EXPERIMENTER_ID = 0xFF00E04D

STRATOS_OXM_FIELD_BASIC = 0
STRATOS_OXM_FIELD_RADIOTAP = 1

class stratos_basic(int):
	def __hash__(self):
		return hash((STRATOS_OXM_FIELD_BASIC, int(self)))

class stratos_radiotap(int):
	def __hash__(self):
		return hash((STRATOS_OXM_FIELD_RADIOTAP, int(self)))

stratos_names = '''unknown
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
	dot11_tag_vendor'''.split()
for (i,n) in enumerate(stratos_names):
	if n != "_":
		globals()["STROXM_BASIC_{:s}".format(n.upper())] = stratos_basic(i)

radiotap_names = '''
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
for (i,n) in enumerate(radiotap_names):
	if n != "_":
		globals()["STROXM_RADIOTAP_{:s}".format(n.upper())] = stratos_radiotap(i)


_bin2str = {}
_str2bin = {}

def header(field_or_etype):
	if isinstance(field_or_etype, stratos_basic):
		return struct.pack("!HBBIH", OFPXMC_EXPERIMENTER, STRATOS_OXM_FIELD_BASIC<<1, 0,
			STRATOS_EXPERIMENTER_ID, field_or_etype)
	elif isinstance(field_or_etype, stratos_radiotap):
		return struct.pack("!HBBIH", OFPXMC_EXPERIMENTER, STRATOS_OXM_FIELD_RADIOTAP<<1, 0,
			STRATOS_EXPERIMENTER_ID, field_or_etype)
	else:
		return struct.pack("!HBB", OFPXMC_OPENFLOW_BASIC, (field_or_etype<<1), 0)


def uint_bin2str(fmt):
	def bin2str(payload, has_mask):
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


def uint_str2bin(field_or_etype, size):
	hdr = header(field_or_etype)
	def str2bin(unparsed):
		ret = bytearray(hdr)
		
		num,l = parseInt(unparsed)
		for s in reversed(range(size)):
			ret.append(0xFF & (num>>(8*s)))
		
		if unparsed[l:].startswith("/"):
			num,e = parseInt(unparsed[l+1:])
			for s in reversed(range(size)):
				ret.append(0xFF & (num>>(8*s)))
			
			l += e + 1
			ret[2] |= 1
			ret[3] = len(hdr) - 4 + size * 2
		else:
			ret[3] = len(hdr) - 4 + size
		
		return bytes(ret), l
	
	return str2bin


def port_bin2str(name):
	def bin2str(payload, has_mask):
		assert not has_mask, "{:s} does not take mask".format(name)
		assert len(payload) == 4, repr(payload)
		num = struct.unpack_from("!I", payload)[0]
		if num in ofpp:
			return "{:s}={:s}".format(name, ofpp[num])
		else:
			return "{:s}={:d}".format(name, num)
	
	return bin2str


def port_str2bin(field):
	def str2bin(unparsed):
		def build(num):
			return struct.pack("!HBBI", OFPXMC_OPENFLOW_BASIC, field<<1, 4, num)
		
		for (v,name) in ofpp.items():
			if unparsed.startswith(name):
				return build(v), len(name)
		
		v, l = parseInt(unparsed)
		return build(v), l
	
	return str2bin


def mac_bin2str(name):
	def bin2str(payload, has_mask):
		value = ":".join(map("{:02x}".format, struct.unpack("!6B", payload[:6])))
		if has_mask:
			assert len(payload) == 12
			return "{:s}={:s}/{:s}".format(name, value, ":".join(map("{:02x}".format, struct.unpack("!6B", payload[6:]))))
		else:
			assert len(payload) == 6
			return "{:s}={:s}".format(name, value)
	
	return bin2str


def mac_str2bin(field_or_etype):
	hdr = header(field_or_etype)
	def str2bin(unparsed):
		ret = bytearray(hdr)
		
		def scan(txt):
			for r,l in (("([0-9A-Fa-f]{12})", 12),
					(".".join(["([0-9A-Fa-f]{4})"]*3), 14),
					(":".join(["([0-9A-Fa-f]{2})"]*6), 17),
					("-".join(["([0-9A-Fa-f]{2})"]*6), 17)):
				m = re.match("^"+r, txt)
				if m:
					return "".join(m.groups()), l
			
			raise ValueError("mac format error {:s}".format(txt))
		
		value, l = scan(unparsed)
		if unparsed[l:].startswith("/"):
			mask, l2 = scan(unparsed[l+1:])
			
			ret[2] |= 1
			ret[3] = len(hdr) - 4 + 12
			return ret+binascii.a2b_hex(value+mask), l+l2+1
		else:
			ret[3] = len(hdr) - 4 + 6
			return ret+binascii.a2b_hex(value), l
	
	return str2bin


def ipv4_bin2str(name):
	def bin2str(payload, has_mask):
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
		lead, v, ext, m = get_value(unparsed)
		value = socket.inet_aton(v)
		if ext is not None:
			try:
				mask = socket.inet_aton(m)
			except ValueError:
				mask_len = int(m)
				mask = struct.pack("!I", 0xFFFFFFFF<<(32-mask_len))
			
			return struct.pack("!HBB", OFPXMC_OPENFLOW_BASIC, (field<<1)+1, 8)+value+mask, len(lead)+len(v)+len(ext)
		else:
			return struct.pack("!HBB", OFPXMC_OPENFLOW_BASIC, field<<1, 4)+value, len(lead)+len(v)
	
	return str2bin


def ipv6_bin2str(name):
	def bin2str(payload, has_mask):
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
		lead, v, ext, m = get_value(unparsed)
		value = socket.inet_pton(socket.AF_INET6, v)
		if ext is not None:
			try:
				mask = socket.inet_pton(socket.AF_INET6, m)
			except:
				mask_len = int(m)
				mask_int = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF<<(128-int(mask_len))
				mask = struct.pack("!QQ", mask_int>>64, mask_int&0xFFFFFFFFFFFFFFFF)
			
			return struct.pack("!HBB", OFPXMC_OPENFLOW_BASIC, (field<<1)+1, 32)+value+mask, len(lead)+len(v)+len(ext)
		else:
			return struct.pack("!HBB", OFPXMC_OPENFLOW_BASIC, field<<1, 16)+value, len(lead)+len(v)
	
	return str2bin


def pkt_bin2str(payload, has_mask):
	assert not has_mask
	assert len(payload) == 4
	return "packet_type={:#x}:{:#x}".format(*struct.unpack("!HH", payload))


def pkt_str2bin(unparsed):
	ns, l = parseInt(unparsed)
	assert unparsed[l] == ":"
	ns_type, l2 = parseInt(unparsed[l+1:])
	return struct.pack("!HBBHH", OFPXMC_OPENFLOW_BASIC, OXM_OF_PACKET_TYPE<<1, 4, ns, ns_type), l+l2+1


def hex_bin2str(name):
	def bin2str(payload, has_mask):
		if has_mask:
			split = len(payload)//2
			return "{:s}={:s}/{:s}".format(name,
				binascii.b2a_hex(payload[:split]).decode("UTF-8"),
				binascii.b2a_hex(payload[split:]).decode("UTF-8"))
		else:
			return "{:s}={:s}".format(name,
				binascii.b2a_hex(payload).decode("UTF-8"))
	
	return bin2str


def hex_str2bin(field_or_etype):
	hdr = header(field_or_etype)
	def str2bin(unparsed):
		lead, v, ext, m = get_value(unparsed)
		value = bytearray.fromhex(v)
		if ext is not None:
			mask = bytearray.fromhex(m)
			bl = max(len(value), len(mask))
			ret = bytearray(len(hdr) + bl*2)
			ret[:len(hdr)] = hdr
			ret[2] |= 1
			ret[3] = len(hdr) - 4 + bl*2
			ret[len(hdr):] = value + mask
			return bytes(ret), len(lead)+len(v)+len(ext)
		else:
			ret = bytearray(len(hdr)+len(value))
			ret[:len(hdr)] = hdr
			ret[3] = len(hdr) - 4 + len(value)
			ret[len(hdr):] = value
			return bytes(ret), len(lead)+len(v)
	
	return str2bin


def ssid_bin2str(payload, has_mask):
	if has_mask:
		split = len(payload)//2
		return "dot11_ssid={:s}/{:s}".format(
			payload[:split].decode("UTF-8").partition("\0")[0],
			binascii.b2a_hex(payload[split:]).decode("UTF-8"))
	else:
		return "dot11_ssid={:s}".format(payload.decode("UTF-8").partition("\0")[0])


def ssid_str2bin(unparsed):
	lead, v, ext, m = get_value(unparsed)
	value = v.encode("UTF-8")
	if ext is not None:
		mask = bytearray.fromhex(m)
		bl = max(len(value), len(mask))
		
		payload = bytearray(bl*2)
		payload[:len(value)] = value
		payload[bl:bl+len(mask)] = mask
		ret = struct.pack("!HBBIH", OFPXMC_EXPERIMENTER, (STRATOS_OXM_FIELD_BASIC<<1)|1, 10+bl*2,
			STRATOS_EXPERIMENTER_ID, STROXM_BASIC_DOT11_SSID)+payload
		return ret, len(lead)+len(v)+len(ext)
	else:
		ret = struct.pack("!HBBIH", OFPXMC_EXPERIMENTER, STRATOS_OXM_FIELD_BASIC<<1, 10+len(value),
			STRATOS_EXPERIMENTER_ID, STROXM_BASIC_DOT11_SSID)+value
		return ret, len(lead)+len(v)


def le_bin2str(fmt):
	def bin2str(payload, has_mask):
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


def le_str2bin(field_or_etype, size):
	hdr = header(field_or_etype)
	def str2bin(unparsed):
		ret = bytearray(hdr)
		
		num,l = parseInt(unparsed)
		for s in range(size):
			ret.append(0xFF & (num>>(8*s)))
		
		if unparsed[l:].startswith("/"):
			num,e = parseInt(unparsed[l+1:])
			for s in range(size):
				ret.append(0xFF & (num>>(8*s)))
			
			l += e + 1
			ret[2] |= 1
			ret[3] = len(hdr) - 4 + size * 2
		else:
			ret[3] = len(hdr) - 4 + size
		
		return bytes(ret), l
	
	return str2bin


def rate_bin2str(payload, has_mask):
	assert not has_mask
	rate = struct.unpack_from("!B", payload)[0]
	if rate < 2:
		return "radiotap_rate={:.1f}K".format(rate*500.0)
	else:
		return "radiotap_rate={:.1f}M".format(float(rate)/2.0)


def rate_str2bin(unparsed):
	num, l = parseFloat(unparsed)
	if unparsed[l] == "K":
		rate = num / 500
	elif unparsed[l] == "M":
		rate = num * 2
	else:
		raise ValueError("rate unit error")
	
	return struct.pack("!HBBIHB", OFPXMC_EXPERIMENTER, STRATOS_OXM_FIELD_RADIOTAP<<1, 11,
		STRATOS_EXPERIMENTER_ID, STROXM_RADIOTAP_RATE, int(rate)), l+1


def ch_bin2str(payload, has_mask):
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
	ret = bytearray(header(STROXM_RADIOTAP_CHANNEL))
	v1,l = parseInt(unparsed)
	assert unparsed[l] == ":"
	v2,l2 = parseInt(unparsed[l+1:])
	ret += struct.pack("!HH", v1, v2)
	
	if unparsed[l+1+l2:].startswith("/"):
		m1 = 0
		l3 = 0
		if not unparsed[l+1+l2+1:].startswith(":"):
			m1,l3 = parseInt(unparsed[l+1+l2+1:])
		assert unparsed[l+1+l2+1+l3:].startswith(":")
		m2,l4 = parseInt(unparsed[l+1+l2+1+l3+1:])
		
		ret[2] |= 1
		ret[3] = 14
		ret += struct.pack("!HH", m1, m2)
		return bytes(ret), sum((l, l2, l3, l4, 3))
	else:
		ret[3] = 10
		return bytes(ret), sum((l, l2, 1))


def comp_bin2str(name, packs, fmts):
	def bin2str(payload, has_mask):
		def collect(data):
			ret = []
			for n,fmt in zip(struct.unpack_from(packs, data), fmts):
				if n == 0:
					ret.append("")
				else:
					ret.append(fmt.format(n))
			return ":".join(ret)
		
		ret = "{:s}=".format(name)
		ret += collect(payload)
		if has_mask:
			ret += "/"
			ret += collect(payload[struct.calcsize(packs):])
		
		return ret

	return bin2str


def comp_str2bin(field_or_etype, packs):
	hdr = header(field_or_etype)
	def str2bin(unparsed):
		def collect(txt):
			ps = []
			for t in txt.split(":"):
				v = l = 0
				if len(t):
					v, l = parseInt(t)
					assert len(t) == l
				ps.append(v)
			
			return struct.pack(packs, *ps)
		
		lead, v, ext, m = get_value(unparsed)
		value = collect(v)
		if ext is not None:
			mask = collect(m)
			ret = bytearray(len(hdr) + len(value) + len(mask))
			ret[:len(hdr)] = hdr
			ret[2] |= 1
			ret[3] = len(ret) - 4
			ret[len(hdr):] = value + mask
			return bytes(ret), len(lead)+len(v)+len(ext)
		else:
			ret = bytearray(len(hdr) + len(value))
			ret[:len(hdr)] = hdr
			ret[3] = len(ret) - 4
			ret[len(hdr):] = value
			return bytes(ret), len(lead)+len(v)
	
	return str2bin


def vht_bin2str(payload, has_mask):
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
	
	ret = "radiotap_vht="
	ret += collect(payload)
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
	
	lead, v, ext, m = get_value(unparsed)
	hdr = header(STROXM_RADIOTAP_VHT)
	value = collect(v)
	if ext is not None:
		mask = collect(m)
		ret = bytearray(len(hdr) + struct.calcsize(packs)*2)
		ret[:len(hdr)] = hdr
		ret[2] |= 1
		ret[3] = len(ret) - 4
		ret[len(hdr):] = value+mask
		return bytes(ret), len(lead)+len(v)+len(ext)
	else:
		ret = bytearray(len(hdr) + struct.calcsize(packs))
		ret[:len(hdr)] = hdr
		ret[3] = len(ret) - 4
		ret[len(hdr):] = value
		return bytes(ret), len(lead)+len(v)


def s8_bin2str(name):
	def bin2str(payload, has_mask):
		assert not has_mask
		return "{:s}={:d}".format(name, struct.unpack("<b", payload)[0])
	
	return bin2str


def s8_str2bin(field_or_etype):
	hdr = header(field_or_etype)
	def str2bin(unparsed):
		ret = bytearray(hdr)
		num,l = parseInt(unparsed)
		ret[3] = len(hdr) - 4 + 1
		ret += struct.pack("<b", num)
		return bytes(ret), l
	
	return str2bin


def si_bin2str(name): # Little endian
	def bin2str(payload, has_mask):
		assert not has_mask
		return "{:s}={:d}".format(name, struct.unpack("<i", payload)[0])
	
	return bin2str


def si_str2bin(field_or_etype): # Little endian
	hdr = header(field_or_etype)
	def str2bin(unparsed):
		ret = bytearray(hdr)
		num,l = parseInt(unparsed)
		ret[3] = len(hdr) - 4 + 4
		ret += struct.pack("<i", num)
		return bytes(ret), l
	
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

_bin2str[OXM_OF_TCP_FLAGS] = uint_bin2str("tcp_flags={:04x}/{:04x}")
_str2bin["tcp_flags"] = uint_str2bin(OXM_OF_TCP_FLAGS, 2)

_bin2str[OXM_OF_ACTSET_OUTPUT] = port_bin2str("actset_output")
_str2bin["actset_output"] = port_str2bin(OXM_OF_ACTSET_OUTPUT)

_bin2str[OXM_OF_PACKET_TYPE] = pkt_bin2str
_str2bin["packet_type"] = pkt_str2bin

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

_bin2str[STROXM_RADIOTAP_DBM_TX_POWER] = si_bin2str("radiotap_dbm_tx_power")
_str2bin["radiotap_dbm_tx_power"] = si_str2bin(STROXM_RADIOTAP_DBM_TX_POWER)

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
	while len(msg) > 4:
		(kls,f1,l) = struct.unpack_from("!HBB", msg)
		if kls == OFPXMC_OPENFLOW_BASIC:
			tokens.append(_bin2str[f1>>1](msg[4:4+l], (f1&1)==1))
		elif kls == OFPXMC_EXPERIMENTER:
			exp = struct.unpack_from("!I", msg, 4)[0]
			if exp == STRATOS_EXPERIMENTER_ID:
				etype = struct.unpack_from("!H", msg, 8)[0]
				field = f1>>1
				if field == STRATOS_OXM_FIELD_BASIC:
					tokens.append(_bin2str[stratos_basic(etype)](msg[10:4+l], (f1&1)==1))
				elif field == STRATOS_OXM_FIELD_RADIOTAP:
					tokens.append(_bin2str[stratos_radiotap(etype)](msg[10:4+l], (f1&1)==1))
				else:
					tokens.append("?") # unknown stratos field
			else:
				tokens.append("?") # unknown experimenter id
		else:
			tokens.append("?") # unknown oxm class {:x}".format(kls)
		
		if loop:
			msg = msg[4+l:]
		else:
			break
	
	return ",".join(tokens)


def str2oxm(unparsed, loop=True):
	step = 0
	msg = b""
	while loop:
		try:
			lead, key, op, payload = get_unit(unparsed[step:])
			b,p = _str2bin[key](payload)
			if not p:
				break
			
			msg += b
			step += len(lead)+len(key)+len(op)+p
		except:
			break
	
	return msg, step
