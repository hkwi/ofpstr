import struct
from .util import ofpp, parseInt, get_token, parse_func, parse_bits, split
from .oxm import str2oxm, oxm2str, str2oxmid, oxmid2str

align8 = lambda x:(x+7)//8*8

OFPT_FLOW_MOD = 14

OFPTT_MAX = 0xfe
OFPTT_ALL = 0xff

OFPCML_MAX = 0xffe5
OFPCML_NO_BUFFER = 0xffff

OFP_NO_BUFFER = 0xffffffff

for num,name in ofpp.items():
	globals()["OFPP_{:s}".format(name.upper())] = num

ofpg = {
	0xffffff00: "max",
	0xfffffffc: "all",
	0xffffffff: "any",
}
for num,name in ofpg.items():
	globals()["OFPG_{:s}".format(name.upper())] = num

OFPFC_ADD = 0
OFPFC_MODIFY = 1
OFPFC_MODIFY_STRICT = 2
OFPFC_DELETE = 3
OFPFC_DELETE_STRICT = 4

OFPMT_OXM = 1

action_names = {
	0: "output",
	11: "copy_ttl_out",
	12: "copy_ttl_in",
	15: "set_mpls_ttl",
	16: "dec_mpls_ttl",
	17: "push_vlan",
	18: "pop_vlan",
	19: "push_mpls",
	20: "pop_mpls",
	21: "set_queue",
	22: "group",
	23: "set_nw_ttl",
	24: "dec_nw_ttl",
	25: "set_field",
	26: "push_pbb",
	27: "pop_pbb",
	0xffff: "experimenter",
}
for n,name in action_names.items():
	globals()["OFPAT_{:s}".format(name.upper())] = n

def action_generic_str2act(ofpat):
	def str2act(payload, readarg):
		return struct.pack("!HH4x", ofpat, 8), 0
	return str2act

def action_generic_act2str(name):
	def act2str(payload):
		assert payload == bytearray(4)
		return name
	return act2str

def action_uint_str2act(ofpat, pack):
	def str2act(unparsed, readarg):
		h,b,unparsed = get_token(unparsed)
		num,l = parseInt(b)
		assert l==len(b)
		value = struct.pack(pack, num)
		return struct.pack("!HH", ofpat, 4+len(value))+value, len(h)+len(b)

	return str2act

def action_uint_act2str(fmt, pack):
	def act2str(payload):
		return fmt.format(*struct.unpack_from(pack, payload))
	return act2str

def action_output_str2act(unparsed, readarg):
	h,b,unparsed = get_token(unparsed)
	assert b.find("/")<0
	ps = b.split(":", 2)
	port = None
	for num,name in ofpp.items():
		if name == ps[0]:
			port = num
	if port is None:
		port,l = parseInt(ps[0])
		assert len(ps[0]) == l

	maxLen = OFPCML_NO_BUFFER
	if len(ps) > 1:
		maxLen,l = parseInt(ps[1])
		assert len(ps[1]) == l

	return struct.pack("!HHIH6x", OFPAT_OUTPUT, 16, port, maxLen), len(h) + len(b)

def action_output_act2str(payload):
	(port,maxLen) = struct.unpack("!IH6x", payload)
	name = ofpp.get(port, "{:d}".format(port))
	if maxLen == OFPCML_NO_BUFFER:
		return "output={:s}".format(name)
	else:
		return "output={:s}:{:#x}".format(name, maxLen)

def action_push_str2act(ofpat):
	def str2act(unparsed, readarg):
		h,b,unparsed = get_token(unparsed)
		num, l = parseInt(b)
		return struct.pack("!HHH2x", ofpat, 8, num), len(h)+len(b)
	return str2act

def action_push_act2str(name):
	def act2str(payload):
		num = struct.unpack_from("!H", payload)[0]
		return "{:s}={:#06x}".format(name, num)
	return act2str

NX_VENDOR_ID = 0x00002320

class nxast(int):
	def __hash__(self):
		return hash((NX_VENDOR_ID, int(self)))

nxast_names = {
	21: "cnt_ids", # DEC_TTL_CNT_IDS; controller ids to packet-in
	7: "reg_load",
	33: "reg_load2",
	6: "reg_move",
	1: "resubmit",
	14: "resubmit_table",
	2: "set_tunnel",
	9: "set_tunnel64",
	5: "pop_queue",
	8: "note",
	10: "multipath",
	12: "bundle",
	13: "bundle_load",
	15: "output_reg",
	32: "output_reg2",
	16: "learn",
	17: "exit",
	19: "fin_timeout",
	20: "controller",
	22: "write_metadata",
	27: "stack_push",
	28: "stack_pop",
	29: "sample",
	34: "conjunction"
}
for n,name in nxast_names.items():
	globals()["NXAST_{:s}".format(name.upper())] = nxast(n)

def _pad8(bin):
	l = (len(bin)+7)//8*8
	return bin+bytes(bytearray(l-len(bin)))

def _nxast_hdr(subtype):
	return struct.pack("!HHIH", OFPAT_EXPERIMENTER, 10, NX_VENDOR_ID, subtype)

def _fix_act_len(bin):
	if len(bin) == struct.unpack_from("!H", bin, 2):
		return bin
	return bin[0:2]+struct.pack("!H", len(bin))+bin[4:]

def _nxast_str2act(func):
	def str2act(unparsed, readarg):
		bin,rlen = func(unparsed, readarg)
		return _fix_act_len(_pad8(bin)), rlen
	return str2act


@_nxast_str2act
def action_cnt_ids_str2act(unparsed, readarg):
	if readarg:
		op,value,unparsed = get_token(unparsed)
		assert op.find("=")>=0
		ids = value.split(":")
		length = len(op)+len(value)
	else:
		ids = split(unparsed)
		length = 0
	ids = map(lambda x: parseInt(x)[0], ids)
	return _nxast_hdr(NXAST_CNT_IDS)+struct.pack("!H4x{:d}H".format(len(ids)), len(ids), *ids), length

def action_cnt_ids_act2str(payload):
	num = struct.unpack_from("!H", payload)[0]
	return "cnt_ids({:s})".format(",".join(map(lambda x: "{:#x}".format(x), struct.unpack_from("!{:d}H".format(num), payload, 6))))

def action_reg_load_str2act(subtype):
	@_nxast_str2act
	def str2act(unparsed, readarg):
		if readarg:
			raise ValueError("reg_load argument error")
		oxm, rlen = str2oxm(unparsed, loop=False)
		if rlen==0:
			raise ValueError("invalid reg_load argument {0}".format(unparsed))
		
		oxm_class, oxm_field, oxm_length = struct.unpack_from("!HBB", oxm)
		payload = oxm[4:]
		if oxm_class == 0xffff:
			payload = oxm[6:]
		
		if subtype == NXAST_REG_LOAD:
			shift = 0
			nbits = None
			if oxm_field&0x1: # has_mask
				size = len(payload)//2
				mask = payload[size:]
				payload = payload[:size]
				for m in reversed(mask):
					v = ord(m)
					for d in range(8):
						if v & (1<<d):
							if nbits is None:
								nbits = 0
							nbits += 1
						elif nbits is None:
							shift += 1
						else:
							break
			else:
				size = len(payload)
				nbits = size * 8
			
			value = 0
			for p in payload:
				value = (value<<8) + ord(p)
			
			value = value>>shift
			return _nxast_hdr(NXAST_REG_LOAD)+struct.pack("!HHBBQ",
				(shift<<6)+(nbits-1), oxm_class, oxm_field&0xfe, size, value), rlen
		elif subtype == NXAST_REG_LOAD2:
			return _nxast_hdr(NXAST_REG_LOAD2)+oxm, rlen
		else:
			return b"", 0
	return str2act

def action_reg_load_act2str(payload):
	ofs_nbits,oxm_class,oxm_field,oxm_length,value = struct.unpack_from("!HHBBQ", payload)
	name = oxmid2str(payload[2:6])
	oxmid = str2oxmid(name, loop=False, has_mask=False)
	info = struct.unpack_from("!HBB", oxmid)
	size = info[2]
	
	shift = ofs_nbits>>6
	nbits = (ofs_nbits & 0x3f) + 1
	if shift == 0 and nbits == size*8:
		has_mask = False
		u = b""
		for s in range(size):
			u = chr(value>>(s*8))+u
		arg = oxm2str(oxmid+u)
	else:
		value = value<<shift
		mask = 0
		for s in range(nbits):
			mask = (mask<<1) + 1
		for s in range(shift):
			mask = mask<<1
		
		u = b""
		for s in range(size):
			u = chr((mask>>(s*8))&0xff)+u
		for s in range(size):
			u = chr((value>>(s*8))&0xff)+u
		
		import binascii
		print binascii.b2a_hex(struct.pack("!HBB", oxm_class, oxm_field|0x1, size*2)+u)
		arg = oxm2str(struct.pack("!HBB", oxm_class, oxm_field|0x1, size*2)+u)
	
	return "reg_load({:s})".format(arg)

def action_reg_load2_act2str(payload):
	return "reg_load2({:s})".format(oxm2str(payload, loop=False))

#
# cnt_ids=id1:id2:id3
# reg_load=0xFE:eth_dst[0:2]
# reg_load2=0xFE:dot11_addr1[0:2]
# reg_move=eth_dst[0:2]:eth_src[0:2]
# reg_move=nxm_reg0[0:4]:nxm_reg1[0:4]
# resubmit=in_port
# resubmit_table=in_port:all
# set_tunnel=0xff
# pop_queue
#


_str2act = {}
_act2str = {}

_str2act["output"] = action_output_str2act
_act2str[OFPAT_OUTPUT] = action_output_act2str

_str2act["copy_ttl_out"] = action_generic_str2act(OFPAT_COPY_TTL_OUT)
_act2str[OFPAT_COPY_TTL_OUT] = action_generic_act2str("copy_ttl_out")

_str2act["copy_ttl_in"] = action_generic_str2act(OFPAT_COPY_TTL_IN)
_act2str[OFPAT_COPY_TTL_IN] = action_generic_act2str("copy_ttl_in")

_str2act["set_mpls_ttl"] = action_uint_str2act(OFPAT_SET_MPLS_TTL, "!B3x")
_act2str[OFPAT_SET_MPLS_TTL] = action_uint_act2str("set_mpls_ttl={:d}", "!B3x")

_str2act["dec_mpls_ttl"] = action_generic_str2act(OFPAT_DEC_MPLS_TTL)
_act2str[OFPAT_DEC_MPLS_TTL] = action_generic_act2str("dec_mpls_ttl")

_str2act["push_vlan"] = action_push_str2act(OFPAT_PUSH_VLAN)
_act2str[OFPAT_PUSH_VLAN] = action_push_act2str("push_vlan")

_str2act["pop_vlan"] = action_generic_str2act(OFPAT_POP_VLAN)
_act2str[OFPAT_POP_VLAN] = action_generic_act2str("pop_vlan")

_str2act["push_mpls"] = action_push_str2act(OFPAT_PUSH_MPLS)
_act2str[OFPAT_PUSH_MPLS] = action_push_act2str("push_mpls")

_str2act["pop_mpls"] = action_push_str2act(OFPAT_POP_MPLS)
_act2str[OFPAT_POP_MPLS] = action_push_act2str("pop_mpls")

_str2act["push_mpls"] = action_push_str2act(OFPAT_PUSH_MPLS)
_act2str[OFPAT_PUSH_MPLS] = action_push_act2str("push_mpls")

_str2act["set_queue"] = action_uint_str2act(OFPAT_SET_QUEUE, "!I")
_act2str[OFPAT_SET_QUEUE] = action_uint_act2str("set_queue={:d}", "!I")

_str2act["group"] = action_uint_str2act(OFPAT_GROUP, "!I")
_act2str[OFPAT_GROUP] = action_uint_act2str("group={:d}", "!I")

_str2act["set_nw_ttl"] = action_uint_str2act(OFPAT_SET_NW_TTL, "!B")
_act2str[OFPAT_SET_NW_TTL] = action_uint_act2str("set_nw_ttl={:d}", "!B")

_str2act["dec_nw_ttl"] = action_generic_str2act(OFPAT_DEC_NW_TTL)
_act2str[OFPAT_DEC_NW_TTL] = action_generic_act2str("dec_nw_ttl")

_str2act["push_pbb"] = action_push_str2act(OFPAT_PUSH_PBB)
_act2str[OFPAT_PUSH_PBB] = action_push_act2str("push_pbb")

_str2act["pop_pbb"] = action_generic_str2act(OFPAT_POP_PBB)
_act2str[OFPAT_POP_PBB] = action_generic_act2str("pop_pbb")

_str2act["cnt_ids"] = action_cnt_ids_str2act
_act2str[NXAST_CNT_IDS] = action_cnt_ids_act2str

_str2act["reg_load"] = action_reg_load_str2act(NXAST_REG_LOAD)
_act2str[NXAST_REG_LOAD] = action_reg_load_act2str

_str2act["reg_load2"] = action_reg_load_str2act(NXAST_REG_LOAD2)
_act2str[NXAST_REG_LOAD2] = action_reg_load2_act2str

def str2act(s):
	h,name,arg = get_token(s)
	fname,farg = parse_func(name)

	if farg and fname in _str2act:
		b,p = _str2act[fname](farg, False)
		return bytes(b), len(h)+len(name)
	elif name in _str2act:
		b,p = _str2act[name](arg, True)
		return bytes(b), len(h)+len(name)+p
	elif name.startswith("set_"):
		if farg:
			op,payload,s = get_token(farg)
			oxm,p = str2oxm(fname[4:]+"="+payload, loop=False)
		else:
			op,payload,s = get_token(arg)
			oxm,p = str2oxm(name[4:]+op+payload, loop=False)

		l = align8(len(oxm)+4)
		ret = bytearray(l)
		ret[:4] = struct.pack("!HH", OFPAT_SET_FIELD, l)
		ret[4:4+len(oxm)] = oxm
		return bytes(ret), len(h)+4+p
	else:
		return b"", len(h)

def act2str(msg, loop=True):
	tokens = []
	while len(msg) > 4:
		(atype,l) = struct.unpack_from("!HH", msg)
		offset = 4
		if atype == OFPAT_EXPERIMENTER:
			vendor = struct.unpack_from("!I", msg, 4)[0]
			if vendor == NX_VENDOR_ID:
				atype = nxast(struct.unpack_from("!H", msg, 8)[0])
				offset = 10

		act = _act2str.get(atype)
		if atype == OFPAT_SET_FIELD:
			tokens.append("set_"+oxm2str(msg[4:], loop=False))
		elif act:
			tokens.append(act(msg[offset:l]))
		else:
			tokens.append("?")

		if loop:
			msg = msg[l:]
		else:
			break

	return ",".join(tokens)

instruction_names = {
	1: "goto_table",
	2: "write_metadata",
	3: "write_actions",
	4: "apply_actions",
	5: "clear_actions",
	6: "meter"
}
for n,name in instruction_names.items():
	globals()["OFPIT_{:s}".format(name.upper())] = n


def inst2str(msg, loop=True):
	tokens = []
	while len(msg) > 4:
		(itype,l) = struct.unpack_from("!HH", msg)
		if itype == OFPIT_GOTO_TABLE:
			assert l==8
			tokens.append("@goto={:d}".format(*struct.unpack_from("!B", msg, 4)))
		elif itype == OFPIT_WRITE_METADATA:
			assert l==24
			(v,m) = struct.unpack_from("!QQ", msg, 8)
			if m == 0:
				tokens.append("@metadata={:#x}".format(v))
			else:
				tokens.append("@metadata={:#x}/{:#x}".format(v,m))
		elif itype == OFPIT_WRITE_ACTIONS:
			assert l%8==0
			tokens.append("@write")
			arg = act2str(msg[8:l])
			if len(arg):
				tokens.append(arg)
		elif itype == OFPIT_APPLY_ACTIONS:
			assert l%8==0
			tokens.append("@apply")
			arg = act2str(msg[8:l])
			if len(arg):
				tokens.append(arg)
		elif itype == OFPIT_CLEAR_ACTIONS:
			assert l == 8
			tokens.append("@clear")
		elif itype == OFPIT_METER:
			assert l == 8, repr(msg)
			tokens.append("@meter={:d}".format(*struct.unpack_from("!I", msg, 4)))
		else:
			tokens.append("?")

		if loop:
			msg = msg[l:]
		else:
			break

	return ",".join(tokens)

PHASE_MATCH = 0
PHASE_ACTION = 1
PHASE_NOARG = 2

def str2dict(s, defaults={}):
	ret = {}
	ret.update(defaults)
	ret.update(dict(
		match= b"",
		inst= b"",
	))

	actions = b""
	def inst_action(atype):
		def func():
			ret["inst"] += struct.pack("!HH4x", atype, 8+len(actions))+actions
		return func

	func = None
	phase = PHASE_MATCH
	while len(s) > 0:
		h,name,s = get_token(s)
		assert h.find("=")<0
		if name.startswith("@"):
			if func is not None:
				func()

			func = None
			phase = PHASE_NOARG
			if name in ("@goto", "@goto_table"):
				op,payload,s = get_token(s)
				assert op.find("=")>=0, "goto requires arg"
				num,l = parseInt(payload)
				assert l == len(payload)
				ret["inst"] += struct.pack("!HHB3x", OFPIT_GOTO_TABLE, 8, num)
			elif name in ("@metadata", "@write_metadata"):
				op,payload,s = get_token(s)
				assert op.find("=")>=0, "metadata requires arg"
				vm = payload.split("/", 1)
				num,l = parseInt(vm[0])
				assert l == len(vm[0])
				if len(vm) > 1:
					mask,l = parseInt(vm[1])
					assert l == len(vm[1])
					ret["inst"] += struct.pack("!HH4xQQ", OFPIT_WRITE_METADATA, 24, num, mask)
				else:
					ret["inst"] += struct.pack("!HH4xQQ", OFPIT_WRITE_METADATA, 24, num, 0)
			elif name in ("@apply", "@apply_actions"):
				func = inst_action(OFPIT_APPLY_ACTIONS)
				actions = b""
				phase = PHASE_ACTION
			elif name in ("@write", "@write_actions"):
				func = inst_action(OFPIT_WRITE_ACTIONS)
				actions = b""
				phase = PHASE_ACTION
			elif name in ("@clear", "@clear_actions"):
				ret["inst"] += struct.pack("!HH4x", OFPIT_CLEAR_ACTIONS, 8)
			elif name == "@meter":
				op,payload,s = get_token(s)
				assert op.find("=")>=0, "metadata requires arg"
				assert payload.find("/") < 0, "meter does not take mask"
				num,l = parseInt(payload)
				assert l == len(payload)
				ret["inst"] += struct.pack("!HHI", OFPIT_METER, 8, num)
			else:
				raise ValueError("unknown {:s}".format(name))
		elif phase == PHASE_MATCH:
			def proc(field):
				op,payload,unparsed = get_token(s)
				assert op.find("=")>=0 and payload.find("/")<0
				num,l = parseInt(payload)
				assert len(payload) == l
				ret[field] = num
				return unparsed

			if name in ("table", "priority", "idle_timeout", "hard_timeout", "buffer"):
				s = proc(name)
			elif name == "cookie":
				op,payload,s = get_token(s)
				assert op.find("=")>=0, "cookie take value"
				vm = payload.split("/", 1)
				num,l = parseInt(vm[0])
				assert len(vm[0]) == l
				ret[name] = num
				if len(vm) > 1:
					num,l = parseInt(vm[1])
					ret["cookie_mask"] = num
			elif name == "out_port":
				op,payload,s = get_token(s)
				assert op.find("=") >= 0 and payload.find("/") < 0
				port = None
				for num,pname in ofpp.items():
					if pname == payload:
						port = num
				if port is None:
					port,l = parseInt(payload)
					assert l == len(payload)
				ret[name] = port
			elif name == "out_group":
				op,payload,s = get_token(s)
				assert op.find("=")>=0 and payload.find("/")<0
				port = None
				for num,gname in ofpg.items():
					if gname == payload:
						port = num
				if port is None:
					port,l = parseInt(payload)
					assert l == len(payload)
				ret[name] = port
			else:
				oxm, l = str2oxm(name+s, loop=False)
				if l == 0:
					raise ValueError("unknown match {:s}".format(s))
				ret["match"] += oxm
				s = (name+s)[l:]
		elif phase == PHASE_ACTION:
			act, l = str2act(name+s)
			if l == 0:
				raise ValueError("unknown action {:s}".format(s))
			actions += act
			s = (name+s)[l:]
		else:
			raise ValueError("invalid syntax")
	if func:
		func()

	return ret


ofpfc_del_default = dict(
	table= OFPTT_ALL,
	out_port= OFPP_ANY,
	out_group= OFPG_ANY,
)

ofpfc_default = dict(
	buffer = OFP_NO_BUFFER,
)

def str2mod(s, cmd=OFPFC_ADD, xid=0):
	default = ofpfc_default
	if cmd in (OFPFC_DELETE, OFPFC_DELETE_STRICT):
		default = ofpfc_del_default

	info = str2dict(s, default)

	OFPMT_OXM = 1
	oxm = info.get("match", b"")
	length = 4 + len(oxm)
	match = struct.pack("!HH", OFPMT_OXM, length) + oxm
	match += b"\0" * (align8(length)-length)

	inst = info.get("inst", b"")

	return struct.pack("!BBHIQQBBHHHIIIH2x", 4, OFPT_FLOW_MOD, 48+align8(length)+len(inst), xid,
		info.get("cookie", 0),
		info.get("cookie_mask", 0),
		info.get("table", 0),
		cmd,
		info.get("idle_timeout", 0),
		info.get("hard_timeout", 0),
		info.get("priority", 0),
		info.get("buffer", OFP_NO_BUFFER),
		info.get("out_port", default.get("out_port", 0)),
		info.get("out_group", default.get("out_group", 0)),
		0)+match+inst

def mod2str(msg):
	(hdr_version, hdr_type, hdr_length, hdr_xid,
	cookie,
	cookie_mask,
	table,
	cmd,
	idle_timeout,
	hard_timeout,
	priority,
	buffer_id,
	out_port,
	out_group,
	flags,
	match_type,
	match_length) = struct.unpack_from("!BBHIQQBBHHHIIIH2xHH", msg)

	default = ofpfc_default
	if cmd in (OFPFC_DELETE, OFPFC_DELETE_STRICT):
		default = ofpfc_del_default

	ret = []
	if cookie_mask != 0:
		ret.append("cookie={:#x}/{:#x}".format(cookie, cookie_mask))
	elif cookie != 0:
		ret.append("cookie={:#x}".format(cookie))

	if table != default.get("table", 0):
		ret.append("table={:d}".format(table))

	if priority != 0:
		ret.append("priority={:d}".format(priority))

	if buffer_id != default.get("buffer", 0):
		ret.append("buffer={:#x}".format(buffer_id))

	if out_port != default.get("out_port", 0):
		if out_port in ofpp:
			ret.append("out_port={:s}".format(ofpp[out_port]))
		else:
			ret.append("out_port={:d}".format(out_port))

	if out_group != default.get("out_group", 0):
		if out_group in ofpg:
			ret.append("out_group={:s}".format(ofpg[out_group]))
		else:
			ret.append("out_group={:d}".format(out_group))

	if idle_timeout != 0:
		ret.append("idle_timeout={:d}".format(idle_timeout))

	if hard_timeout != 0:
		ret.append("hard_timeout={:d}".format(hard_timeout))

	if match_type == OFPMT_OXM:
		rstr = oxm2str(msg[52:52+match_length-4])
		if len(rstr):
			ret.append(rstr)
	else:
		raise ValueError("match_type {:d} not supported".format(match_type))

	istr = inst2str(msg[48+align8(match_length):])
	if len(istr):
		ret.append(istr)

	return ",".join(ret)
