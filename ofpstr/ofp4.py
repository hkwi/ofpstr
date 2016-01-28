import binascii
import struct
from .util import ofpp, parseInt, get_token, parse_func
from .oxm import str2oxm, oxm2str
from .nx import nxast, register_nxast, NX_VENDOR_ID

align8 = lambda x:(x+7)//8*8

OFPT_FLOW_MOD = 14
OFPT_GROUP_MOD = 15
OFPT_MULTIPART_REQUEST = 18
OFPT_MULTIPART_REPLY = 19

OFPMP_FLOW = 1
OFPMP_GROUP_DESC = 7

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

ofpff = {
	"send_flow_rem": 1<<0,
	"check_overlap": 1<<1,
	"reset_counts": 1<<2,
	"no_pkt_counts": 1<<3,
	"no_byt_counts": 1<<4 }

for name,num in ofpff.items():
	globals()["OFPFF_{:s}".format(name.upper())] = num

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
	if port == OFPP_CONTROLLER and maxLen != OFPCML_NO_BUFFER:
		return "output={:s}:{:#x}".format(name, maxLen)
	else:
		return "output={:s}".format(name)

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

register_nxast(_str2act, _act2str)

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
			consumed_length = len(h)+len(name)
		else:
			op,payload,s = get_token(arg)
			oxm,p = str2oxm(name[4:]+op+payload, loop=False)
			consumed_length = len(h)+4+p

		l = align8(len(oxm)+4)
		ret = bytearray(l)
		ret[:4] = struct.pack("!HH", OFPAT_SET_FIELD, l)
		ret[4:4+len(oxm)] = oxm
		return bytes(ret), consumed_length
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
				assert op.find("=")>=0, "meter requires arg"
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
			elif name in ofpff:
				ret["flags"] = ret.get("flags", 0) | ofpff[name]
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

def _fixed(default, cookie=0, cookie_mask=0,
		priority=0, buffer=0,
		idle_timeout=0, hard_timeout=0,
		flags=0, **kwargs):
	ret = []
	if cookie_mask != 0:
		ret.append("cookie={:#x}/{:#x}".format(cookie, cookie_mask))
	elif cookie != 0:
		ret.append("cookie={:#x}".format(cookie))

	k = "table"
	if k in kwargs and k in default and kwargs[k] != default[k]:
		table = kwargs[k]
		ret.append("table={:d}".format(table))

	if priority != 0:
		ret.append("priority={:d}".format(priority))

	if buffer != default.get("buffer", 0):
		ret.append("buffer={:#x}".format(buffer))

	k = "out_port"
	if k in kwargs and k in default and kwargs[k] != default[k]:
		out_port = kwargs[k]
		if out_port in ofpp:
			ret.append("out_port={:s}".format(ofpp[out_port]))
		else:
			ret.append("out_port={:d}".format(out_port))

	k = "out_group"
	if k in kwargs and k in default and kwargs[k] != default[k]:
		out_group = kwargs[k]
		if out_group in ofpg:
			ret.append("out_group={:s}".format(ofpg[out_group]))
		else:
			ret.append("out_group={:d}".format(out_group))

	if idle_timeout != 0:
		ret.append("idle_timeout={:d}".format(idle_timeout))

	if hard_timeout != 0:
		ret.append("hard_timeout={:d}".format(hard_timeout))
	
	for name,num in ofpff.items():
		if flags & num:
			ret.append(name)
	
	return ret

ofpgc = ("add", "modify", "delete")
for num, name in enumerate(ofpgc):
	globals()["OFPGC_{:s}".format(name.upper())] = num

ofpgt = ("all", "select", "indirect", "ff")
for num, name in enumerate(ofpgt):
	globals()["OFPGT_{:s}".format(name.upper())] = num

def buckets2str(msg, group_type=OFPGT_ALL):
	buckets = []
	while len(msg) >= 16:
		(length,
		weight,
		watch_port,
		watch_group) = struct.unpack_from("!HHII4x", msg)
		ret = dict(actions=act2str(msg[16:length]))
		if group_type == OFPGT_SELECT:
			ret["weight"] = weight
		if group_type == OFPGT_FF:
			if watch_port != OFPP_ANY:
				ret["watch_port"] = watch_port
			if watch_group != OFPG_ANY:
				ret["watch_group"] = watch_group
		buckets.append(ret)
		msg = msg[length:]
	return buckets

def str2buckets(buckets, group_type=OFPGT_ALL):
	default = {}
	if group_type == OFPGT_FF:
		default = dict(watch_port=OFPP_ANY, watch_group=OFPG_ANY)
	
	ret = b""
	for b in buckets:
		acts,_ = str2act(b.get("actions", ""))
		ret += struct.pack("!HHII4x",
			align8(16+len(acts)),
			b.get("weight", 0),
			b.get("watch_port", default.get("watch_port", 0)),
			b.get("watch_group", default.get("watch_group", 0)))
		ret += acts
		ret += b"\0"*(align8(len(acts))-len(acts))
	return ret

ofpfc_del_default = dict(
	table = OFPTT_ALL,
	out_port = OFPP_ANY,
	out_group = OFPG_ANY,
)

ofpfc_default = dict(
	table = 0,
	buffer = OFP_NO_BUFFER,
)

def str2mod(s, command=OFPFC_ADD, xid=0):
	default = ofpfc_default
	if command in (OFPFC_DELETE, OFPFC_DELETE_STRICT):
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
		command,
		info.get("idle_timeout", 0),
		info.get("hard_timeout", 0),
		info.get("priority", 0),
		info.get("buffer", default.get("buffer", 0)),
		info.get("out_port", default.get("out_port", 0)),
		info.get("out_group", default.get("out_group", 0)),
		info.get("flags", 0))+match+inst

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

	ret = _fixed(default,
		cookie=cookie,
		cookie_mask=cookie_mask,
		table=table,
		priority=priority,
		buffer=buffer_id,
		out_port=out_port,
		out_group=out_group,
		idle_timeout=idle_timeout,
		hard_timeout=hard_timeout,
		flags=flags)

	if match_type == OFPMT_OXM:
		rstr = oxm2str(msg[52:52+match_length-4])
		if len(rstr):
			ret.append(rstr)
	else:
		raise ValueError("match_type {:d} not supported".format(match_type))

	istr = inst2str(msg[48+align8(match_length):hdr_length])
	if len(istr):
		ret.append(istr)

	return ",".join(ret)

def mod2extra(msg):
	(hdr_version, hdr_type, hdr_length, hdr_xid,
	cookie,
	cookie_mask,
	table,
	cmd) = struct.unpack_from("!BBHIQQBB", msg)
	if cmd != OFPFC_ADD:
		return dict(command=cmd, xid=hdr_xid)
	return dict(xid=hdr_xid)

def str2flows(rules, type=OFPT_MULTIPART_REPLY, xid=0):
	if type!=OFPT_MULTIPART_REPLY and not rules:
		rules = [{}]
	
	msgs = []
	capture = b""
	for rule in rules:
		r = dict(rule)
		info = str2dict(r.pop("flow", ""), r)
		
		oxm = info.get("match", b"")
		length = 4 + len(oxm)
		match = struct.pack("!HH", OFPMT_OXM, length) + oxm
		match += b"\0" * (align8(length)-length)

		inst = info.get("inst", b"")

		body = b""
		if type!=OFPT_MULTIPART_REPLY:
			body = struct.pack("!B3xII4xQQ",
				info.get("table", OFPTT_ALL),
				info.get("out_port", OFPP_ANY),
				info.get("out_group", OFPG_ANY),
				info.get("cookie", 0),
				info.get("cookie_mask", 0)) + match
		else:
			body = struct.pack("!HBxIIHHHH4xQQQ",
				48 + len(match) + len(inst),
				info.get("table", 0),
				info.get("duration_sec", 0),
				info.get("duration_nsec", 0),
				info.get("priority", 0),
				info.get("idle_timeout", 0),
				info.get("hard_timeout", 0),
				info.get("flags", 0),
				info.get("cookie", 0),
				info.get("packet_count", 0),
				info.get("byte_count", 0)) + match + inst
		
		if len(capture) + len(body) > 0xffff - 16:
			flag = OFPMPF_REPLY_MORE
			if type==OFPT_MULTIPART_REQUEST:
				flag = OFPMPF_REQ_MORE
			msgs.append(struct.pack("!BBHIHH4x",
				4, type, 16+len(capture), xid,
				OFPMP_FLOW, flag)+capture)
			capture = body
		else:
			capture += body
	
	msgs.append(struct.pack("!BBHIHH4x",
		4, type, 16+len(capture), xid,
		OFPMP_FLOW, 0)+capture)
	return msgs

def flows2str(msg):
	(hdr_version, hdr_type, hdr_length, hdr_xid,
	mp_type,
	mp_flags) = struct.unpack_from("!BBHIHH4x", msg)
	
	assert mp_type == OFPMP_FLOW, "OFPMP_FLOW required"
	
	rules = []
	body = msg[16:hdr_length]
	if hdr_type != OFPT_MULTIPART_REPLY:
		(table_id,
		out_port,
		out_group,
		cookie,
		cookie_mask,
		match_type,
		match_length) = struct.unpack_from("!B3xII4xQQHH", body)
		ret = _fixed({"table":OFPTT_ALL, "out_port":OFPP_ANY, "out_group":OFPG_ANY},
			table=table_id,
			out_port=out_port,
			out_group=out_group,
			cookie=cookie,
			cookie_mask=cookie_mask)
		if match_type == OFPMT_OXM:
			rstr = oxm2str(body[36:36+match_length-4])
			if len(rstr):
				ret.append(rstr)
		else:
			raise ValueError("match_type {:d} not supported".format(match_type))
		rules.append(dict(flow=",".join(ret)))
	else:
		while len(body) >= 56:
			(length,
			table_id,
			duration_sec,
			duration_nsec,
			priority,
			idle_timeout,
			hard_timeout,
			flags,
			cookie,
			packet_count,
			byte_count,
			match_type,
			match_length) = struct.unpack_from("!HBxIIHHHH4xQQQHH", body)

			ret = _fixed({"table": 0},
				cookie=cookie,
				table=table_id,
				priority=priority,
				idle_timeout=idle_timeout,
				hard_timeout=hard_timeout,
				flags=flags)

			if match_type == OFPMT_OXM:
				rstr = oxm2str(body[52:52+match_length-4])
				if len(rstr):
					ret.append(rstr)
			else:
				raise ValueError("match_type {:d} not supported".format(match_type))

			istr = inst2str(body[48+align8(match_length):length])
			if len(istr):
				ret.append(istr)

			rules.append(dict(
				flow=",".join(ret),
				duration_sec=duration_sec,
				duration_nsec=duration_nsec,
				packet_count=packet_count,
				byte_count=byte_count))
			body = body[length:]
	return rules

def flows2extra(msg):
	(hdr_version, hdr_type, hdr_length, hdr_xid,
	mp_type,
	mp_flags) = struct.unpack_from("!BBHIHH4x", msg)
	
	assert mp_type == OFPMP_FLOW, "OFPMP_FLOW required"
	
	ret = dict(xid=hdr_xid)
	if hdr_type != OFPT_MULTIPART_REPLY:
		ret["type"] = hdr_type
	
	if mp_flags != 0:
		ret["flags"] = mp_flags
	
	return ret

def str2group(buckets, command=OFPGC_ADD, group_type=OFPGT_ALL, group_id=0, xid=0):
	body = str2buckets(buckets, group_type=group_type)
	return struct.pack("!BBHIHBxI",
		4, OFPT_GROUP_MOD, 16+len(body), xid,
		command, group_type, group_id) + body

def group2str(msg):
	(hdr_version, hdr_type, hdr_length, hdr_xid,
	command,
	group_type,
	group_id) = struct.unpack_from("!BBHIHBxI", msg)
	assert hdr_type == OFPT_GROUP_MOD
	return buckets2str(msg[16:hdr_length], group_type)

def group2extra(msg):
	(hdr_version, hdr_type, hdr_length, hdr_xid,
	command,
	group_type,
	group_id) = struct.unpack_from("!BBHIHBxI", msg)
	
	assert hdr_type == OFPT_GROUP_MOD
	
	ret = dict(xid=hdr_xid, group_id=group_id)
	if command != OFPGC_ADD:
		ret["command"] = command
	if group_type != OFPGT_ALL:
		ret["group_type"] = group_type
	return ret

def str2groups_desc(groups, type=OFPT_MULTIPART_REPLY, xid=0):
	if type != OFPT_MULTIPART_REPLY:
		return [struct.pack("!BBHIHH4x",
			4, type, 16, xid, OFPMP_GROUP_DESC, 0)]
	
	msgs = []
	capture = b""
	for g in groups:
		bs = str2buckets(g.get("buckets", []),
			group_type=g.get("group_type", OFPGT_ALL))
		body = struct.pack("!HBxI",
			8+len(bs),
			g.get("group_type", OFPGT_ALL),
			g.get("group_id", 0)) + bs
		if len(body)+len(capture) > 0xffff - 16:
			msgs.append(struct.pack("!BBHIHH4x",
				4, type, 16+len(capture), xid,
				OFPMP_GROUP_DESC,
				OFPMPF_REPLY_MORE)+capture)
			capture = body
		else:
			capture += body
	msgs.append(struct.pack("!BBHIHH4x",
		4, type, 16+len(capture), xid,
		OFPMP_GROUP_DESC,
		0)+capture)
	return msgs

def groups_desc2str(msg):
	(hdr_version, hdr_type, hdr_length, hdr_xid,
	mp_type,
	mp_flags) = struct.unpack_from("!BBHIHH4x", msg)
	
	assert mp_type == OFPMP_GROUP_DESC, "OFPMP_GROUP_DESC required"
	
	if hdr_type != OFPT_MULTIPART_REPLY:
		return []
	
	groups = []
	r = msg[16:hdr_length]
	while len(r) >= 8:
		(length, group_type, group_id) = struct.unpack_from("!HBxI", r)
		assert length>=8
		group = dict(
			group_id=group_id,
			buckets=buckets2str(r[8:length], group_type=group_type))
		if group_type != OFPGT_ALL:
			group["group_type"] = group_type
		groups.append(group)
		r = r[length:]
	
	return groups

def groups_desc2extra(msg):
	(hdr_version, hdr_type, hdr_length, hdr_xid,
	mp_type,
	mp_flags) = struct.unpack_from("!BBHIHH4x", msg)
	
	assert mp_type == OFPMP_GROUP_DESC, "OFPMP_GROUP_DESC required"
	
	ret = dict(xid=hdr_xid)
	if hdr_type != OFPT_MULTIPART_REPLY:
		ret["type"] = hdr_type
	return ret
