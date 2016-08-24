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
OFPMP_GROUP = 6
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

ofpgc = ("add", "modify", "delete")
for num, name in enumerate(ofpgc):
	globals()["OFPGC_{:s}".format(name.upper())] = num

ofpgt = ("all", "select", "indirect", "ff")
for num, name in enumerate(ofpgt):
	globals()["OFPGT_{:s}".format(name.upper())] = num

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

def str2dict(s):
	'''convert a string into a flow rule information dictionary'''
	ret = dict(
		match= b"",
		inst= b"",
	)

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

def _fixed(default, **kwargs):
	'''
	@param default parameters the is equal in this will be suppressed
	'''
	def emit(name):
		return name in kwargs and kwargs[name] != default.get(name)
	
	ret = []
	if emit("cookie_mask"):
		ret.append("cookie={:#x}/{:#x}".format(kwargs["cookie"], kwargs["cookie_mask"]))
	elif emit("cookie"):
		ret.append("cookie={:#x}".format(kwargs["cookie"]))
	
	if emit("table"):
		ret.append("table={:d}".format(kwargs["table"]))

	if emit("priority"):
		ret.append("priority={:d}".format(kwargs["priority"]))

	if emit("buffer"):
		ret.append("buffer={:#x}".format(kwargs["buffer"]))

	if emit("out_port"):
		out_port = kwargs["out_port"]
		if out_port in ofpp:
			ret.append("out_port={:s}".format(ofpp[out_port]))
		else:
			ret.append("out_port={:d}".format(out_port))

	if emit("out_group"):
		out_group = kwargs["out_group"]
		if out_group in ofpg:
			ret.append("out_group={:s}".format(ofpg[out_group]))
		else:
			ret.append("out_group={:d}".format(out_group))

	if emit("idle_timeout"):
		ret.append("idle_timeout={:d}".format(kwargs["idle_timeout"]))

	if emit("hard_timeout"):
		ret.append("hard_timeout={:d}".format(kwargs["hard_timeout"]))
	
	if emit("flags"):
		for name,num in ofpff.items():
			if kwargs["flags"] & num:
				ret.append(name)
	
	return ret

def bucket2str(msg, group_type=OFPGT_ALL):
	(length,
	weight,
	watch_port,
	watch_group) = struct.unpack_from("!HHII4x", msg)
	
	ret = []
	if group_type == OFPGT_SELECT and weight != 1:
		ret.append("weight={:d}".format(weight))
	if watch_port != OFPP_ANY:
		ret.append("watch_port={:d}".format(watch_port))
	if watch_group != OFPG_ANY:
		ret.append("watch_group={:d}".format(watch_group))
	
	a = act2str(msg[16:length])
	if a:
		ret.append(a)
	
	return ",".join(ret)

def str2bucket(s, group_type=OFPGT_ALL):
	info = dict(
		weight=0,
		watch_port=OFPP_ANY,
		watch_group=OFPG_ANY)
	if group_type == OFPGT_SELECT:
		info["weight"] = 1
	
	actions = b""
	unparsed = s
	while len(unparsed):
		h,name,r = get_token(unparsed)
		assert h.find("=") < 0
		if name.startswith("@"):
			break
		elif name in ("weight", "watch_port", "watch_group"):
			op,payload,unparsed = get_token(r)
			assert op.find("=")>=0
			num,l = parseInt(payload)
			assert len(payload) == l
			info[name] = num
		else:
			b,l = str2act(unparsed)
			if l > 0:
				actions += b
				unparsed = unparsed[l:]
			else:
				break
	
	consumed_length = len(s) - len(unparsed)
	if consumed_length == 0:
		return b"", 0
	return struct.pack("!HHII4x",
		16 + len(actions),
		info["weight"],
		info["watch_port"],
		info["watch_group"]) + actions, consumed_length


# OFPT_FLOW_MOD

ofpfc_del_default = dict(
	cookie = 0,
	cookie_mask = 0,
	table = OFPTT_ALL,
	idle_timeout = 0,
	hard_timeout = 0,
	priority = 0x8000,
	buffer = 0,
	out_port = OFPP_ANY,
	out_group = OFPG_ANY,
	flags = 0,
)

ofpfc_default = dict(
	cookie = 0,
	cookie_mask = 0,
	table = 0,
	idle_timeout = 0,
	hard_timeout = 0,
	priority = 0x8000,
	buffer = OFP_NO_BUFFER,
	out_port = 0,
	out_group = 0,
	flags = 0,
)

def str2mod(s, command=OFPFC_ADD, xid=0):
	default = ofpfc_default
	if command in (OFPFC_DELETE, OFPFC_DELETE_STRICT):
		default = ofpfc_del_default

	info = dict(default)
	info.update(str2dict(s))

	OFPMT_OXM = 1
	oxm = info.get("match", b"")
	length = 4 + len(oxm)
	match = struct.pack("!HH", OFPMT_OXM, length) + oxm
	match += b"\0" * (align8(length)-length)

	inst = info.get("inst", b"")

	return struct.pack("!BBHIQQBBHHHIIIH2x", 4, OFPT_FLOW_MOD, 48+align8(length)+len(inst), xid,
		info["cookie"],
		info["cookie_mask"],
		info["table"],
		command,
		info["idle_timeout"],
		info["hard_timeout"],
		info["priority"],
		info["buffer"],
		info["out_port"],
		info["out_group"],
		info["flags"])+match+inst

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


# OFPT_GROUP_MOD

def str2group(s, command=OFPGC_ADD, xid=0):
	group_id=OFPG_ANY
	group_type=OFPGT_ALL

	unparsed = s
	while len(unparsed) > 0:
		h,name,r = get_token(unparsed)
		if name == "group":
			op,payload,r = get_token(r)
			if payload.lower() == "all":
				group_id = OFPG_ALL
			else:
				num,l = parseInt(payload)
				assert len(payload) == l
				group_id = num
			
			unparsed = r
		elif name in ofpgt:
			group_type = ofpgt.index(name)
			unparsed = r
		else:
			break

	buckets = b""
	info = {}
	while len(unparsed) > 0:
		b, l = str2bucket(unparsed, group_type=group_type)
		if l:
			buckets += b
			unparsed = unparsed[l:]
		else:
			h,name,r = get_token(unparsed)
			if not name or name == "@bucket":
				unparsed = r
			else:
				break
	
	assert not unparsed, unparsed

	return struct.pack("!BBHIHBxI",
		4, OFPT_GROUP_MOD, 16+len(buckets), xid,
		command, group_type, group_id) + buckets

def group2str(msg):
	(hv, ht, hl, xid,
	command, group_type, group_id) = struct.unpack_from("!BBHIHBxI", msg)
	
	if group_id == OFPG_ALL:
		ret = ["group=all"]
	elif group_id == OFPG_ANY:
		ret = []
	else:
		ret = ["group={:d}".format(group_id)]
	
	ret.append(ofpgt[group_type])
	
	bin = msg[16:]
	while len(bin) > 16:
		(l,) = struct.unpack_from("!H", bin)
		ret += ["@bucket",
			bucket2str(bin[:l], group_type=group_type)]
		bin = bin[l:]
	
	return ",".join(ret)

def group2extra(msg):
	(hdr_version, hdr_type, hdr_length, hdr_xid,
	command,
	group_type,
	group_id) = struct.unpack_from("!BBHIHBxI", msg)
	
	assert hdr_type == OFPT_GROUP_MOD
	
	ret = dict(xid=hdr_xid, group_id=group_id)
	if command != OFPGC_ADD:
		ret["command"] = command
	return ret


# OFPMP_FLOW / OFPT_MULTIPART_*

def text2mpflow(txt, type=OFPT_MULTIPART_REPLY, xid=0):
	def parse(s):
		ret = {}
		while len(s) > 0:
			h,name,r = get_token(s)
			if name not in ("packet_count", "byte_count", "duration_sec", "duration_nsec"):
				break
			
			op,payload,s = get_token(r)
			assert op.find("=")>=0 and payload.find("/")<0
			num,l = parseInt(payload)
			assert l == len(payload)
			ret[name] = num
		
		ret.update(str2dict(s))
		return ret
	
	rules = [parse(s) for s in txt.split("\n")]
	
	if type!=OFPT_MULTIPART_REPLY and not rules:
		rules = [{}]
	
	msgs = b""
	capture = b""
	for info in rules:
		oxm = info["match"]
		length = 4 + len(oxm)
		match = struct.pack("!HH", OFPMT_OXM, length) + oxm
		match += b"\0" * (align8(length)-length)

		inst = info["inst"]

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
			msgs += struct.pack("!BBHIHH4x",
				4, type, 16+len(capture), xid,
				OFPMP_FLOW, flag)+capture
			capture = body
		else:
			capture += body
	
	msgs += struct.pack("!BBHIHH4x",
		4, type, 16+len(capture), xid,
		OFPMP_FLOW, 0) + capture
	
	return msgs

def mpflow2text_one(msg):
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
		defaults = dict(
			table = OFPTT_ALL,
			out_port = OFPP_ANY,
			out_group = OFPG_ANY,
			cookie=0,
			cookie_mask=0)
		ret = _fixed(defaults,
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
		rules.append(flow=",".join(ret))
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

			defaults = dict(
				cookie = 0,
				table = 0,
				priority = 0x8000,
				idle_timeout = 0,
				hard_timeout = 0,
				flags = 0)
			ret = _fixed(defaults,
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

			c = []
			L = locals()
			for name in ("packet_count", "byte_count", "duration_sec", "duration_nsec"):
				if L[name]:
					c.append("{:s}={:d}".format(name, L[name]))
			
			rules.append(" ".join([",".join(x) for x in [c, ret] if x]))
			body = body[length:]
	return rules

def mpflow2text(msgs):
	rows = []
	while msgs:
		(hv, ht, hl, xid) = struct.unpack_from("!BBHI", msgs)
		rows += mpflow2text_one(msgs[:hl])
		msgs = msgs[hl:]
	return "\n".join(rows)


# OFPMP_GROUP_DESC / OFPT_MULTIPART_*

def text2mpgroupdesc(txt, type=OFPT_MULTIPART_REPLY, xid=0):
	if type != OFPT_MULTIPART_REPLY:
		return struct.pack("!BBHIHH4x",
			4, type, 16, xid, OFPMP_GROUP_DESC, 0)
	
	msgs = b""
	capture = b""
	for s in txt.split("\n"):
		group_id = 0
		group_type = OFPGT_ALL
		
		ret = {}
		while len(s) > 0:
			h,name,r = get_token(s)
			if name == "group":
				op,payload,s = get_token(r)
				assert op.find("=")>=0 and payload.find("/")<0
				num,l = parseInt(payload)
				assert l == len(payload)
				group_id = num
			elif name.lower() in ofpgt:
				group_type = ofpgt.index(name.lower())
				s = r
			else:
				break
		
		bs = b""
		while len(s) > 0:
			h,name,r = get_token(s)
			if name == "@bucket":
				s = r
				continue
			
			b,l = str2bucket(s, group_type=group_type)
			if l:
				s = s[l:]
				bs += b
			else:
				break
		
		body = struct.pack("!HBxI",
			8+len(bs), group_type, group_id) + bs
		
		if len(body)+len(capture) > 0xffff - 16:
			msgs += struct.pack("!BBHIHH4x",
				4, type, 16+len(capture), xid,
				OFPMP_GROUP_DESC,
				OFPMPF_REPLY_MORE)+capture
			capture = body
		else:
			capture += body
	msgs += struct.pack("!BBHIHH4x",
		4, type, 16+len(capture), xid,
		OFPMP_GROUP_DESC,
		0) + capture
	return msgs

def mpgroupdesc2text_one(msg):
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
		
		ret = ["group={:d}".format(group_id),
			ofpgt[group_type]]
		bin = r[8:length]
		while len(bin) >= 16:
			(l,) = struct.unpack_from("!H", bin)
			ret += ["@bucket",
				bucket2str(bin[:l], group_type=group_type)]
			bin = bin[l:]
		
		groups.append(",".join(ret))
		r = r[length:]
	
	return groups

def mpgroupdesc2text(msgs):
	rows = []
	while msgs:
		(hv, ht, hl, xid) = struct.unpack_from("!BBHI", msgs)
		rows += mpgroupdesc2text_one(msgs[:hl])
		msgs = msgs[hl:]
	return "\n".join(rows)



# OFPMP_GROUP / OFPT_MULTIPART_*

def text2mpgroup(txt, type=OFPT_MULTIPART_REPLY, xid=0):
	msgs = b""
	capture = b""
	for s in txt.split("\n"):
		group_id = 0
		
		while len(s) > 0:
			h,name,r = get_token(s)
			if name == "group":
				op,payload,s = get_token(r)
				assert op.find("=")>=0 and payload.find("/")<0
				num,l = parseInt(payload)
				assert l == len(payload)
				
				group_id = num
			else:
				break
		
		if type != OFPT_MULTIPART_REPLY:
			capture = struct.pack("!I4x", group_id)
			break
		
		group = {}
		buckets = []
		while len(s) > 0:
			h,name,r = get_token(s)
			if name == "@bucket":
				buckets.append({})
				s = r
				continue
			
			op,payload,s = get_token(r)
			assert op.find("=")>=0 and payload.find("/")<0
			num,l = parseInt(payload)
			assert l == len(payload)
			
			if buckets:
				if name in ("packet_count", "byte_count"):
					buckets[-1][name] = num
				else:
					break
			elif name in ("ref_count", "packet_count", "byte_count", "duration_sec", "duration_nsec"):
				group[name] = num
			else:
				break
		
		bs = b"".join([struct.pack("!QQ",
			b.get("packet_count", 0), b.get("byte_count", 0)) for b in buckets])
		
		body = struct.pack("!H2xII4xQQII",
			40+len(bs), group_id,
			group.get("ref_count", 0),
			group.get("packet_count", 0),
			group.get("byte_count", 0),
			group.get("duration_sec", 0),
			group.get("duration_nsec", 0)) + bs
		
		if len(body)+len(capture) > 0xffff - 16:
			msgs += struct.pack("!BBHIHH4x",
				4, type, 16+len(capture), xid,
				OFPMP_GROUP,
				OFPMPF_REPLY_MORE) + capture
			capture = body
		else:
			capture += body
	msgs += struct.pack("!BBHIHH4x",
		4, type, 16+len(capture), xid,
		OFPMP_GROUP,
		0) + capture
	return msgs

def mpgroup2text_one(msg):
	(hdr_version, hdr_type, hdr_length, hdr_xid,
	mp_type,
	mp_flags) = struct.unpack_from("!BBHIHH4x", msg)
	
	assert mp_type == OFPMP_GROUP, "OFPMP_GROUP required"
	
	if hdr_type != OFPT_MULTIPART_REPLY:
		(group_id,) = struct.unpack_from("!I4x", msg, 16)
		if group_id == OFPG_ALL:
			return [] # default
		elif group_id == OFPG_ANY:
			return ["group=any"]
		else:
			return ["group={:d}".format(group_id)]
	
	groups = []
	r = msg[16:hdr_length]
	
	while len(r) >= 40:
		(length, group_id, ref_count,
		packet_count, byte_count,
		duration_sec, duration_nsec) = struct.unpack_from("!H2xII4xQQII", r)
		assert length>=40
		
		group = []
		L = locals()
		for k in ("ref_count", "packet_count", "byte_count",
				"duration_sec", "duration_nsec"):
			if L[k]:
				group.append("{:s}={:d}".format(k, L[k]))
		
		bs = r[40:length]
		while len(bs) >= 16:
			group.append("@bucket")
			(pc,bc) = struct.unpack_from("!QQ", bs)
			if pc != 0:
				group.append("packet_count={:d}".format(pc))
			if bc != 0:
				group.append("byte_count={:d}".format(bc))
			bs = bs[16:]
		
		stat = ",".join(group)
		if group_id == OFPG_ALL:
			groups.append("group=all " + stat)
		elif group_id == OFPG_ANY:
			groups.append(stat)
		else:
			groups.append("group={:d} ".format(group_id) + stat)

		r = r[length:]
	
	return groups

def mpgroup2text(msgs):
	rows = []
	while msgs:
		(hv, ht, hl, xid) = struct.unpack_from("!BBHI", msgs)
		rows += mpgroup2text_one(msgs[:hl])
		msgs = msgs[hl:]
	return "\n".join(rows)
