import binascii
import struct
from .util import ofpp, parseInt, get_token, split, parse_func
from .oxm import str2oxm, oxm2str, str2oxmid, oxmid2str

align8 = lambda x:(x+7)//8*8

OFPAT_EXPERIMENTER = 0xffff
NX_VENDOR_ID = 0x00002320

nx_hash_names = ("eth_src", "symmetric_l4")
for n,name in enumerate(nx_hash_names):
	globals()["NX_HASH_FIELDS_{:s}".format(name.upper())] = n

nx_mp_alg_names = ("modulo_n", "hash_threshold", "hrw", "iter_hash")
for n,name in enumerate(nx_mp_alg_names):
	globals()["NX_MP_ALG_{:s}".format(name.upper())] = n

nx_bd_alg_names = ("active_backup", "hrw")
for n,name in enumerate(nx_bd_alg_names):
	globals()["NX_BD_ALG_{:s}".format(name.upper())] = n

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
	return bin+bytes(bytearray(align8(len(bin))-len(bin)))

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

def get_bits(unparsed):
	h1,F,unparsed = get_token(unparsed)
	name,arg = parse_func(F)
	oxmid = str2oxmid(name, has_mask=False, loop=False)
	oxm_class,oxm_field,oxm_length = struct.unpack_from("!HBB", oxmid)
	size = oxm_length
	if oxm_class == 0xffff:
		size = oxm_length-4
	
	shift = 0
	nbits = size*8
	if arg:
		shift,limit = map(lambda x: int(x) if len(x) else None, arg.split(":", 1))
		if shift is None:
			shift = 0
		if limit is None:
			limit = size*8
		nbits = limit - shift
	return oxmid, shift, nbits, unparsed

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
		
		arg = oxm2str(struct.pack("!HBB", oxm_class, oxm_field|0x1, size*2)+u)
	
	return "reg_load({:s})".format(arg)

def action_reg_load2_act2str(payload):
	return "reg_load2({:s})".format(oxm2str(payload, loop=False))

@_nxast_str2act
def action_reg_move_str2act(unparsed, readarg):
	if readarg:
		raise ValueError("reg_move argument error")
	
	total = len(unparsed)
	loxm, lshift, lnbits, unparsed = get_bits(unparsed)
	roxm, rshift, rnbits, unparsed = get_bits(unparsed)
	assert lnbits == rnbits
	
	return _nxast_hdr(NXAST_REG_MOVE)+struct.pack(
		"!HHH", lnbits, rshift, lshift)+roxm+loxm, total-len(unparsed)

def action_reg_move_act2str(payload):
	n_bits, src_ofs, dst_ofs = struct.unpack_from("!HHH", payload)
	src = oxmid2str(payload[6:], loop=False)
	sinfo = struct.unpack_from("!HBB", payload, 6)
	if src_ofs == 0 and n_bits == sinfo[2]*8:
		arg = src
	else:
		arg = "{:s}[{:d}:{:d}]".format(src, src_ofs, src_ofs+n_bits)
	
	doffset = 10
	if sinfo[0] == 0xffff:
		doffset = 14
	dst = oxmid2str(payload[doffset:], loop=False)
	dinfo = struct.unpack_from("!HBB", payload, doffset)
	if dst_ofs == 0 and n_bits == sinfo[2]*8:
		arg = dst+"="+arg
	else:
		arg = "{:s}[{:d}:{:d}]={:s}".format(dst, dst_ofs, dst_ofs+n_bits, arg)
	
	return "reg_move({:s})".format(arg)

def action_resubmit_str2act(subtype):
	@_nxast_str2act
	def str2act(unparsed, readarg):
		total = len(unparsed)
		h,p,unparsed=get_token(unparsed)
		port = None
		if p.upper() == "IN_PORT":
			port = 0xfff8
		if port is None:
			port, rlen = parseInt(p)
			assert len(p) == rlen
			assert port < 0xff00
		
		tbl = ""
		if readarg:
			assert "=" in h
			if subtype == NXAST_RESUBMIT_TABLE and unparsed.startswith(":"):
				h2,tbl,unparsed = get_token(unparsed[1:])
		elif subtype == NXAST_RESUBMIT_TABLE:
			h2,tbl,unparsed = get_token(unparsed)
		
		if len(tbl)==0 or tbl.upper() == "ALL":
			table = 0xff
		else:
			table, rlen = parseInt(tbl)
			assert rlen == len(tbl)
		
		return _nxast_hdr(subtype)+struct.pack("!HB", port, table), total-len(unparsed)
	return str2act

def action_resubmit_act2str(payload):
	p = struct.unpack_from("!H", payload)[0]
	port = "in_port" if p==0xfff8 else "{:d}".format(p)
	return "resubmit({:s})".format(port)

def action_resubmit_table_act2str(payload):
	p,tbl = struct.unpack_from("!HB", payload)
	port = "in_port" if p==0xfff8 else "{:d}".format(p)
	if tbl == 0xff:
		table = "all"
	else:
		table = "{:d}".format(tbl)
	return "resubmit_table({:s},{:s})".format(port, table)

def action_set_tunnel_str2act(subtype):
	@_nxast_str2act
	def str2act(unparsed, readarg):
		h,b,unparsed = get_token(unparsed)
		if readarg:
			assert "=" in h
		num, rlen = parseInt(b)
		assert rlen==len(b)
		fmt = "!I"
		stype = subtype
		if num > 0xffffffff:
			stype = NXAST_SET_TUNNEL64
			fmt = "!Q"
		
		return _nxast_hdr(stype)+struct.pack(fmt, num), len(h)+len(b)
	return str2act

def action_set_tunnel_act2str(size, fmt):
	def act2str(payload):
		if size==4:
			num = struct.unpack_from("!I", payload)[0]
		elif size==8:
			num = struct.unpack_from("!Q", payload)[0]
		return fmt.format(num)
	return act2str

def action_null_str2act(subtype):
	@_nxast_str2act
	def str2act(unparsed, readarg):
		return _nxast_hdr(subtype), 0
	return str2act

def action_null_act2str(fmt):
	def act2str(payload):
		return fmt
	return act2str

def action_qp_str2act(subtype):
	def str2act(unparsed, readarg):
		h,b,unparsed = get_token(unparsed)
		if readarg:
			assert "=" in h
		return _fix_act_len(_nxast_hdr(subtype)+binascii.a2b_qp(b)), len(h)+len(b)
	return str2act

def action_qp_act2str(fmt):
	def act2str(payload):
		return fmt.format(binascii.b2a_qp(payload))
	return act2str

@_nxast_str2act
def action_multipath_str2act(unparsed, readarg):
	if readarg:
		raise ValueError("multipath argument must be in func style")
	total = len(unparsed)
	h,hash_name,unparsed = get_token(unparsed)
	mhash = nx_hash_names.index(hash_name)
	h,basis_str,unparsed = get_token(unparsed)
	basis,rlen = parseInt(basis_str) # basis, nx_hash universal parameter
	assert rlen == len(basis_str)
	h,mp_alg_name,unparsed = get_token(unparsed)
	malg = nx_mp_alg_names.index(mp_alg_name)
	h,link_str,unparsed = get_token(unparsed)
	max_link, rlen = parseInt(link_str)
	assert rlen == len(link_str)
	h,arg_str,unparsed = get_token(unparsed)
	arg, rlen = parseInt(arg_str)
	h3,dst,unparsed = get_token(unparsed)
	oxm, shift, nbits, junk = get_bits(dst)
	assert len(junk) == 0
	return _nxast_hdr(NXAST_MULTIPATH)+struct.pack("!HH2xHHI2xH",
		mhash, basis, malg, max_link, arg, (shift<<6)+(nbits-1)
		)+oxm, total-len(unparsed)

def action_multipath_act2str(payload):
	mhash,basis,malg,max_link,arg,ofs_nbits = struct.unpack_from("!HH2xHHI2xH", payload)
	shift = ofs_nbits>>6
	nbits = (ofs_nbits&0x3f)+1
	dst = oxmid2str(payload[18:], loop=False)
	return "multipath({:s},{:d},{:s},{:d},{:#x},{:s}[{:d}:{:d}])".format(
		nx_hash_names[mhash],
		basis,
		nx_mp_alg_names[malg],
		max_link,
		arg,
		dst,
		shift,
		shift+nbits)

@_nxast_str2act
def action_bundle_str2act(unparsed, readarg):
	total = len(unparsed)
	if readarg:
		raise ValueError("func style")
	# bundle(<hash_fields>, <basis>, <bundle_algorithm>, <slave_type>, slaves(<slaves>, ...))
	_,fields,unparsed = get_token(unparsed)
	_,basis,unparsed = get_token(unparsed)
	_,algorithm,unparsed = get_token(unparsed)
	_,slave_type,unparsed = get_token(unparsed)
	_,slaves,unparsed = get_token(unparsed)
	
	fields = nx_hash_names.index(fields)
	basis, rlen = parseInt(basis)
	algorithm = nx_bd_alg_names.index(algorithm)
	oxmid = str2oxmid(slave_type, loop=False)
	sname, sargs = parse_func(slaves)
	assert sname == "slaves"
	slaves = []
	if sargs:
		for p in split(sargs):
			port = None
			for num,pname in ofpp.items():
				if pname == p:
					port = num
			if port is None:
				port,rlen = parseInt(p)
			slaves.append(port)
	
	parts = [_nxast_hdr(NXAST_BUNDLE),
		struct.pack("!HHH", algorithm, fields, basis),
		oxmid,
		struct.pack("!HHI4x", len(slaves), 0, 0),
		struct.pack("!{:d}H".format(len(slaves)), *slaves)]
	return b"".join(parts), total-len(unparsed)

def action_bundle_act2str(payload):
	# algorithm,fields,basis,slave_type,n_slaves,ofs_nbits,dst,zero[4]
	fs = "!HHHIHHI4x"
	f = struct.unpack_from(fs, payload)
	# bundle(<hash_fields>, <basis>, <bundle_algorithm>, <slave_type>(<slaves>, ...))
	ports = struct.unpack_from("!{:d}H".format(f[4]), payload, struct.calcsize(fs))
	slaves = []
	for p in ports:
		port = None
		for num,pname in ofpp.items():
			if (num & 0xffff) == p:
				port = pname
		
		if port is None:
			port = "{:d}".format(p)
		
		slaves.append(port)
	
	return "bundle({:s},{:d},{:s},{:s},slaves({:s}))".format(
		nx_hash_names[f[1]],
		f[2],
		nx_bd_alg_names[f[0]],
		oxmid2str(payload[6:10], loop=False),
		",".join(slaves),
		)

@_nxast_str2act
def action_bundle_load_str2act(unparsed, readarg):
	total = len(unparsed)
	if readarg:
		raise ValueError("func style")
	# bundle_load(<hash_fields>, <basis>, <bundle_algorithm>, <slave_type>, <dst>[start:end], slaves(1,2,3))
	_,fields,unparsed = get_token(unparsed)
	_,basis,unparsed = get_token(unparsed)
	_,algorithm,unparsed = get_token(unparsed)
	_,slave_type,unparsed = get_token(unparsed)
	_,dst,unparsed = get_token(unparsed)
	_,slave,unparsed = get_token(unparsed)
	
	fields = nx_hash_names.index(fields)
	basis, rlen = parseInt(basis)
	algorithm = nx_bd_alg_names.index(algorithm)
	dname, dargs = parse_func(dst)
	doxmid = str2oxmid(dname, loop=False)
	if dargs:
		r = map(int, dargs.split(":", 1))
	else:
		cls,field,size=struct.unpack("!HBB", doxmid)
		r = [0, size*8]
	
	sname, sargs = parse_func(slave)
	assert sname == "slaves"
	slaves = []
	if sargs:
		for p in split(sargs):
			port = None
			for num,pname in ofpp.items():
				if pname == p:
					port = num
			if port is None:
				port,rlen = parseInt(p)
			slaves.append(port)
	
	parts = [_nxast_hdr(NXAST_BUNDLE_LOAD),
		struct.pack("!HHH", algorithm, fields, basis),
		str2oxmid(slave_type, loop=False),
		struct.pack("!HH", len(slaves), (r[0]<<6)+(r[1]-1)),
		doxmid,
		b"\0"*4, # padding
		struct.pack("!{:d}H".format(len(slaves)), *slaves)]
	return b"".join(parts), total-len(unparsed)

def action_bundle_load_act2str(payload):
	# algorithm,fields,basis,slave_type,n_slaves,ofs_nbits,dst,zero[4]
	fs = "!HHHIHHI4x"
	f = struct.unpack_from(fs, payload)
	shift = f[5]>>6
	nbits = (f[5]&0x3f)+1
	# bundle(<hash_fields>, <basis>, <bundle_algorithm>, <slave_type>(<slaves>, ...))
	ports = struct.unpack_from("!{:d}H".format(f[4]), payload, struct.calcsize(fs))
	slaves = []
	for p in ports:
		port = None
		for num,pname in ofpp.items():
			if (num & 0xffff) == p:
				port = pname
		
		if port is None:
			port = "{:d}".format(p)
		
		slaves.append(port)
	
	return "bundle_load({:s},{:d},{:s},{:s},{:s}[{:d}:{:d}],slaves({:s}))".format(
		nx_hash_names[f[1]],
		f[2],
		nx_bd_alg_names[f[0]],
		oxmid2str(payload[6:10], loop=False),
		oxmid2str(payload[14:18], loop=False),
		shift,
		shift+nbits,
		",".join(slaves),
		)

def action_output_reg_str2act(subtype):
	@_nxast_str2act
	def str2act(unparsed, readarg):
		total = len(unparsed)
		# output_reg(<src>[<start>:<end>])
		h,arg,unparsed = get_token(unparsed)
		name, arg = parse_func(arg)
		oxmid = str2oxmid(name, loop=False, has_mask=False)
		if arg:
			r = map(int, arg.split(":", 1))
		else:
			cls,field,size = struct.unpack_from("!HBB", oxmid)
			r = [0, size*8]
		
		max_len = 0xffff
		h,arg,unparsed = get_token(unparsed)
		if len(arg) and max_len:
			max_len,rlen = parseInt(arg)
		
		stype = subtype
		if len(oxmid) > 4:
			stype = NXAST_OUTPUT_REG2
		
		if stype == NXAST_OUTPUT_REG:
			parts = [_nxast_hdr(stype),
				struct.pack("!H", (r[0]<<6)+((r[1]&0x3f)-1)),
				oxmid,
				struct.pack("!H", max_len),
				b"\0"*6]
			return b"".join(parts), total-len(unparsed)
		elif stype == NXAST_OUTPUT_REG2:
			parts = [_nxast_hdr(stype),
				struct.pack("!HH", (r[0]<<6)+((r[1]&0x3f)-1), max_len),
				oxmid]
			return b"".join(parts), total-len(unparsed)
	return str2act

def action_output_reg_act2str(payload):
	f = struct.unpack_from("!HHBBH6x", payload)
	shift = f[0]>>6
	nbits = (f[0]&0x3f)+1
	size = f[3]
	name = oxmid2str(payload[2:6], loop=False)
	if shift == 0 and nbits == size*8:
		return "output_reg({:s})".format(name)
	else:
		return "output_reg({:s}[{:d}:{:d}])".format(
			name, shift, shift+nbits)

def action_output_reg2_act2str(payload):
	f = struct.unpack_from("!HHHBB", payload)
	shift = f[0]>>6
	nbits = (f[0]&0x3f)+1
	size = f[4]
	name = oxmid2str(payload[4:], loop=False)
	if shift == 0 and nbits == size*8:
		return "output_reg2({:s})".format(name)
	else:
		return "output_reg2({:s}[{:d}:{:d}])".format(
			name, shift, shift+nbits)

fixed_keys = '''idle_timeout
	hard_timeout
	priority
	cookie
	flags
	table
	fin_idle_timeout
	fin_hard_timeout'''.split()

@_nxast_str2act
def action_learn_str2act(unparsed, readarg):
	total = len(unparsed)
	if readarg:
		raise ValueError("learn must use func style")
	
	SRC_SHIFT = 12
	DST_SHIFT = 10
	def flow_mod_spec(src, dst, mode):
		flags = 0
		nbits = None
		
		sname,sarg = parse_func(src)
		soxm = str2oxmid(sname, has_mask=False)
		if soxm:
			assert len(soxm) == 4
			_,_,size = struct.unpack("!HBB", soxm)
			sshift = 0
			if sarg:
				r = map(lambda n: int(n) if n else None, sarg.split(":", 1))
				if r[0] is not None:
					sshift = r[0]
				if r[1] is None:
					nbits = size*8 - sshift
				else:
					nbits = r[1] - sshift
			else:
				nbits = size*8
			sobj = soxm+struct.pack("!H", sshift)
		else:
			sobj,_ = parseInt(sname)
			flags |= 1<<SRC_SHIFT
		
		if mode == "output":
			flags += 2<<DST_SHIFT
			if isinstance(sobj, int):
				nbits = 2
				return struct.pack("!HH", flags+nbits, sobj)
			else:
				return struct.pack("!H", flags+nbits)+sobj
		
		dname,darg = parse_func(dst)
		doxm = str2oxmid(dname, has_mask=False)
		assert len(doxm) == 4
		_,_,size = struct.unpack("!HBB", doxm)
		dnbits = size*8
		dshift = 0
		if darg:
			r = map(lambda n: int(n) if n else None, darg.split(":", 1))
			if r[0] is not None:
				dshift = r[0]
			if r[1] is not None:
				dnbits = r[1]-dshift
		if nbits:
			assert nbits == dnbits
		else:
			nbits = dnbits
		
		dbin = doxm+struct.pack("!H", dshift)
		if isinstance(sobj, (int,long)):
			sbin = b""
			for s in range((nbits+15)//16*2):
				sbin = chr((sobj>>(s*8))&0xff) + sbin
			sobj = sbin
		
		if mode == "reg_load":
			flags += 1<<DST_SHIFT
		return struct.pack("!H", flags+nbits)+sobj+dbin
	
	info = {}
	specs = b""
	left = None
	def single(token):
		fname,farg = parse_func(token)
		assert farg, left
		_,dst,farg = get_token(farg)
		h,src,farg = get_token(farg)
		assert "=" in h
		return flow_mod_spec(src, dst, fname)
	
	while unparsed:
		h,arg,unparsed = get_token(unparsed)
		if "=" in h:
			if left in fixed_keys:
				info[left],rlen = parseInt(arg)
			else:
				specs += flow_mod_spec(arg, left, None)
			left = None
		else:
			if left:
				specs += single(left)
			left = arg
	if left:
		specs += single(left)
	
	return _nxast_hdr(NXAST_LEARN)+struct.pack("!HHHQHBxHH",
		info.get("idle_timeout", 0),
		info.get("hard_timeout", 0),
		info.get("priority", 0),
		info.get("cookie", 0),
		info.get("flags", 0),
		info.get("table", 0),
		info.get("fin_idle_timeout", 0),
		info.get("fin_hard_timeout", 0))+specs, total-len(unparsed)

def action_learn_act2str(payload):
	ret = []
	
	fixed = "!HHHQHBxHH"
	f = struct.unpack_from(fixed, payload)
	if f[0]:
		ret.append("idle_timeout={:d}", f[0])
	if f[1]:
		ret.append("hard_timeout={:d}", f[1])
	if f[2]:
		ret.append("priority={:d}", f[2])
	if f[3]:
		ret.append("cookie={:#x}", f[3])
	if f[4]:
		ret.append("flags={:#x}", f[4])
	if f[5]:
		ret.append("table={:d}", f[5])
	if f[6]:
		ret.append("fin_idle_timeout={:d}", f[6])
	if f[7]:
		ret.append("fin_hard_timeout={:d}", f[7])
	
	payload = payload[struct.calcsize(fixed):]
	specs = []
	while len(payload)>2:
		n = struct.unpack_from("!H", payload)[0]
		if not n:
			break
		payload = payload[2:]
		
		nbits = n & 0x3ff
		dst = (n>>10) & 0x03
		src = (n>>12) & 0x01
		assert (n>>13) == 0
		if src:
			rlen = (nbits+15)//16*2
			n = 0
			for i in payload[:rlen]:
				n = (n<<8) + ord(i)
			payload = payload[rlen:]
			sobj = n
		else:
			sname = oxmid2str(payload, loop=False)
			_,_,size,shift = struct.unpack_from("!HBBH", payload)
			payload = payload[6:]
			if shift==0 and size*8==nbits:
				sobj = sname
			else:
				sobj = "{:s}[{:d}:{:d}]".format(
					sname,
					shift,
					shift+nbits)
		
		if dst != 2:
			if isinstance(sobj, (int,long)):
				sobj = "{:#x}".format(sobj)
			
			dname = oxmid2str(payload, loop=False)
			_,_,size,shift = struct.unpack_from("!HBBH", payload)
			payload = payload[6:]
			if shift==0 and size*8==nbits:
				dobj = dname
			else:
				dobj = "{:s}[{:d}:{:d}]".format(
					dname,
					shift,
					shift+nbits)
			if dst == 0:
				spec = "{:s}={:s}".format(dobj, sobj)
			elif dst == 1:
				spec = "reg_load({:s}={:s})".format(dobj, sobj)
		else:
			if isinstance(sobj, (int,long)):
				sobj = "{:d}".format(sobj)
			
			spec= "output({:s})".format(sobj)
		specs.append(spec)
	
	ret.append("learn({:s})".format(",".join(specs)))
	return ",".join(ret)

_str2act = {}
_act2str = {}

def register_nxast(str2act, act2str):
	str2act.update(_str2act)
	act2str.update(_act2str)

#
# learn
# fin_timeout
# controller
# write_metadata
# stack_push
# stack_pop
# sample
# conjunction
#

_str2act["cnt_ids"] = action_cnt_ids_str2act
_act2str[NXAST_CNT_IDS] = action_cnt_ids_act2str

_str2act["reg_load"] = action_reg_load_str2act(NXAST_REG_LOAD)
_act2str[NXAST_REG_LOAD] = action_reg_load_act2str

_str2act["reg_load2"] = action_reg_load_str2act(NXAST_REG_LOAD2)
_act2str[NXAST_REG_LOAD2] = action_reg_load2_act2str

_str2act["reg_move"] = action_reg_move_str2act
_act2str[NXAST_REG_MOVE] = action_reg_move_act2str

_str2act["resubmit"] = action_resubmit_str2act(NXAST_RESUBMIT)
_act2str[NXAST_RESUBMIT] = action_resubmit_act2str

_str2act["resubmit_table"] = action_resubmit_str2act(NXAST_RESUBMIT_TABLE)
_act2str[NXAST_RESUBMIT_TABLE] = action_resubmit_table_act2str

_str2act["set_tunnel"] = action_set_tunnel_str2act(NXAST_SET_TUNNEL)
_act2str[NXAST_SET_TUNNEL] = action_set_tunnel_act2str(4, "set_tunnel({:#x})")

_str2act["set_tunnel64"] = action_set_tunnel_str2act(NXAST_SET_TUNNEL64)
_act2str[NXAST_SET_TUNNEL64] = action_set_tunnel_act2str(8, "set_tunnel64({:#x})")

_str2act["pop_queue"] = action_null_str2act(NXAST_POP_QUEUE)
_act2str[NXAST_POP_QUEUE] = action_null_act2str("pop_queue")

_str2act["note"] = action_qp_str2act(NXAST_NOTE)
_act2str[NXAST_NOTE] = action_qp_act2str("note({:s})")

_str2act["exit"] = action_null_str2act(NXAST_EXIT)
_act2str[NXAST_EXIT] = action_null_act2str("exit")

_str2act["multipath"] = action_multipath_str2act
_act2str[NXAST_MULTIPATH] = action_multipath_act2str

_str2act["bundle"] = action_bundle_str2act
_act2str[NXAST_BUNDLE] = action_bundle_act2str

_str2act["bundle_load"] = action_bundle_load_str2act
_act2str[NXAST_BUNDLE_LOAD] = action_bundle_load_act2str

_str2act["output_reg"] = action_output_reg_str2act(NXAST_OUTPUT_REG)
_act2str[NXAST_OUTPUT_REG] = action_output_reg_act2str

_str2act["output_reg2"] = action_output_reg_str2act(NXAST_OUTPUT_REG2)
_act2str[NXAST_OUTPUT_REG2] = action_output_reg2_act2str

_str2act["learn"] = action_learn_str2act
_act2str[NXAST_LEARN] = action_learn_act2str

