import re
import string

try:
	L0 = long(0)
except:
	L0 = 0
	long = int

ofpp = {
	0xffffff00: "max",
	0xfffffff8: "in_port",
	0xfffffff9: "table",
	0xfffffffa: "normal",
	0xfffffffb: "flood",
	0xfffffffc: "all",
	0xfffffffd: "controller",
	0xfffffffe: "local",
	0xffffffff: "any"
	}

def is_delimiter(c):
	return c in "," or c in string.whitespace

pars = dict(("()", "{}", "[]", "<>"))
def scan_paren(end):
	def scan(reader):
		'''
		reader is iterator that yields a char
		@returns payload, right-parenthesis
		'''
		payload = ""
		for c in reader:
			if c == end:
				return payload, c
			else:
				payload += c
				if c in pars:
					p,r = scan_paren(pars[c])(reader)
					payload += p
					if r:
						payload += r
		return payload, ""
	return scan

def get_token(unparsed):
	head = "" # leading non-token string
	m = re.match("^(\s*=\s*|[\s,]+)", unparsed)
	if m:
		head = m.group(1)
	
	body = ""
	reader = iter(unparsed[len(head):])
	for c in reader:
		if is_delimiter(c) or c == "=":
			break
		body += c
		if c in pars:
			p,r = scan_paren(pars[c])(reader)
			body += p + r
	
	return head, body, unparsed[len(head)+len(body):]

def split(unparsed):
	ret = []
	while unparsed:
		h,b,unparsed = get_token(unparsed)
		if not b:
			break
		ret.append(b)
	return ret

def parse_func(nojunk):
	'''
	parses argument is function-style string or not.
	This checks argument is cleanly closed with parenthesis
	'''
	name = ""
	reader = iter(nojunk)
	for c in reader:
		if c in pars:
			p, r = scan_paren(pars[c])(reader)
			assert len(nojunk) == len(name)+1+len(p)+len(r)
			# cleanly closed only if len(r)!=0, should we raise warn here?
			return name, p
		else:
			name += c
	
	return name, None

def parse_bits(nojunk):
	name, args = parse_func(nojunk)
	if args:
		ns = map(lambda x: int(x) if len(x) else None, args.split(":", 1))
		return name, ns[0], ns[1]
	return name, None, None

def longest(s, char_set):
	'''returns the maximum continuous length of string, which is made from char_set.'''
	i = 0
	for c in s:
		if c in char_set:
			i += 1
		else:
			break
	return i

def parseInt(unparsed):
	if unparsed.startswith("-"):
		l = 1 + longest(unparsed[1:], "0123456789")
		return -long(unparsed[1:l]), l
	
	if unparsed.startswith("0x") or unparsed.startswith("0X"):
		l = 2 + longest(unparsed[2:], "0123456789abcdefABCDEF")
		return long(unparsed[2:l], 16), l
	elif unparsed.startswith("0") and len(unparsed)>2 and unparsed[1] in "01234567":
		l = 1 + longest(unparsed[1:], "01234567")
		return long(unparsed[1:l], 8), l
	else:
		l = longest(unparsed, "0123456789")
		return long(unparsed[:l]), l

def parseFloat(unparsed):
	neg = False
	if unparsed.startswith("-"):
		neg = True
		unparsed = unparsed[1:]
	
	l = longest(unparsed, "0123456789")
	ret = long(unparsed[:l])
	if unparsed[l:].startswith("."):
		l2 = longest(unparsed[l+1:], "0123456789")
		ret += float(long(unparsed[l+1:l+l2+1]))/(10**l2)
		l += l2+1
	
	return ret, l
