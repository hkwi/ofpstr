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

re_value = re.compile(r"^(\s*=?\s*)([^,=/\s]+)(\s*/\s*([^,=/\s]+))?")
def get_value(unparsed):
	return re_value.match(unparsed).groups()


re_unit = re.compile(r"^(\s*,?\s*)([^,=\s]+)(\s*=?\s*)(.*)")
def get_unit(unparsed):
	return re_unit.match(unparsed).groups()


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
