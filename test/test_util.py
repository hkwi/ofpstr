import unittest
import ofpstr.util

class TestToken(unittest.TestCase):
	rules = (
		("a,b,c", ("", "a", ",b,c")), # comma separated list
		(",b,c", (",", "b", ",c")),
		(",c", (",", "c", "")),
		("a b c", ("", "a", " b c")), # whitespace separated list
		(" b c", (" ", "b", " c")),
		(" c", (" ", "c", "")),
		("a = b, c = d", ("", "a", " = b, c = d")), # mixture
		(" = b, c = d", (" = ", "b", ", c = d")),
		("learn(hoge),learn(geho)", ("", "learn(hoge)", ",learn(geho)")), # parenthesis
	)
	def test_expected(self):
		for input,output in self.rules:
			processed = ofpstr.util.get_token(input)
			assert output == processed, "{0}=>{1}".format(input, processed)

if __name__ == "__main__":
	unittest.main()
