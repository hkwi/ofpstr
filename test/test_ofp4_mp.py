import unittest
import ofpstr.ofp4

mpflow = [
'''in_port=1,@apply,output=2
in_port=2,@apply,output=1''',
'''packet_count=1,byte_count=2,duration_sec=3,duration_nsec=4 in_port=1,@apply,output=2
packet_count=5,byte_count=6,duration_sec=7,duration_nsec=8 in_port=1,@apply,output=2'''
]
mpgroupdesc = [
'''group=1,all,@bucket,output=1,@bucket,output=2
group=2,select,@bucket,output=1,@bucket,output=2
group=4,indirect,@bucket,output=2
group=3,ff,@bucket,watch_port=7,output=2''',
]
mpgroup = [
'''group=1 @bucket,packet_count=1,@bucket,packet_count=2
group=2 packet_count=5,byte_count=6,duration_sec=1,duration_nsec=2,@bucket,byte_count=4''',
]

class TestRoundTrip(unittest.TestCase):
	def test_mpflow(self):
		for text in mpflow:
			rt = ofpstr.ofp4.mpflow2text(ofpstr.ofp4.text2mpflow(text))
			assert text == rt, rt
	
	def test_mpgroupdesc(self):
		for text in mpgroupdesc:
			rt = ofpstr.ofp4.mpgroupdesc2text(ofpstr.ofp4.text2mpgroupdesc(text))
			assert text == rt, rt

	def test_mpgroup(self):
		for text in mpgroup:
			rt = ofpstr.ofp4.mpgroup2text(ofpstr.ofp4.text2mpgroup(text))
			assert text == rt, rt

if __name__ == "__main__":
	unittest.main()
