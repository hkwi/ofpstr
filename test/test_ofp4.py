import unittest
import ofpstr.ofp4

class TestRoundTrip(unittest.TestCase):
	actions = (
		"output=controller",
		"output=1",
		"copy_ttl_out",
		"copy_ttl_in",
		"set_mpls_ttl=3",
		"dec_mpls_ttl",
		"push_vlan=0x8100",
		"pop_vlan",
		"push_mpls=0x8847",
		"pop_mpls=0x0800",
		"set_queue=1",
		"group=1",
		"set_nw_ttl=3",
		"dec_nw_ttl",
		"set_vlan_vid=0x10",
		"push_pbb=0x88e7",
		"pop_pbb"
		)
	flows = (
		"cookie=0x1",
		"cookie=0x1/0xf",
		"table=2",
		"priority=10",
		"buffer=0x3",
		"out_port=1",
		"out_port=controller",
		"out_group=any",
		"out_group=1",
		"idle_timeout=10",
		"hard_timeout=4",
		"@metadata=0x1,@meter=3,@apply,@clear,@write,@goto=5",
		"dot11=1,dot11_frame_ctrl=40/ff,@apply,output=controller",
		"table=1,priority=10,in_port=1,@apply,output=controller,@goto=2",
		"priority=20,idle_timeout=30,dot11=1,dot11_frame_ctrl=00/0f,dot11_addr2=01:23:45:67:89:01,@apply,output=controller",
		"cookie=0x1/0xf,priority=4,buffer=0x1,idle_timeout=300,hard_timeout=300,vlan_vid=0x1,@apply,set_vlan_vid=0x2,output=3,@goto=3",
		)
	def test_action(self):
		for rule in self.actions:
			msg, length = ofpstr.ofp4.str2act(rule)
			assert length == len(rule), "{:s} captured {:d}".format(rule, length)
			assert rule == ofpstr.ofp4.act2str(msg)
	
	def test_mod(self):
		for flow in self.flows:
			ret = ofpstr.ofp4.mod2str(ofpstr.ofp4.str2mod(flow))
			assert ret == flow, ret

if __name__ == "__main__":
	unittest.main()
