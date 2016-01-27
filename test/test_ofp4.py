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
		"pop_pbb",
		"cnt_ids(0x1,0x2,0x3)",
		"reg_load(nxm_vlan_tci=0xa/0x0fff)",
		"reg_load2(nxm_vlan_tci=0xa/0x0fff)",
		"reg_move(nxm_eth_dst=nxm_eth_src)",
		"reg_move(nxm_eth_dst[0:4]=nxm_eth_src[4:8])",
		"resubmit(in_port)",
		"resubmit(1)",
		"resubmit_table(in_port,all)",
		"resubmit_table(1,1)",
		"set_tunnel(0x11223344)",
		"set_tunnel64(0x1122334455667788)",
		"pop_queue",
		"note(openflow)",
		"multipath(eth_src,50,hrw,12,0x0,nxm_reg0[0:4])",
		"bundle(eth_src,50,active_backup,nxm_in_port,slaves(1,2,3))",
		"bundle_load(symmetric_l4,60,hrw,nxm_in_port,nxm_reg0[0:16],slaves(2,3))",
		"output_reg(in_port)",
		"output_reg(in_port[0:1])",
		"output_reg2(in_port)",
		"output_reg2(in_port[0:1])",
		"learn(nxm_in_port=0x10,nxm_eth_dst=nxm_eth_src,reg_load(nxm_reg1[16:32]=nxm_in_port))",
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
	aliased_flows = [
		("@apply,set_nxm_tun_ipv4_src(192.168.0.1),set_nxm_tun_ipv4_dst(192.168.0.2)",
			"@apply,set_nxm_tun_ipv4_src=192.168.0.1,set_nxm_tun_ipv4_dst=192.168.0.2"),
		]
	def test_action(self):
		for rule in self.actions:
			msg, length = ofpstr.ofp4.str2act(rule)
			assert length == len(rule), "{:s} captured {:d}".format(rule, length)
			assert rule == ofpstr.ofp4.act2str(msg), "{0} != {1}".format(rule, ofpstr.ofp4.act2str(msg))
	
	def test_mod(self):
		for flow in self.flows:
			ret = ofpstr.ofp4.mod2str(ofpstr.ofp4.str2mod(flow))
			assert ret == flow, ret
		for aliased, flow in self.aliased_flows:
			ret = ofpstr.ofp4.mod2str(ofpstr.ofp4.str2mod(aliased))
			assert ret == flow, ret

class TestFlowStat(unittest.TestCase):
	def test_empty_req(self):
		flows = {"": {}}
		msgs = ofpstr.ofp4.str2flows(flows)
		assert len(msgs) == 1
		rules = ofpstr.ofp4.flows2str(msgs[0])
		for rule, extra in rules.items():
			assert not rule
			assert not extra

	def test_empty_res(self):
		OFPT_MULTIPART_REPLY = 19
		flows = {"": {}}
		msgs = ofpstr.ofp4.str2flows(flows, mp_type=OFPT_MULTIPART_REPLY)
		assert len(msgs) == 1
		rules = ofpstr.ofp4.flows2str(msgs[0])
		assert not rules

	def test_single_res(self):
		OFPT_MULTIPART_REPLY = 19
		flows = {"send_flow_rem,in_port=1": {"byte_count":20}}
		msgs = ofpstr.ofp4.str2flows(flows, mp_type=OFPT_MULTIPART_REPLY)
		assert len(msgs) == 1
		rules = ofpstr.ofp4.flows2str(msgs[0])
		for rule, extra in rules.items():
			assert rule == "send_flow_rem,in_port=1"
			assert extra.pop("byte_count") == 20

if __name__ == "__main__":
	unittest.main()
