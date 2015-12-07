import unittest
import binascii
import ofpstr.oxm

class TestRoundTrip(unittest.TestCase):
	rules = (
		"in_port=any",
		"in_port=10",
		"in_phy_port=10",
		"metadata=0x5/0xff",
		"eth_src=00:00:00:00:00:00",
		"eth_src=00:00:00:00:00:00/01:00:00:00:00:00",
		"ipv4_src=192.168.0.1",
		"ipv4_src=192.168.0.1/255.255.255.0",
		"ipv4_src=192.168.0.1/255.0.255.255",
		"ipv6_src=::/ffff::",
		"vlan_vid=0x5",
		"vlan_vid=0x1000/0x1000",
		"pbb_isid=0x5",
		"packet_type=0x2:0x3",
		"dot11=0",
		"dot11=1",
		"dot11_frame_ctrl=0000",
		"dot11_frame_ctrl=0000/fff0",
		"dot11_addr1=ff:ff:ff:ff:ff:ff",
		"dot11_addr1=01:00:00:00:00:00/01:00:00:00:00:00", # broadcast,multicast
		"dot11_ssid=stratos1",
		"dot11_ssid=stratos/ffffffffffffff00000000",
		"dot11_action_category=03",
		"dot11_action_category=7f00e04d", # vendor action
		"dot11_public_action=10",         # GAS initial
		"dot11_tag=0",
		"dot11_tag_vendor=00e04d",
		"radiotap_tsft=1",
		"radiotap_flags=0x00",
		"radiotap_rate=500.0K",
		"radiotap_rate=11.0M",
		"radiotap_channel=2412:0x1234",
		"radiotap_channel=2412:0x1234/:0x00ff",
		"radiotap_fhss=0102",
		"radiotap_dbm_antsignal=-80",
		"radiotap_mcs=0x01:1:2",
		"radiotap_ampdu_status=0x12345678:0x1234:0x12:0x12",
		"radiotap_ampdu_status=:::/0x12345678:0x1234:0x12:0x12",
		"radiotap_vht=0x1234:0x12:0:12345678:0x12:0:0x0000",
		"nxm_in_port=any",
		"nxm_eth_dst=00:11:22:33:44:55",
		"nxm_eth_src=00:11:22:33:44:55/01:00:00:00:00:00",
		"nxm_eth_type=0x88a8",
		"nxm_vlan_tci=0x3001",
		"nxm_ip_tos=0x10", # IPTOS_LOWDELAY
		"nxm_ip_proto=6",
		"nxm_ip_src=192.168.0.1",
		"nxm_ip_dst=192.168.0.0/255.255.255.0",
		"nxm_tcp_src=80",
		"nxm_tcp_dst=8080",
		"nxm_udp_src=53",
		"nxm_udp_dst=4789",
		"nxm_icmp_type=30",
		"nxm_icmp_code=0",
		"nxm_arp_op=1",
		"nxm_arp_spa=192.168.0.1",
		"nxm_arp_tpa=192.168.0.0/255.255.255.0",
		)
	def test_all(self):
		for rule in self.rules:
			msg, length = ofpstr.oxm.str2oxm(rule)
			assert length == len(rule), "length {0}!={1} {2}".format(length, len(rule), rule)
			assert rule == ofpstr.oxm.oxm2str(msg), "{0}!={1} {2}".format(rule, ofpstr.oxm.oxm2str(msg), binascii.b2a_hex(msg))
	
	def test_id(self):
		for rule in self.rules:
			strid = rule.split("=")[0]
			oxmid = ofpstr.oxm.str2oxmid(strid)
			assert len(oxmid) in (4, 8)
			assert strid == ofpstr.oxm.oxmid2str(oxmid), "{0}!={1}".format(strid, ofpstr.oxm.oxmid2str(oxmid))

if __name__ == "__main__":
	unittest.main()
