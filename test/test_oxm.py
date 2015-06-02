import unittest
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
		)
	def test_all(self):
		for rule in self.rules:
			msg, length = ofpstr.oxm.str2oxm(rule)
			assert length == len(rule)
			assert rule == ofpstr.oxm.oxm2str(msg)


if __name__ == "__main__":
	unittest.main()
