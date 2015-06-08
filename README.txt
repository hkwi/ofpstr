About
-----
ofpstr is openflow stringer library and it converts string into 
openflow binary message, like ovs-ofctl flow rule arguments.
It can also convert binary message back to string representation.
The syntax is DIFFERENT from ovs-ofctl, using more direct naming 
as is defined in the spec. For example, ovs-ofctl use `dl_vlan`
for vlan tagging, which is not present in openflow 1.3 spec.
ofpstr use `vlan_vid` for this.

usage
-----
There are two modes of `oxm` and `ofp_mod_flow`.

`oxm` example:

.. code:: python

   import ofpstr.oxm
   # string to binary message
   oxm_msg,parsed_len = ofpstr.oxm.str2oxm("in_port=1,vlan_vid=0x1,eth_type=0x0800")
   # binary message to string
   print(ofpstr.oxm.oxm2str(oxm_msg))

`ofp_mod_flow` example:

.. code:: python

   import ofpstr.ofp4
   # string to binary message
   ofp_flow_mod_msg = ofpstr.ofp4.str2mod("in_port=1,@apply,output=controller", xid=16)
   # binary message to string
   print(ofpstr.ofp4.mod2str(ofp_flow_mod_msg))
   # in_port=1,@apply,output=controller


general syntax
--------------
Tokens are separated by comma, field may take argument with `=` separator.
argument may have mask with "/" separator. Examples:

.. code:: ini

  # integer mode
  metadata=0x01/0x0F
  tunnel_id=10
  # mac mode
  eth_dst=01:00:00:00:00:00/01:00:00:00:00:00
  # ipv4 mode
  ipv4_src=192.168.1.0/24
  ipv4_src=192.168.1.0/255.255.255.0
  # ipv6 mode
  ipv6_src=::
  # port mode may use special names or integer
  in_port=controller
  in_port=1
  # pkt mode use two integer representing (namespace,ns_type)
  packet_type=0:1
  # hex mode use hex string (like binascii hex)
  dot11_frame_ctrl=c000/ff00
  # ssid mode use string directly
  dot11_ssid=TestAP

Full list follows:

* integer mode: metadata, eth_type, vlan_vid, vlan_pcp, ip_dscp, ip_ecn, ip_proto, 
  tcp_src, tcp_dst, udp_src, udp_dst, sctp_src, sctp_dst, icmpv4_type, icmpv4_code, 
  arp_op, ipv6_label, icmpv6_type, icmpv6_code, mpls_bale, mpls_tc, mpls_bos, 
  pbb_isid, tunnel_id, ipv6_exthdr, pbb_uca, tcp_flags, 
  dot11, dot11_public_action, dot11_tag, 
  radiotap_tsft, radiotap_flags, radiotap_lock_quality, radiotap_tx_attenuation, 
  radiotap_db_tx_attenuation, radiotap_antenna, radiotap_db_antsignal, radiotap_db_antnoise, 
  radiotap_rx_flags, radiotap_tx_flags, radiotap_rts_retries, radiotap_data_retries, 
  radiotap_dbm_antsignal, radiotap_dbm_antnoise, radiotap_dbm_tx_power
* mac mode: eth_dst, eth_src, arp_sha, arp_tha, ipv6_nd_sll, ipv6_nd_tll, dot11_addr1, dot11_addr2, dot11_addr3, dot11_addr4
* ipv4 mode: ipv4_src, ipv4_dst, arp_spa, arp_tpa
* ipv6 mode: ipv6_src, ipv6_dst, ipv6_nd_target
* port mode: in_port, in_phy_port, actset_output
* pkt mode: packet_type
* hex mode: dot11_frame_ctrl, dot11_action_category, dot11_tag_vendor, radiotap_fhss
* ssid mode: dot11_ssid
* rate mode: radiotap_rate
* ch mode: radiotap_channel
* comp mode: radiotap_mcs, radiotap_ampdu_status
* vht mode: radiotap_vht


LICENSE
-------
ofpstr is available under Apache 2.0 License and Python Software 
Foundation License.
