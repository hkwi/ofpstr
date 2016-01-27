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

Full oxm list follows:

* integer mode: metadata, eth_type, vlan_vid, vlan_pcp, ip_dscp, ip_ecn, ip_proto, 
  tcp_src, tcp_dst, udp_src, udp_dst, sctp_src, sctp_dst, icmpv4_type, icmpv4_code, 
  arp_op, ipv6_label, icmpv6_type, icmpv6_code, mpls_bale, mpls_tc, mpls_bos, 
  pbb_isid, tunnel_id, ipv6_exthdr, pbb_uca, tcp_flags, 
  nxm_in_port, nxm_eth_type, nxm_vlan_tci, nxm_ip_tos, nxm_ip_proto, 
  nxm_tcp_src, nxm_tcp_dst, nxm_udp_src, nxm_udp_dst, nxm_icmp_type, nxm_icmp_code, nxm_arp_op, 
  nxm_reg0, nxm_reg1, nxm_reg2, nxm_reg3, nxm_reg4, nxm_reg5, nxm_reg6, nxm_reg7, 
  nxm_tun_id, nxm_icmpv6_type, nxm_icmpv6_code, nxm_ip_frag, nxm_ipv6_label, nxm_ip_ecn, nxm_ip_ttl, 
  nxm_pkt_mark, nxm_tcp_flags, nxm_dp_hash, nxm_recirc_id, nxm_conj_id, 
  nxm_tun_gbp_id, nxm_tun_gbp_flags, 
  dot11, dot11_public_action, dot11_tag, 
  radiotap_tsft, radiotap_flags, radiotap_lock_quality, radiotap_tx_attenuation, 
  radiotap_db_tx_attenuation, radiotap_antenna, radiotap_db_antsignal, radiotap_db_antnoise, 
  radiotap_rx_flags, radiotap_tx_flags, radiotap_rts_retries, radiotap_data_retries, 
  radiotap_dbm_antsignal, radiotap_dbm_antnoise, radiotap_dbm_tx_power
* mac mode: eth_dst, eth_src, arp_sha, arp_tha, ipv6_nd_sll, ipv6_nd_tll, 
  nxm_eth_dst, nxm_eth_src, nxm_arp_sha, nxm_arp_tha, nxm_nd_sll, nxm_nd_tll, 
  dot11_addr1, dot11_addr2, dot11_addr3, dot11_addr4
* ipv4 mode: ipv4_src, ipv4_dst, arp_spa, arp_tpa,
  nxm_ip_src, nxm_ip_dst, nxm_arp_spa, nxm_arp_tpa, nxm_tun_ipv4_src, nxm_tun_ipv4_dst
* ipv6 mode: ipv6_src, ipv6_dst, ipv6_nd_target, 
  nxm_ipv6_src, nxm_ipv6_dst, nxm_nd_target
* port mode: in_port, in_phy_port, actset_output
* pkt mode: packet_type
* hex mode: dot11_frame_ctrl, dot11_action_category, dot11_tag_vendor, radiotap_fhss
* ssid mode: dot11_ssid
* rate mode: radiotap_rate
* ch mode: radiotap_channel
* comp mode: radiotap_mcs, radiotap_ampdu_status
* vht mode: radiotap_vht

Actions may take arguments in function style. oxm with set\_ prefix will be set_field action.
Some nxm actions accepts only function style. Examples:

.. code:: ini

  # alias for set_vlan_vid=10
  set_vlan_vid(10)
  # nicira extensions
  cnt_ids(0x1,0x2,0x3)
  reg_load(nxm_vlan_tci=0xa/0x0fff)
  reg_load2(nxm_vlan_tci=0xa/0x0fff)
  reg_move(nxm_eth_dst=nxm_eth_src)
  reg_move(nxm_eth_dst[0:4]=nxm_eth_src[4:8])
  resubmit(in_port)
  resubmit(1)
  resubmit_table(in_port,all)
  resubmit_table(1,1)
  set_tunnel(0x11223344)
  set_tunnel64(0x1122334455667788)
  pop_queue()
  note(some text)
  multipath(eth_src,50,hrw,12,0x0,nxm_reg0[0:4])
  bundle(eth_src,50,active_backup,nxm_in_port,slaves(1,2,3))
  bundle_load(symmetric_l4,60,hrw,nxm_in_port,nxm_reg0[0:16],slaves(2,3))
  output_reg(in_port)
  output_reg(in_port[0:1])
  output_reg2(in_port)
  output_reg2(in_port[0:1])
  learn(nxm_in_port=0x10,nxm_eth_dst=nxm_eth_src,reg_load(nxm_reg1[16:32]=nxm_in_port))
  exit()

* integer mode: output, set_mpls_ttl, push_vlan, pop_mpls, push_mpls, 
  set_queue, group, set_nw_ttl, push_pbb, 
* flag mode: copy_ttl_out, copy_ttl_in, dec_mpls_ttl, dec_nw_ttl, pop_pbb

Advanced features
-----------------
`flow` and `actions` will be in string representation, and the other part will be 
stored in dictionary.

flow_stats multipart example:

.. code:: python

   import ofpstr.ofp4
   # create dummy reply
   msg, = ofpstr.ofp4.str2flows([dict(flow="in_port=1"), dict(flow="in_port=2")])
   # parse that reply
   print(ofpstr.ofp4.flows2str(msg))
   # [{'byte_count': 0, 'packet_count': 0, 'duration_sec': 0, 'flow': 'in_port=1', 'duration_nsec': 0},
   #  {'byte_count': 0, 'packet_count': 0, 'duration_sec': 0, 'flow': 'in_port=2', 'duration_nsec': 0}]

group_mod example:

.. code:: python

   import ofpstr.ofp4
   # create request
   msg = ofpstr.ofp4.str2group([dict(actions="output=1"), dict(actions="output=2")])

group_desc multipart example:

.. code:: python

   import ofpstr.ofp4
   # create dummy reply
   msg, = ofpstr.ofp4.str2groups_desc([
     dict(group_id=1, buckets=[dict(actions="output=1"), dict(actions="output=2")]),
     dict(group_id=2, buckets=[dict(actions="output=1"), dict(actions="output=2")])])
   # parse that reply
   ofpstr.ofp4.groups_desc2str(msg)
   # [{'buckets': [{'actions': 'output=1'}, {'actions': 'output=2'}], 'group_id': 1},
   #  {'buckets': [{'actions': 'output=1'}, {'actions': 'output=2'}], 'group_id': 2}]

LICENSE
-------
ofpstr is available under Apache 2.0 License and Python Software 
Foundation License.
