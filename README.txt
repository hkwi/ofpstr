About
-----
ofpstr is openflow stringer library and it converts string into 
openflow binary message, like ovs-ofctl flow rule arguments.
It can also convert binary message back to string representation.
The syntax is DIFFERENT from ovs-ofctl, using more direct naming 
as is defined in the spec. For example, ovs-ofctl use `dl_vlan`
for vlan tagging, which is not present in openflow 1.3 spec.
ofpstr use `vlan_vid` for this.

LICENSE
-------
ofpstr is available under Apache 2.0 License and Python Software 
Foundation License.
