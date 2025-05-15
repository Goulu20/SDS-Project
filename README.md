# SDS-Project

Steps to execute project:
# MININET: sudo python3 myTopo.py
# RYU: ryu-manager simple_switch_snort.py --verbose

Then, in a new terminal execute snort:
# sudo ovs-vsctl add-port s1 s1-snort
# check your snort port: sudo ovs-ofctl show s1 and update simple_switch_snort.py
# sudo snort -i s1-snort -A unsock -l /tmp -c /etc/snort/snort.conf

# To test hping3, : h2 python3 dos.py h3


