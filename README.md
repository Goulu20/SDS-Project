# SDS-Project


Steps to execute project:

---

## Steps to execute the project

### 1. Execute Mininet and Ryu topology

```bash
sudo python3 myTopo.py
ryu-manager simple_switch_snort.py --verbose
```
### 2. In a new terminal, execute snort
```bash
sudo ovs-vsctl add-port s1 s1-snort
```
Check your assigned port with the following command and update simple_switch_snort.py file
```bash
sudo ovs-ofctl show s1 and update simple_switch_snort.py
```
Finally execute snort
```bash
sudo snort -i s1-snort -A unsock -l /tmp -c /etc/snort/snort.conf
```
### 2. Test DoS attack in mininet
```bash
h2 python3 dos.py h3
```






