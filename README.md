# SDS-Project


Steps to execute project:

---

## Steps to execute the project

### 1. Execute Mininet and Ryu topology

```bash
sudo mn -c
sudo python3 myTopo.py
ryu-manager simple_switch_snort.py --verbose
```
### 2. In a new terminal, execute snort
```bash
sudo ip link add name s1-snort type dummy
sudo ovs-vsctl add-port s1 s1-snort
sudo ip link set s1 snort up
```
Check your assigned port with the following command and update simple_switch_snort.py file
```bash
sudo ovs-ofctl show s1 | grep s1-snort
```
![image](https://github.com/user-attachments/assets/06a30d57-d5a4-4c33-97e8-ade492fa4e78)

and update simple_switch_snort.py file.
```bash
/home/sds/.local/lib/python3.8/site-packages/ryu/app/simple_switch_snort.py
```
![image](https://github.com/user-attachments/assets/6193f11b-503d-4acd-8a14-5f4899ff81ec)


Finally execute snort
```bash
sudo snort -i s1-snort -A unsock -l /tmp -c /etc/snort/snort.conf
```
### 2. Test DoS attack in mininet
```bash
h2 python3 dos.py h3
```






