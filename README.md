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
sudo ip link set s1-snort up
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

Finally execute snort in snort_files directory
```bash
sudo snort -i s1-snort -c snort.conf -l /tmp
```
### 3. Test DoS attack in mininet
```bash
h2 python3 dos.py h3
```
### 4. To create the graphic
To start Influxdb in the directory SDS-Project
```bash
sudo systemctl start influxdb
```
To start Telegraf in the directory SDS-Project
```bash
sudo telegraf --config telegraf.conf
```

GRAFANA:

➕ Add InfluxDB as a Data Source

&nbsp;Click the gear icon (⚙️) on the left → Data Sources  
&nbsp;Click Add data source  
&nbsp;Select InfluxDB

🛠 Configure the InfluxDB Data Source

Basic settings:

URL:  
&nbsp;&nbsp;If InfluxDB runs locally: http://localhost:8086  
&nbsp;&nbsp;If remote: http://<server-ip>:8086  
Auth settings (if no auth set in InfluxDB):  
&nbsp;&nbsp;Leave Basic Auth and Auth details off  

Database settings:  
&nbsp;&nbsp;Database: snortdb (or your actual InfluxDB database name)  
&nbsp;&nbsp;User / Password: Leave blank unless authentication is enabled  

Create a Dashboard  
&nbsp;&nbsp;Click the + icon on the left → Dashboard  
&nbsp;&nbsp;Click Add a new panel  
&nbsp;&nbsp;In Query > Data source, select your InfluxDB  
&nbsp;&nbsp;In the query field, use:  
```bash
SELECT count("message") FROM "snort_alerts" WHERE $timeFilter GROUP BY time($__interval)
```
