#from mininet.topo import Topo
#class MyTopo(Topo):
 #   def __init__(self):
 #       # Initialize topology
 #       Topo.__init__(self)
 #       # Add hosts and switches
 #       h1 = self.addHost('h1')
 #       h2 = self.addHost('h2')
 #       h3 = self.addHost('h3')
 #       h4 = self.addHost('h4')
 #       s1 = self.addSwitch('s1')
 #       s2 = self.addSwitch('s2')
 #       # Add (bidirectional) links
 #       self.addLink(h1, s1)
 #       self.addLink(h2, s1)
 #       self.addLink(s1, s2)
 #       self.addLink(s2, h3)
 #       self.addLink(s2, h4)


# Adding the 'topos' dict with a key/value pair to
# generate our newly defined topology enables one
# to pass in '--topo=mytopo' from the command line.
#topos = {'mytopo': (lambda: MyTopo())}

#!/usr/bin/env python3
from mininet.net import Mininet
from mininet.node import RemoteController, OVSSwitch
from mininet.link import TCLink
from mininet.log import setLogLevel, info
import time
import subprocess

class TopoSDN:
    def build(self):
        net = Mininet(controller=None, link=TCLink, switch=OVSSwitch)

        # Hosts normales y servidores web
        hosts = {}
        for h, ip in [('h1','10.0.0.1'), ('h2','10.0.0.2'), ('h3','10.0.0.3'),
                      ('h4','10.0.0.4'), ('h5','10.0.0.5')]:
            hosts[h] = net.addHost(h, ip=ip)

        # Host Snort
        snort1 = net.addHost('snort1', ip='10.0.0.10')

        # Switches
        s1 = net.addSwitch('s1')
        s2 = net.addSwitch('s2')
	
        #subprocess.run(['sudo', 'ip', 'link', 'add', 'name', 's1-snort', 'type', 'dummy'], check=False)
        #subprocess.run(['sudo', 'ip', 'link', 'set', 's1-snort', 'up'], check=False)
        #subprocess.run(['sudo', 'ovs-vsctl', 'add-port', 's1', 's1-snort'], check=False)
        #subprocess.run([
        #    'sudo', 'ovs-vsctl', '--', '--id=@m', 'create', 'mirror', 'name=mirror1',
        #    'select-all=true', 'output-port=s1-snort',
        #    '--', 'set', 'bridge', 's1', 'mirrors=@m'
        #], check=False)
	
        # Enlaces
        net.addLink(hosts['h1'], s1)
        net.addLink(hosts['h2'], s1)
        net.addLink(s1, hosts['h4'])  # web1
        net.addLink(s1, hosts['h5'])  # web2
        net.addLink(s1, s2)
        net.addLink(s2, hosts['h3'])
        #net.addLink(s1, snort1)  # Tráfico hacia Snort

        # Controlador remoto en localhost:6633
        c0 = RemoteController('c0', ip='127.0.0.1', port=6633)
        net.addController(c0)

        net.start()
	
        #snort1_intf = snort1.defaultIntf()
        #if snort1_intf:
        #        info(f"*** Interfície de Snort detectada: {snort1_intf}\n")
        #else:
        #        info("*** Error: Snort no té interfície. Comprova la topologia.\n")
        #        net.stop()
        #        return
        #snort_cmd = f"snort -i snort1 -A unsock -l /tmp -c /etc/snort/snort.conf"
        #snort1.cmd(snort_cmd)
        #info("*** Snort iniciat en snort1 amb la interfície correcta.\n")

        # Esperar uns segons per assegurar que Snort s'inicia correctament
        #time.sleep(2)
	
        # Iniciar Snort en el host snort1
        #snort1.cmd("sudo snort -i snort1-eth0 -A unsock -l /var/log/snort -c /etc/snort/snort.conf &")

        info("*** Topología iniciada.\n")
        net.interact()
        net.stop()

if __name__ == '__main__':
    setLogLevel('info')
    topo = TopoSDN()
    topo.build()
