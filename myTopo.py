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
        #s2 = net.addSwitch('s2')
	
        # Enlaces
        net.addLink(hosts['h1'], s1)
        net.addLink(hosts['h2'], s1)
	net.addLink(hosts['h3'], s1)    
        net.addLink(s1, hosts['h4'])  # web1
        net.addLink(s1, hosts['h5'])  # web2
        #net.addLink(s1, s2)
        #net.addLink(s2, hosts['h3'])

        # Controlador remoto en localhost:6633
        c0 = RemoteController('c0', ip='127.0.0.1', port=6633)
        net.addController(c0)

        net.start()

        info("*** Topología iniciada.\n")
        net.interact()
        net.stop()

if __name__ == '__main__':
    setLogLevel('info')
    topo = TopoSDN()
    topo.build()
