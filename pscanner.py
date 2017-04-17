#!/usr/bin/env python3
import optparse

import socket as sk
import ipaddress

class Main():
    def __init__(self, target, ports, toScan, doTCP, doUDP):
        self.doTCP = doTCP
        self.doUDP = doUDP
        if '-' in ports:
            self.portRange = range(int(ports.split('-')[0]), 1+int(ports.split('-')[1]))
        elif ',' in ports:
            self.portRange = list(map(int,ports.split(',')))
        self.openPorts=0
        self.ips = []
        self.reportTCP = {}
        self.reportUDP = {}
        if toScan != "none":
            theFile = open(toScan, 'r')
            for line in theFile:
                self.ips.append(line.rstrip())
        elif '/' in target:
            self.ips = ipaddress.ip_network(target)
        else:
            self.ips.append(target)

    def scan(self):
        if self.doTCP:
            for target in self.ips:
                target = str(target)
                self.reportTCP[target] = 0
                print ("Target:\t\t%s" % (target))
                print ("Ports:\t\t%s" % (options.ports))
                print ("Protocol:\t%s" % ("TCP"))
                print ("---------------------------")
                for port in self.portRange:
                    try:
                        s=sk.socket(sk.AF_INET,sk.SOCK_STREAM)
                        s.settimeout(.001)
                        s.connect((target,port))
                        print ('%d:OPEN' % (port))
                        self.reportTCP[target]+=1
                        s.close
                    except:
                        continue
                print()
        if self.doUDP:
            for target in self.ips:
                target = str(target)
                self.reportUDP[target] = 0
                print ("Target:\t\t%s" % (target))
                print ("Ports:\t\t%s" % (options.ports))
                print ("Protocol:\t%s" % ("UDP"))
                print ("---------------------------")
                for port in self.portRange:
                    try:
                        data="Hello"
                        s=sk.socket(sk.AF_INET,sk.SOCK_DGRAM)
                        s.sendto(data, (target,port))
                        s.settimeout(0)
                        print ((s.recvfrom(1024)))
                        print ('%d:OPEN' % (port))
                        self.reportUDP[target]+=1
                        s.close
                    except:
                        continue
                print()
        print ("Finished Scan:")
        for target in self.reportTCP:
            if self.doTCP:
                print ("\tTarget %s has %s TCP ports open" % (target, self.reportTCP[target]))
            elif self.doUDP:
                print ("\tTarget %s has %s UDP ports open" % (target, self.reportUDP[target]))
        if len(self.reportTCP) < 1:
            print ("\tDid you specify protocol? (--tcp or --udp)")


if __name__ == '__main__':
    parser = optparse.OptionParser(
        usage="%prog -t [Target] -p [Ports]", version="%prog -.1")
    parser.add_option("-t", "--target", dest="target",
                      default="127.0.0.1",
                      help="target to scan")
    parser.add_option("-p", "--ports", dest="ports",
                      default="1-1024",
                      help="ports to scan (syntax %d-%d)")
    parser.add_option("-f", "--file", dest="toScan",
                      default="none",
                      help="optional file with list of IPS")
    parser.add_option ("--tcp", dest="doTCP", action="store_true",
                      default=False,
                      help="Use TCP protocol")
    parser.add_option ("--udp", dest="doUDP", action="store_true",
                      default=False,
                      help="Use UDP protocol")
    (options, args) = parser.parse_args()

    m = Main(options.target, options.ports, options.toScan, options.doTCP, options.doUDP)
    m.scan()
