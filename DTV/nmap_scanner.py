import optparse
import nmap


def nmapScan(tgtHost, tgtPort):
    nScan = nmap.PortScanner()
    nScan.scan(tgtHost, tgtPort, '-v --version-all')
    print("[*] HOST: {}:{}".format(tgtHost, tgtPort))
    for p in nScan[tgtHost]['tcp'].keys():
        print("[+] Port {:>4}: ".format(p) + str(nScan[tgtHost]['tcp'][int(p)]['state']))

def Main():
    parser = optparse.OptionParser("usage %prog -H <target host> " + \
                                   "-p <target port>")
    parser.add_option("-H", dest="tgtHost", type="string", help="Specify a target host")
    parser.add_option("-p", dest="tgtPort", type="string", help="Specify target port[s] separated by commas")
    (options, args) = parser.parse_args()

    if options.tgtHost is None or options.tgtPort is None:
        print(parser.usage)
        exit(0)
    else:
        tgtHost = options.tgtHost
        tgtPorts = options.tgtPort

    print("Scan in progress...")
    nmapScan(tgtHost, tgtPorts)

if __name__ == "__main__":
    Main()