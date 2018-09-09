import optparse
from socket import *
from threading import *

screenLock = Semaphore(value=1)

def connScan(tgtHost, tgtPort):
    try:
        connSkt = socket(AF_INET, SOCK_STREAM)
        connSkt.connect((tgtHost, int(tgtPort)))
        connSkt.send("hello\r\n".encode())
        results = connSkt.recv(1024)
        print("results: {}".format(results))
        screenLock.acquire()
        print("[+] {}/tcp open".format(tgtPort))
    except Exception as e:
        screenLock.acquire()
        print("exception: {}".format(str(e)))
        print("[-] {}/tcp closed".format(tgtPort))
    finally:
        screenLock.release()
        connSkt.close()

def portScan(tgtHost, tgtPorts):
    try:
        tgtIP = gethostbyname(tgtHost)
    except:
        print("[-] Cannot resolve {}: Unknown host".format(tgtHost))
        return

    try:
        tgtName = gethostbyaddr(tgtIP)
        print("\n[+] Scan Results for: {}".format(tgtName[0]))
    except:
        print("\n[+] Scan Results for: {}".format(tgtIP))

    #setdefaulttimeout(1)
    for tgtPort in tgtPorts:
        t = Thread(target=connScan, args=(tgtHost, int(tgtPort)))
        t.start()

def Main():
    parser = optparse.OptionParser("usage %prog -H <target host> " +\
                                   "-p <target port>")
    parser.add_option("-H", dest="tgtHost", type="string", help="Specify a target host")
    parser.add_option("-p", dest="tgtPort", type="string", help="Specify target port[s] separated by commas")
    (options, args) = parser.parse_args()

    if options.tgtHost is None or options.tgtPort is None:
        print(parser.usage)
        exit(0)
    else:
        tgtHost = options.tgtHost
        tgtPorts = str(options.tgtPort).split(",")
    portScan(tgtHost, tgtPorts)

if __name__ == "__main__":
    Main()