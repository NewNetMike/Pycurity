import optparse
import zipfile
from threading import Thread

def extract_zip(zFile, password):
    try:
        password = bytes(password.encode('utf-8'))
        zFile.extractall(pwd=password)
        print("[+] Password found: {}\n".format(password.decode("utf-8") ))
    except:
        pass

def Main():
    parser = optparse.OptionParser("Usage: %prog "+\
                                   "-f <zipfile> -d <dictionary>")
    parser.add_option("-f", dest="zname", type="string",\
                      help="specify zipfile")
    parser.add_option("-d", dest="dname", type="string",\
                      help="specify dictionary")
    (options, arg) = parser.parse_args()
    if options.zname is None or options.dname is None:
        print(parser.usage)
        exit(0)
    else:
        zname = options.zname
        dname = options.dname

    zFile = zipfile.ZipFile(zname)
    passFile = open(dname)

    for line in passFile.readlines():
        password = line.strip("\n")
        t = Thread(target=extract_zip, args=(zFile, password))
        t.start()

if __name__ == "__main__":
    Main()