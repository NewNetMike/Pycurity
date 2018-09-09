import crypt
import optparse

def test_pass(cpass, dname):
    salt = cpass[:2]
    dfile = open(dname, "r")
    for word in dfile.readline():
        word = word.strip("\n")
        cryptWord = crypt.crypt(word, salt)
        print("cryptword =" + cryptWord + " | cpass = " + cpass)
        if cryptWord == cpass:
            print("[*] Found Password: {}\n".format(word))
            return
    print("[-] Password not found.\n")
    return

def main():
    passFile = open("passwords.txt", "r")
    for line in passFile.readlines():
        if ":" in line:
            user = line.split(":")[0]
            cryptPass = line.split(":")[1].strip(" ")
            print("[*] Cracking password for: {}".format(user))
            test_pass(cryptPass, "dictionary.txt")

if __name__ == "__main__":
    main()