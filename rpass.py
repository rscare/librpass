class UnencryptedFile(IOError):
    """Exception to take care of unencrypted files."""
    pass

class ExistingEntry(ValueError):
    """Exception raised when attempting to overwrite an existing entry."""
    pass

class NonexistentEntry(ValueError):
    """Exception raised when attempting to modify nonexistent entry."""
    pass

class InvalidEncryptionKey(ValueError):
    """Exception raised when key is nonexistent or incorrect."""
    pass

def DecryptPassFile(passfile = None):
     if passfile == None:
         from os.path import expanduser,join
         passfile = join(expanduser('~'),".passwords.gpg")
 
     from os.path import isfile
     if not isfile(passfile): raise IOError

     from subprocess import Popen,PIPE
     proc = Popen(['ps', '-e'], stdout = PIPE, stderr = PIPE)
     proclst = ['gpg', '--quiet', '--output', '-', '--decrypt', passfile]
     if 'gpg-agent' in str(proc.communicate()[0], encoding = 'utf-8'): proclst.insert(1, '--no-tty')
     proc = Popen(proclst, stdout = PIPE, stderr = PIPE)
 
     retstr, errstr = tuple(str(s, encoding = "utf-8") for s in proc.communicate())
     if errstr.find("gpg: no valid OpenPGP data found.") != -1: raise UnencryptedFile
     elif errstr.find("gpg: decryption failed: secret key not available") != -1: raise InvalidEncryptionKey

     return retstr.strip()

def EncryptPassFile(contents, passfile = None):
    if passfile == None:
        from os.path import expanduser,join
        passfile = join(expanduser('~'),".passwords.gpg")

    from os.path import exists
    from subprocess import Popen,PIPE
    textproc = Popen(['echo', contents], shell=False, stdout=PIPE)
    encproc = Popen(['gpg', '--default-recipient-self', '--yes', '--output', passfile, '--encrypt'], shell=False, stdin=textproc.stdout).wait()

def ParsePassFile(contents = None, passfile = None):
    if contents == None: contents = DecryptPassFile(passfile = passfile)

    import re
    parray = [s.strip() for s in contents.split('\n') if not(re.match(r'^\s*$', s))]
    pdict = {}
    ckey = ""
    accountpatt = re.compile(r'^\[([^]]+)\]$')
    fieldpatt = re.compile(r'^(.*?)\s*=\s*(.*)$')
    for i in parray:
        if accountpatt.match(i) != None:
            ckey = accountpatt.match(i).group(1)
            pdict[ckey] = {}
        else:
            match = fieldpatt.match(i)
            pdict[ckey][match.group(1)] = match.group(2)

    return pdict

def GetAccountInfo(account, pinfo = None, strict = False):
    if pinfo == None: pinfo = ParsePassFile()

    import re
    accountpatt = ''
    if strict:
        accountpatt = re.compile("^{0}$".format(account))
    else:
        accountpatt = re.compile(account, re.I)
    accountdict = {}

    for ac in pinfo.keys():
        if accountpatt.search(ac): accountdict[ac] = pinfo[ac]

    return accountdict

def PrintAccountInfo(acinfo = None, account = '.', pfull = False, ppass = False, keys = None, batch = False):
    fgnescape = '\x1b[0;38;5;{0}m'
    bgnescape = '\x1b[0;48;5;{0}m'
    fgbescape = '\x1b[1;38;5;{0}m'

    if acinfo == None: acinfo = GetAccountInfo(account, strict = batch)

    ac_color = fgbescape.format(7)
    user_color = fgnescape.format(6)
    pass_color = fgnescape.format(9)

    if keys:
        acinfokeys = keys

    for ac in sorted(acinfo.keys()):
        if not(batch):
            if 'user' in acinfo[ac]:
                print(ac_color + ac + " - {0}{1}".format(user_color,acinfo[ac]['user']))
            else: print(ac_color + ac)
            if ppass and ('pass' in acinfo[ac]):
                print("\t{0}{1}".format(pass_color,acinfo[ac]['pass']))
            if pfull:
                for (k, v) in acinfo[ac].items():
                    if k not in ['user', 'pass']:
                        print("\t{0}: {1}".format(k, v))
        else:
            for (k, v) in acinfo[ac].items():
                if not(acinfokeys) or (k in acinfokeys):
                    print(v)

def CopyPass(account = '.', acinfo = None):
    if acinfo == None: acinfo = GetAccountInfo(account)
    from subprocess import Popen,PIPE

    for ac in sorted(acinfo.keys()):
        if 'pass' in acinfo[ac]:
            echoproc = Popen(['echo', acinfo[ac]['pass']], shell=False, stdout=PIPE)
            copyproc = Popen(['xclip'], shell=False, stdin=echoproc.stdout)
            return True
    return False

def AddEntry(new_entry = None, pinfo = None, passfile = None):
    if pinfo == None: pinfo = ParsePassFile(passfile = passfile)
    if new_entry == None:
        acname = input("Account name: ")
        if (acname) in pinfo.keys(): raise ExistingEntry
        pinfo[acname] = {}
        print("Please enter field followed by value - blank field cancels.")
        field = input("Field: ")
        while(field):
            if field in ["username", "u"]: field = "user"
            if field in ["password", "p", "pass"]:
                from getpass import getpass as gp
                field = "pass"
                pinfo[acname][field] = gp("{0}: ".format(field))
            else:
                pinfo[acname][field] = input("{0}: ".format(field))
            field = input("Field: ")
    else:
        acname = new_entry['acname']
        if acname in pinfo.keys(): raise ExistingEntry
        pinfo[acname] = {key:value for (key, value) in new_entry.items() if key != 'acname'}

    EncryptPassFile(CreatePassFile(pinfo))

def CreatePassFile(pinfo):
    contents = ""
    ftemplate = "    {0} = {1}\n"
    sorted_accounts = sorted(pinfo.keys())
    for key in sorted_accounts:
        contents += "[{0}]\n".format(key)
        if "user" in pinfo[key]: contents += ftemplate.format("user", pinfo[key]["user"])
        if "pass" in pinfo[key]: contents += ftemplate.format("pass", pinfo[key]["pass"])
        for (field, value) in pinfo[key].items():
            if field not in ["user", "pass"]: contents += ftemplate.format(field, value)
        contents += "\n"
    return contents.strip()

def DeleteEntry(entry, pinfo = None, passfile = None):
    if pinfo == None: pinfo = ParsePassFile(passfile = passfile)
    if entry in pinfo: 
        del(pinfo[entry])
        EncryptPassFile(CreatePassFile(pinfo))
        print("Deleted account {0}.".format(entry))
    else:
        raise NonexistentEntry
