#!/usr/bin/python2

def DecryptPassFile(passfile = None):
    if passfile == None:
        from os.path import expanduser
        passfile = expanduser('~/.passwords.gpg')

    from subprocess import Popen,PIPE
    proc = Popen(['gpg', '--quiet', '--no-tty', '--output', '-', '--decrypt', passfile],
            stdout = PIPE)

    return proc.communicate()[0]

def EncryptPassFile(contents, passfile):
    from subprocess import Popen,PIPE
    textproc = Popen(['echo', contents], shell=False, stdout=PIPE)
    encproc = Popen(['gpg', '--output', passfile, '--encrypt'], shell=False, stdin=textproc.stdout)

def ParsePassFile(contents = None):
    if contents == None: contents = DecryptPassFile()

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

def GetAccountInfo(account, pinfo = None):
    if pinfo == None: pinfo = ParsePassFile()

    import re
    accountpatt = re.compile(account, re.I)
    accountdict = {}

    for ac in pinfo.keys():
        if accountpatt.search(ac): accountdict[ac] = pinfo[ac]

    return accountdict

def PrintAccountInfo(acinfo = None, account = '.', ppass = False):
    fgnescape = '\x1b[0;38;5;{0}m'
    bgnescape = '\x1b[0;48;5;{0}m'
    fgbescape = '\x1b[1;38;5;{0}m'

    if acinfo == None: acinfo = GetAccountInfo(account)

    ac_color = fgbescape.format(7)
    user_color = fgnescape.format(6)
    pass_color = fgnescape.format(9)

    for ac in sorted(acinfo.keys()):
        if acinfo[ac].has_key('user'):
            print ac_color + ac + " - {0}{1}".format(user_color,acinfo[ac]['user'])
        else: print ac_color + ac
        if acinfo[ac].has_key('pass') and ppass:
            print "\t{0}{1}".format(pass_color,acinfo[ac]['pass'])
        for (k, v) in acinfo[ac].items():
            if k not in ['user', 'pass']:
                print "\t{0}: {1}".format(k, v)

def CopyPass(account = '.', acinfo = None):
    if acinfo == None: acinfo = GetAccountInfo(account)
    from subprocess import Popen,PIPE

    for ac in sorted(acinfo.keys()):
        if acinfo[ac].has_key('pass'):
            echoproc = Popen(['echo', acinfo[ac]['pass']], shell=False, stdout=PIPE)
            copyproc = Popen(['xclip'], shell=False, stdin=echoproc.stdout)
            return True
    return False

if __name__=="__main__":
    from optparse import OptionParser

    parser = OptionParser()
    parser.add_option("-p", "--passwords", dest="print_pass",
            action="store_true", default=False,
            help="Print passwords to stdout.")
    parser.add_option("-c", "--no-copy", dest="xclip",
            action="store_false", default=True,
            help="Don't copy alphabetically first matching password to clipboard.")
    parser.add_option("-l", "--login", dest="login",
            action="store_true", default=False,
            help="Just login, don't show anything.")

    (options, args) = parser.parse_args()

    acinfo = {}
    if options.login:
        DecryptPassFile(); exit()
    if len(args) > 0:
        for arg in args: acinfo.update(GetAccountInfo(arg))
    else:
        acinfo = None
    PrintAccountInfo(acinfo=acinfo, ppass=options.print_pass)
    if options.xclip: CopyPass(acinfo=acinfo)
