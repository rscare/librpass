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

def IsRunning(procname):
    import re
    from subprocess import Popen,PIPE

    ppatt = re.compile(r'^\s*\d+ \S*\s*\d\d:\d\d:\d\d (.*)$')
    proc = Popen(['ps', '-e'], stdout = PIPE, stderr = PIPE)

    plist = [re.match(ppatt, p.strip()).groups()[0] for p in str(proc.communicate()[0], encoding='utf-8').split('\n')[1:-1]]

    if procname in plist: return True
    else: return False

class rpass:
    """ Class to encapsulate an rpass user """

    def __init__(self, conf_file = '~/.rpass.conf', passfile = None, executable = False):
        """Initialized rpass from an optional configuration file and arguments.
        
        Set executable to 'true' if instance is not being used for a plugin."""

        from os.path import isfile,expanduser

        if not(self.HasGPGKey()):
            self.CreateGPGKey()

        self.executable = executable
        self.conf_file = conf_file
        (self.options, self.copyerror) = self.ReadConfigFile(filename = self.conf_file)

        if passfile != None: self.options['passfile'] = passfile
        if ('passfile' not in self.options) or not(self.options['passfile']): self.options['passfile'] = '~/.passwords.gpg'

        self.passfile = expanduser(self.options['passfile'])

        if not(isfile(self.passfile)): self.first = True
        else: self.first = False

        self.entries = None
        if not(self.first):
            self.entries = self.ParsePassFile(self.passfile)

    def CreateGPGKey(self):
        """Creates a gpg key for the user."""

        from subprocess import call
        print("Need to first create gpg key pair.")
        print("Choose a secure passphrase -- this is going to be your 'master' password.")
        print("Rerun program after key creation.\n")
        print("WARNING: DO NOT pick a sign-only key type.\n")
        print("-------------------------------------------------------------------------")
        input("Press [ENTER] when ready.")
        call('gpg --gen-key'.split(' '))

    def HasGPGKey(self):
        """Checks if the user has a gpg key pair."""

        from os import stat
        from os.path import expanduser,isfile,join

        secring = join(expanduser('~'), '.gnupg', 'secring.gpg')
        if not(isfile(secring)) or stat(secring).st_size == 0: return False
        else: return True

    def CopyDefaultConf(self, location, conf_locs):
        """Attempts to copy the default configuration to the specified location."""

        from os.path import expanduser,isfile
        fexample = None
        for p in conf_locs:
            if isfile(p): 
                fexample = p
                break

        if not(fexample):
            raise IOError("Could not find default configuration file in any of the following locations: {0}".format(','.join(conf_locs)))
        else:
            from shutil import copyfile
            copyfile(fexample, expanduser(location))

    def ReadConfigFile(self, filename, info = {}):
        """When passed a filename, reads the config file for rpass information.
        
        Returns a dictionary of useful values."""
        import configparser
        from os.path import expanduser,isfile

        if not(isfile(expanduser(filename))):

            # Try to copy the default configuration
            from sys import path

            paths = ["{0}/../share/rpass/", "/usr/share/rpass/", "/usr/local/share/rpass/", "{0}/"]
            paths = [p.format(path[0]) + 'rpass.example.conf' for p in paths]

            try:
                self.CopyDefaultConf(expanduser(filename), paths)
            except IOError as e:
                info['fields'] = []
                return (info, str(e))

        config = configparser.ConfigParser()
        config.read(expanduser(filename))

        if config.has_option('display', 'fields'): 
            info['fields'] = [field.strip() for field in 
                    config.get('display', 'fields').split(',') if field.strip()]
            if len([f for f in info['fields'] if f.strip()]) == 0: info['fields'] = [None]
        if config.has_option('display', 'color'):
            if config.get('display', 'color').lower()[0] == 'y': info['color'] = True
            else: info['color'] = False

        if config.has_option('general', 'passfile'):
            from os.path import expanduser
            info['passfile'] = expanduser(config.get('general', 'passfile'))

        return (info, None)

    def DecryptPassFile(self, passfile):
        from os.path import isfile,expanduser
        if not isfile(passfile): raise IOError("Password file not found.")

        from os import environ
        from rGPG import decrypt_file

        gpg_info_name = expanduser('~/.gpg-agent-info')
        has_gpg_info = isfile(gpg_info_name)
        proclst = ['gpg', '--quiet', '--output', '-', '--decrypt', passfile]

        if not(self.executable):
            if not(IsRunning('gpg-agent')):
                raise RuntimeError("No gpg-agent running when rpass is being used as a plugin.")
            if not(has_gpg_info):
                raise RuntimeError("gpg-agent invoked without --write-env-file option when rpass is being used as a plugin.")

        if IsRunning('gpg-agent'): 
            if has_gpg_info:
                with open(gpg_info_name) as GPG_FILE:
                    tmp = GPG_FILE.readlines()
                    environ.update(dict([tuple(t.strip().split('=')) for t in tmp]))

        return decrypt_file(passfile).strip()

    def EncryptPassFile(self, passfile, contents):
        from rGPG import encrypt_file
        encrypt_file(contents, passfile)

    def Write(self):
        self.EncryptPassFile(self.passfile, self.CreatePassFile(self.entries))

    def ParsePassFile(self, passfile, contents = None):
        if contents == None: contents = self.DecryptPassFile(passfile = passfile)

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

    def GetAccountInfo(self, account, strict = False):
        if self.entries == None:
            return {}

        import re
        accountpatt = ''
        if strict:
            accountpatt = re.compile("^{0}$".format(account))
        else:
            accountpatt = re.compile(account, re.I)
        accountdict = {}

        for ac in self.entries.keys():
            if accountpatt.search(ac): accountdict[ac] = self.entries[ac]

        return accountdict

    def CopyPass(self, acinfo = None, account = '.'):
        if acinfo == None: return False
        from subprocess import Popen,PIPE

        for ac in sorted(acinfo.keys()):
            if 'pass' in acinfo[ac]:
                echoproc = Popen(['echo', acinfo[ac]['pass']], shell=False, stdout=PIPE)
                copyproc = Popen(['xclip'], shell=False, stdin=echoproc.stdout)
                return True
        return False

    def CreatePassFile(self, pinfo):
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

    def DeleteEntry(self, entry):
        if entry in self.entries: 
            del(self.entries[entry])
        else:
            raise NonexistentEntry

    def AddEntry(self, name, entry):
        """Adds an entry to the account."""

        if type(self.entries) == dict:
            if name in self.entries: raise ExistingEntry
        else:
            self.entries = {}

        self.entries[name] = entry
