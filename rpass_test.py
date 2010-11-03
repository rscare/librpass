#!/usr/bin/env python
# encoding: utf-8

import rpass
import unittest

class DecryptFile(unittest.TestCase):
    def test_fail_on_nonexistent_file(self):
        """DecryptFile() should raise exception if file does not exist."""
        self.assertRaises(IOError, rpass.DecryptPassFile, "nonexistent_file.txt")

    def test_fail_on_unencrypted_file(self):
        """DecryptFile() should raise exception if file is not encrypted."""
        self.assertRaises(rpass.UnencryptedFile, rpass.DecryptPassFile, "testing/invalid_gpg_file.gpg")

    def test_accurate_decryption(self):
        """DecryptFile() should return an unencrypted string accurately representing an encrypted file."""
        self.assertEqual(rpass.DecryptPassFile('testing/test.gpg'), open('testing/test').read().strip())

class EncryptFile(unittest.TestCase):
    def test_accurate_encryption(self):
        """EncryptPassFile() should accurately encrypt information that can then be decrypted."""
        test_file = "testing/test_output.gpg"
        test_contents = "The number 7 is the best number ever.\nThe number 7 is also really useful."
        rpass.EncryptPassFile(test_contents, test_file)
        self.assertEqual(test_contents, rpass.DecryptPassFile(test_file))
        from os import unlink; unlink(test_file)

class ParseFile(unittest.TestCase):
    test_info = {
            "Test Account 1":{'user':'Test1', 'pass':'Pass1'},
            "Test Account 2":{'user':'Test2', 'pass':'Pass2'},
            "Test Account 3":{'user':'Test3', 'pass':'Pass3', 'testfield':'Strange3'}
            }
    def test_accurate_parsing(self):
        """ParsePassFile() must return accurate results for accounts formatted 
        [Account name]
        field = value."""
        pinfo = rpass.ParsePassFile(passfile = 'testing/test.gpg')
        for account in pinfo:
            self.assertEqual(self.test_info[account], pinfo[account])

class EditEntries(unittest.TestCase):
    def test_delete_existing_entry(self):
        """Existing entry should be deleted by DeleteEntry."""
        pass

    def test_add_nonexisting_entry(self):
        """Non-existing entry should be added by AddEntry."""
        pass

    def test_add_exception_on_existing(self):
        """Adding an existing entry causes an ExistingEntry exception to be raised."""
        self.assertRaises(rpass.ExistingEntry, rpass.AddEntry, {'acname':'Test Account 1', 'user':'Test2'}, None, 'testing/test.gpg')

    def test_delete_exception_on_nonexisting_entry(self):
        """Non-existent entry should cause a NonexistentEntry exception to be raised."""
        self.assertRaises(rpass.NonexistentEntry, rpass.DeleteEntry, "Not Good Account", None, 'testing/test.gpg')

if __name__ == '__main__':
    unittest.main()
