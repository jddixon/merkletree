#!/usr/bin/env python3
# testMerkleTree.py

""" Test package functionality at the Tree level. """

import os
import shutil
import sys
import time
import unittest

from rnglib import SimpleRNG
from xlattice import (HashTypes, check_hashtype,
                      SHA1_HEX_NONE, SHA2_HEX_NONE, SHA3_HEX_NONE,
                      BLAKE2B_256_HEX_NONE)
from xlcrypto.hash import XLSHA1, XLSHA2, XLSHA3, XLBLAKE2B_256
from merkletree import MerkleTree, MerkleLeaf

ONE = 1
FOUR = 4
MAX_NAME_LEN = 8


class TestMerkleTree(unittest.TestCase):
    """ Test package functionality at the Tree level. """

    def setUp(self):
        self.rng = SimpleRNG(time.time())

    def tearDown(self):
        pass

    # utility functions ---------------------------------------------

    def get_two_unique_directory_names(self):
        """ Make two different quasi-random directory names."""
        dir_name1 = self.rng.next_file_name(MAX_NAME_LEN)
        dir_name2 = dir_name1
        while dir_name2 == dir_name1:
            dir_name2 = self.rng.next_file_name(MAX_NAME_LEN)
        self.assertTrue(len(dir_name1) > 0)
        self.assertTrue(len(dir_name2) > 0)
        self.assertTrue(dir_name1 != dir_name2)
        return (dir_name1, dir_name2)

    def make_one_named_test_directory(self, name, depth, width):
        """ Make a directory tree with a specific name, depth and width."""
        dir_path = "tmp/%s" % name
        if os.path.exists(dir_path):
            if os.path.isfile(dir_path):
                os.unlink(dir_path)
            elif os.path.isdir(dir_path):
                shutil.rmtree(dir_path)
        self.rng.next_data_dir(dir_path, depth, width, 32)
        return dir_path

    def make_two_test_directories(self, depth, width):
        """ Create two test directories with different names. """
        dir_name1 = self.rng.next_file_name(MAX_NAME_LEN)
        dir_path1 = self.make_one_named_test_directory(dir_name1, depth, width)

        dir_name2 = dir_name1
        while dir_name2 == dir_name1:
            dir_name2 = self.rng.next_file_name(MAX_NAME_LEN)
        dir_path2 = self.make_one_named_test_directory(dir_name2, depth, width)

        return (dir_name1, dir_path1, dir_name2, dir_path2)

    def verify_leaf_sha(self, node, path_to_file, hashtype):
        """
        Verify a leaf node is hashed correctly, using a specific SHA hash type.
        """
        self.assertTrue(os.path.exists(path_to_file))
        with open(path_to_file, "rb") as file:
            data = file.read()
        self.assertFalse(data is None)
        if hashtype == HashTypes.SHA1:
            sha = XLSHA1()
        elif hashtype == HashTypes.SHA2:
            sha = XLSHA2()
        elif hashtype == HashTypes.SHA3:
            sha = XLSHA3()
        elif hashtype == HashTypes.BLAKE2B:
            sha = XLBLAKE2B_256()
        else:
            raise NotImplementedError
        sha.update(data)
        hash_ = sha.digest()
        self.assertEqual(hash_, node.bin_hash)

    def verify_tree_sha(self, node, path_to_node, hashtype):
        """
        Verify tree elements are hashed correctly, assuming that the node
        is a MerkleTree, using a specific SHA hash type.
        """
        if node.nodes is None:
            self.assertEqual(None, node.bin_hash)
        else:
            hash_count = 0
            if hashtype == HashTypes.SHA1:
                sha = XLSHA1()
            elif hashtype == HashTypes.SHA2:
                sha = XLSHA2()
            elif hashtype == HashTypes.SHA3:
                sha = XLSHA3()
            elif hashtype == HashTypes.BLAKE2B:
                sha = XLBLAKE2B_256()
            else:
                raise NotImplementedError
            for node_ in node.nodes:
                path_to_file = os.path.join(path_to_node, node_.name)
                if isinstance(node_, MerkleLeaf):
                    self.verify_leaf_sha(node_, path_to_file, hashtype)
                elif isinstance(node_, MerkleTree):
                    self.verify_tree_sha(node_, path_to_file, hashtype)
                else:
                    self.fail("unknown node type!")
                if node_.bin_hash is not None:
                    hash_count += 1
                    sha.update(node_.bin_hash)

            # take care to compare values of the same type;
            # node.binHash is binary, node.hexHash is hex
            if hash_count == 0:
                self.assertEqual(None, node.bin_hash)
            else:
                self.assertEqual(sha.digest(), node.bin_hash)

    # unit tests ----------------------------------------------------

    def test_pathless_unbound(self):
        """
        Test basic characteristics of very simple MerkleTrees created
        using our standard SHA hash types.
        """
        for using in [HashTypes.SHA1, HashTypes.SHA2,
                      HashTypes.SHA3, HashTypes.BLAKE2B]:
            self.do_test_pathless_unbound(using)

    def do_test_pathless_unbound(self, hashtype):
        """
        Test basic characteristics of very simple MerkleTrees created
        using a specific SHA hash type.
        """
        (dir_name1, dir_name2) = self.get_two_unique_directory_names()

        check_hashtype(hashtype)
        tree1 = MerkleTree(dir_name1, hashtype)
        self.assertEqual(dir_name1, tree1.name)
        if hashtype == HashTypes.SHA1:
            self.assertEqual(SHA1_HEX_NONE, tree1.hex_hash)
        elif hashtype == HashTypes.SHA2:
            self.assertEqual(SHA2_HEX_NONE, tree1.hex_hash)
        elif hashtype == HashTypes.SHA3:
            self.assertEqual(SHA3_HEX_NONE, tree1.hex_hash)
        elif hashtype == HashTypes.BLAKE2B_256:
            self.assertEqual(BLAKE2B_256_HEX_NONE, tree1.hex_hash)
        else:
            raise NotImplementedError
        tree2 = MerkleTree(dir_name2, hashtype)
        self.assertEqual(dir_name2, tree2.name)

        # these tests remain skimpy
        self.assertFalse(tree1 is None)
        self.assertTrue(tree1 == tree1)
        self.assertFalse(tree1 == tree2)

        tree1_str = tree1.to_string(0)

        # there should be no indent on the first line
        self.assertFalse(tree1_str[0] == ' ')

        # no extra lines should be added
        lines = tree1_str.split('\n')
        # this split generates an extra blank line, because the serialization
        # ends with CR-LF
        if lines[-1] == '':
            lines = lines[:-1]
        self.assertEqual(1, len(lines))

        tree1_rebuilt = MerkleTree.create_from_serialization(
            tree1_str, hashtype)
        self.assertTrue(tree1 == tree1_rebuilt)

    def test_bound_flat_dirs(self):
        """
        Test handling of flat directories with a few data files
        using varioush SHA hash types.
        """
        for using in [HashTypes.SHA1, HashTypes.SHA2, HashTypes.SHA3, ]:
            self.do_test_bound_flat_dirs(using)

    def do_test_bound_flat_dirs(self, hashtype):
        """test directory is single level, with four data files"""

        check_hashtype(hashtype)
        (dir_name1, dir_path1, dir_name2, dir_path2) =\
            self.make_two_test_directories(ONE, FOUR)
        tree1 = MerkleTree.create_from_file_system(dir_path1, hashtype)
        self.assertEqual(dir_name1, tree1.name)
        nodes1 = tree1.nodes
        self.assertTrue(nodes1 is not None)
        self.assertEqual(FOUR, len(nodes1))
        self.verify_tree_sha(tree1, dir_path1, hashtype)

        tree2 = MerkleTree.create_from_file_system(dir_path2, hashtype)
        self.assertEqual(dir_name2, tree2.name)
        nodes2 = tree2.nodes
        self.assertTrue(nodes2 is not None)
        self.assertEqual(FOUR, len(nodes2))
        self.verify_tree_sha(tree2, dir_path2, hashtype)

        self.assertFalse(tree1 is None)
        self.assertTrue(tree1 == tree1)
        self.assertFalse(tree1 == tree2)

        tree1_str = tree1.to_string(0)
        tree1_rebuilt = MerkleTree.create_from_serialization(
            tree1_str, hashtype)
        self.assertTrue(tree1 == tree1_rebuilt)

    def test_bound_needle_dirs(self):
        """
        Test directories four deep with various SHA hash types.
        """
        for using in [HashTypes.SHA1, HashTypes.SHA2, HashTypes.SHA3, ]:
            self.do_test_bound_needle_dirs(using)

    def do_test_bound_needle_dirs(self, hashtype):
        """test directories four deep with one data file at the lowest level"""
        (dir_name1, dir_path1, dir_name2, dir_path2) =\
            self.make_two_test_directories(FOUR, ONE)
        tree1 = MerkleTree.create_from_file_system(dir_path1, hashtype)

        self.assertEqual(dir_name1, tree1.name)
        nodes1 = tree1.nodes
        self.assertTrue(nodes1 is not None)
        self.assertEqual(ONE, len(nodes1))
        self.verify_tree_sha(tree1, dir_path1, hashtype)

        tree2 = MerkleTree.create_from_file_system(dir_path2, hashtype)
        self.assertEqual(dir_name2, tree2.name)
        nodes2 = tree2.nodes
        self.assertTrue(nodes2 is not None)
        self.assertEqual(ONE, len(nodes2))
        self.verify_tree_sha(tree2, dir_path2, hashtype)

        self.assertTrue(tree1 == tree1)
        self.assertFalse(tree1 == tree2)

        tree1_str = tree1.to_string(0)
        tree1_rebuilt = MerkleTree.create_from_serialization(
            tree1_str, hashtype)
#       # DEBUG
#       print "NEEDLEDIR TREE1:\n" + tree1Str
#       print "REBUILT TREE1:\n" + tree1Rebuilt.toString("")
#       # END
        self.assertTrue(tree1 == tree1_rebuilt)

    # tests of bugs previously found --------------------------------

    def test_gray_boxes_bug1(self):
        """
        Verify that bug #1 in handling serialization of grayboxes website
        has been corrected.
        """
        serialization =\
            '721a08022dd26e7be98b723f26131786fd2c0dc3 grayboxes.com/\n' +\
            ' fcd3973c66230b9078a86a5642b4c359fe72d7da images/\n' +\
            '  15e47f4eb55197e1bfffae897e9d5ce4cba49623 grayboxes.gif\n' +\
            ' 2477b9ea649f3f30c6ed0aebacfa32cb8250f3df index.html\n'

        # create from string array ----------------------------------
        string = serialization.split('\n')
        string = string[:-1]
        self.assertEqual(4, len(string))

        tree2 = MerkleTree.create_from_string_array(string, HashTypes.SHA1)

        ser2 = tree2.to_string(0)
        self.assertEqual(serialization, ser2)

        # create from serialization ---------------------------------
        tree1 = MerkleTree.create_from_serialization(
            serialization, HashTypes.SHA1)

        ser1 = tree1.to_string(0)
        self.assertEqual(serialization, ser1)

        self.assertTrue(tree1 == tree2)

        # 2014-06-26 tagged this on here to test firstLineRE_1()
        first_line = string[0]
        match_ = MerkleTree.first_line_re_1().match(first_line)
        self.assertTrue(match_ is not None)
        self.assertEqual(match_.group(1), '')               # indent
        tree_hash = match_.group(2)
        dir_name = match_.group(3)
        self.assertEqual(tree_hash + ' ' + dir_name, first_line)

    def test_xlattice_bug1(self):
        """
        this test relies on dat.xlattice.org being locally present
        and an internally consistent merkleization
        """
        with open('tests/test_data/dat.xlattice.org', 'rb') as file:
            serialization = str(file.read(), 'utf-8')

        # create from serialization ---------------------------------
        tree1 = MerkleTree.create_from_serialization(
            serialization, HashTypes.SHA1)

#       # DEBUG
#       print "tree1 has %d nodes" % len(tree1.nodes)
#       with open('junk.tree1', 'w') as t:
#           t.write( tree1.toString(0) )
#       # END

        ser1 = tree1.to_string(0)
        self.assertEqual(serialization, ser1)

        # create from string array ----------------------------------
        string = serialization.split('\n')
        string = string[:-1]
        self.assertEqual(2511, len(string))

        tree2 = MerkleTree.create_from_string_array(string, HashTypes.SHA1)

        ser2 = tree2.to_string(0)
        self.assertEqual(serialization, ser2)

        self.assertTrue(tree1 == tree2)

    def test_gray_boxes_bug3(self):
        """ Test solution to bug in handling grayboxes website. """

        serialization =\
            '088d0e391e1a4872329e0f7ac5d45b2025363e26c199a7' + \
            '4ea39901d109afd6ba grayboxes.com/\n' +\
            ' 24652ddc14687866e6b1251589aee7e1e3079a87f80cd' + \
            '7775214f6d837612a90 images/\n' +\
            '  1eb774eef9be1e696f69a2f95711be37915aac283bb4' + \
            'b34dcbaf7d032233e090 grayboxes.gif\n' +\
            ' 6eacebda9fd55b59c0d2e48e2ed59ce9fd683379592f8' + \
            'e662b1de88e041f53c9 index.html\n'

        # create from string array ----------------------------------
        string = serialization.split('\n')
        string = string[:-1]
        self.assertEqual(4, len(string))

        tree2 = MerkleTree.create_from_string_array(string, HashTypes.SHA2)

        ser2 = tree2.to_string(0)
        self.assertEqual(serialization, ser2)

        # create from serialization ---------------------------------
        tree1 = MerkleTree.create_from_serialization(
            serialization, HashTypes.SHA2)

        ser1 = tree1.to_string(0)
        self.assertEqual(serialization, ser1)

        self.assertTrue(tree1 == tree2)

        # 2014-06-26 tagged this on here to test firstLineRE_1()
        first_line = string[0]
        match_ = MerkleTree.first_line_re_2().match(first_line)
        self.assertTrue(match_ is not None)
        self.assertEqual(match_.group(1), '')               # indent
        tree_hash = match_.group(2)
        dir_name = match_.group(3)
        self.assertEqual(tree_hash + ' ' + dir_name, first_line)

    def test_xlattice_bug3(self):
        """
        this test relies on dat2.xlattice.org being locally present
        and an internally consistent merkleization
        """
        with open('tests/test_data/dat2.xlattice.org', 'rb') as file:
            serialization = str(file.read(), 'utf-8')

        # create from serialization ---------------------------------
        tree1 = MerkleTree.create_from_serialization(
            serialization, HashTypes.SHA2)

        ser1 = tree1.to_string(0)
        self.assertEqual(serialization, ser1)

        # create from string array ----------------------------------
        string = serialization.split('\n')
        string = string[:-1]
        self.assertEqual(2511, len(string))

        tree2 = MerkleTree.create_from_string_array(string, HashTypes.SHA2)

        ser2 = tree2.to_string(0)
        self.assertEqual(serialization, ser2)

        self.assertTrue(tree1 == tree2)


if __name__ == '__main__':
    unittest.main()
