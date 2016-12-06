#!/usr/bin/env python3

# testMerkleTree.py
import os
import shutil
import sys
import time
import unittest
import hashlib

from rnglib import SimpleRNG
from xlattice import (QQQ, check_using_sha,
                      SHA1_HEX_NONE, SHA2_HEX_NONE, SHA3_HEX_NONE)
from merkletree import MerkleTree, MerkleLeaf

if sys.version_info < (3, 6):
    # pylint:disable=unused-import
    import sha3                 # monkey-patches hashlib

ONE = 1
FOUR = 4
MAX_NAME_LEN = 8


class TestMerkleTree(unittest.TestCase):

    def setUp(self):
        self.rng = SimpleRNG(time.time())

    def tearDown(self):
        pass

    # utility functions ---------------------------------------------

    def get_two_unique_directory_names(self):
        dir_name1 = self.rng.nextFileName(MAX_NAME_LEN)
        dir_name2 = dir_name1
        while dir_name2 == dir_name1:
            dir_name2 = self.rng.nextFileName(MAX_NAME_LEN)
        self.assertTrue(len(dir_name1) > 0)
        self.assertTrue(len(dir_name2) > 0)
        self.assertTrue(dir_name1 != dir_name2)
        return (dir_name1, dir_name2)

    def make_one_named_test_directory(self, name, depth, width):
        dir_path = "tmp/%s" % name
        if os.path.exists(dir_path):
            shutil.rmtree(dir_path)
        self.rng.nextDataDir(dir_path, depth, width, 32)
        return dir_path

    def make_two_test_directories(self, depth, width):
        dir_name1 = self.rng.nextFileName(MAX_NAME_LEN)
        dir_path1 = self.make_one_named_test_directory(dir_name1, depth, width)

        dir_name2 = dir_name1
        while dir_name2 == dir_name1:
            dir_name2 = self.rng.nextFileName(MAX_NAME_LEN)
        dir_path2 = self.make_one_named_test_directory(dir_name2, depth, width)

        return (dir_name1, dir_path1, dir_name2, dir_path2)

    def verify_leaf_sha(self, node, path_to_file, using_sha):
        self.assertTrue(os.path.exists(path_to_file))
        with open(path_to_file, "rb") as file:
            data = file.read()
        self.assertFalse(data is None)
        # pylint: disable=redefined-variable-type
        if using_sha == QQQ.USING_SHA1:
            sha = hashlib.sha1()
        elif using_sha == QQQ.USING_SHA2:
            sha = hashlib.sha256()
        elif using_sha == QQQ.USING_SHA3:
            # pylint: disable=no-member
            sha = hashlib.sha3_256()
        sha.update(data)
        hash_ = sha.digest()
        self.assertEqual(hash_, node.bin_hash)

    def verify_tree_sha(self, node, path_to_node, using_sha):
        # we assume that the node is a MerkleTree
        if node.nodes is None:
            self.assertEqual(None, node.bin_hash)
        else:
            hash_count = 0
            if using_sha == QQQ.USING_SHA1:
                sha = hashlib.sha1()
            elif using_sha == QQQ.USING_SHA2:
                sha = hashlib.sha256()
            elif using_sha == QQQ.USING_SHA3:
                # pylint: disable=no-member
                sha = hashlib.sha3_256()
            for node_ in node.nodes:
                path_to_file = os.path.join(path_to_node, node_.name)
                if isinstance(node_, MerkleLeaf):
                    self.verify_leaf_sha(node_, path_to_file, using_sha)
                elif isinstance(node_, MerkleTree):
                    self.verify_tree_sha(node_, path_to_file, using_sha)
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

    def test_pathless_unbound_constructor(self):
        for using in [QQQ.USING_SHA1, QQQ.USING_SHA2, QQQ.USING_SHA3, ]:
            self.do_test_pathless_unbound_constructor(using)

    def do_test_pathless_unbound_constructor(self, using_sha):
        (dir_name1, dir_name2) = self.get_two_unique_directory_names()

        check_using_sha(using_sha)
        tree1 = MerkleTree(dir_name1, using_sha)
        self.assertEqual(dir_name1, tree1.name)
        if using_sha == QQQ.USING_SHA1:
            self.assertEqual(SHA1_HEX_NONE, tree1.hex_hash)
        elif using_sha == QQQ.USING_SHA2:
            self.assertEqual(SHA2_HEX_NONE, tree1.hex_hash)
        elif using_sha == QQQ.USING_SHA3:
            self.assertEqual(SHA3_HEX_NONE, tree1.hex_hash)

        tree2 = MerkleTree(dir_name2, using_sha)
        self.assertEqual(dir_name2, tree2.name)

        # these tests remain skimpy
        self.assertTrue(tree1.equal(tree1))
        self.assertFalse(tree1.equal(tree2))
        self.assertFalse(tree1.equal(None))

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
            tree1_str, using_sha)
        self.assertTrue(tree1.equal(tree1_rebuilt))

    def test_bound_flat_dirs(self):
        for using in [QQQ.USING_SHA1, QQQ.USING_SHA2, QQQ.USING_SHA3, ]:
            self.do_test_bound_flat_dirs(using)

    def do_test_bound_flat_dirs(self, using_sha):
        """test directory is single level, with four data files"""

        check_using_sha(using_sha)
        (dir_name1, dir_path1, dir_name2, dir_path2) =\
            self.make_two_test_directories(ONE, FOUR)
        tree1 = MerkleTree.create_from_file_system(dir_path1, using_sha)
        self.assertEqual(dir_name1, tree1.name)
        nodes1 = tree1.nodes
        self.assertTrue(nodes1 is not None)
        self.assertEqual(FOUR, len(nodes1))
        self.verify_tree_sha(tree1, dir_path1, using_sha)

        tree2 = MerkleTree.create_from_file_system(dir_path2, using_sha)
        self.assertEqual(dir_name2, tree2.name)
        nodes2 = tree2.nodes
        self.assertTrue(nodes2 is not None)
        self.assertEqual(FOUR, len(nodes2))
        self.verify_tree_sha(tree2, dir_path2, using_sha)

        # XXX COMMENTED OUT FOR DEBUGGING XXX
        #self.assertTrue  ( tree1.equal(tree1) )
        self.assertFalse(tree1.equal(tree2))
        self.assertFalse(tree1.equal(None))

        tree1_str = tree1.to_string(0)
        tree1_rebuilt = MerkleTree.create_from_serialization(
            tree1_str, using_sha)
        self.assertTrue(tree1.equal(tree1_rebuilt))

    def test_bound_needle_dirs(self):
        for using in [QQQ.USING_SHA1, QQQ.USING_SHA2, QQQ.USING_SHA3, ]:
            self.do_test_bound_needle_dirs(using)

    def do_test_bound_needle_dirs(self, using_sha):
        """test directories four deep with one data file at the lowest level"""
        (dir_name1, dir_path1, dir_name2, dir_path2) =\
            self.make_two_test_directories(FOUR, ONE)
        tree1 = MerkleTree.create_from_file_system(dir_path1, using_sha)

        self.assertEqual(dir_name1, tree1.name)
        nodes1 = tree1.nodes
        self.assertTrue(nodes1 is not None)
        self.assertEqual(ONE, len(nodes1))
        self.verify_tree_sha(tree1, dir_path1, using_sha)

        tree2 = MerkleTree.create_from_file_system(dir_path2, using_sha)
        self.assertEqual(dir_name2, tree2.name)
        nodes2 = tree2.nodes
        self.assertTrue(nodes2 is not None)
        self.assertEqual(ONE, len(nodes2))
        self.verify_tree_sha(tree2, dir_path2, using_sha)

        self.assertTrue(tree1.equal(tree1))
        self.assertFalse(tree1.equal(tree2))

        tree1_str = tree1.to_string(0)
        tree1_rebuilt = MerkleTree.create_from_serialization(
            tree1_str, using_sha)
#       # DEBUG
#       print "NEEDLEDIR TREE1:\n" + tree1Str
#       print "REBUILT TREE1:\n" + tree1Rebuilt.toString("")
#       # END
        self.assertTrue(tree1.equal(tree1_rebuilt))   # GEEP

    # tests of bugs previously found --------------------------------

    def test_gray_boxes_bug1(self):
        serialization =\
            '721a08022dd26e7be98b723f26131786fd2c0dc3 grayboxes.com/\n'       +\
            ' fcd3973c66230b9078a86a5642b4c359fe72d7da images/\n'            +\
            '  15e47f4eb55197e1bfffae897e9d5ce4cba49623 grayboxes.gif\n'    +\
            ' 2477b9ea649f3f30c6ed0aebacfa32cb8250f3df index.html\n'

        # create from string array ----------------------------------
        string = serialization.split('\n')
        string = string[:-1]
        self.assertEqual(4, len(string))

        tree2 = MerkleTree.create_from_string_array(string, QQQ.USING_SHA1)

        ser2 = tree2.to_string(0)
        self.assertEqual(serialization, ser2)

        # create from serialization ---------------------------------
        tree1 = MerkleTree.create_from_serialization(
            serialization, QQQ.USING_SHA1)

        ser1 = tree1.to_string(0)
        self.assertEqual(serialization, ser1)

        self.assertTrue(tree1.equal(tree2))

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
        with open('testData/dat.xlattice.org', 'rb') as file:
            serialization = str(file.read(), 'utf-8')

        # create from serialization ---------------------------------
        tree1 = MerkleTree.create_from_serialization(
            serialization, QQQ.USING_SHA1)

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

        tree2 = MerkleTree.create_from_string_array(string, QQQ.USING_SHA1)

        ser2 = tree2.to_string(0)
        self.assertEqual(serialization, ser2)

        self.assertTrue(tree1.equal(tree2))

    def test_gray_boxes_bug3(self):
        serialization =\
            '088d0e391e1a4872329e0f7ac5d45b2025363e26c199a74ea39901d109afd6ba grayboxes.com/\n' +\
            ' 24652ddc14687866e6b1251589aee7e1e3079a87f80cd7775214f6d837612a90 images/\n' +\
            '  1eb774eef9be1e696f69a2f95711be37915aac283bb4b34dcbaf7d032233e090 grayboxes.gif\n' +\
            ' 6eacebda9fd55b59c0d2e48e2ed59ce9fd683379592f8e662b1de88e041f53c9 index.html\n'

        # create from string array ----------------------------------
        string = serialization.split('\n')
        string = string[:-1]
        self.assertEqual(4, len(string))

        tree2 = MerkleTree.create_from_string_array(string, QQQ.USING_SHA2)

        ser2 = tree2.to_string(0)
        self.assertEqual(serialization, ser2)

        # create from serialization ---------------------------------
        tree1 = MerkleTree.create_from_serialization(
            serialization, QQQ.USING_SHA2)

        ser1 = tree1.to_string(0)
        self.assertEqual(serialization, ser1)

        self.assertTrue(tree1.equal(tree2))            # GEEP

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
        with open('testData/dat2.xlattice.org', 'rb') as file:
            serialization = str(file.read(), 'utf-8')

        # create from serialization ---------------------------------
        tree1 = MerkleTree.create_from_serialization(
            serialization, QQQ.USING_SHA2)

        ser1 = tree1.to_string(0)
        self.assertEqual(serialization, ser1)

        # create from string array ----------------------------------
        string = serialization.split('\n')
        string = string[:-1]
        self.assertEqual(2511, len(string))

        tree2 = MerkleTree.create_from_string_array(string, QQQ.USING_SHA2)

        ser2 = tree2.to_string(0)
        self.assertEqual(serialization, ser2)

        self.assertTrue(tree1.equal(tree2))

if __name__ == '__main__':
    unittest.main()
