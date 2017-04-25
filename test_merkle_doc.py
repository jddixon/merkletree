#!/usr/bin/env python3
# testMerkleDoc.py

""" Test Merkletree functionality at the Document level. """

import hashlib
import os
import shutil
import time
import unittest

from rnglib import SimpleRNG
from merkletree import MerkleDoc, MerkleTree, MerkleLeaf
from xlattice import HashTypes, check_hashtype

ONE = 1
FOUR = 4
MAX_NAME_LEN = 8


class TestMerkleDoc(unittest.TestCase):
    """ Test Merkletree functionality at the Document level. """

    def setUp(self):
        self.rng = SimpleRNG(time.time())

    def tearDown(self):
        pass

    # utility functions #############################################
    def get_two_unique_directory_names(self):
        """ Generate two quasi-random directory names. """

        dir_name1 = self.rng.next_file_name(MAX_NAME_LEN)
        dir_name2 = dir_name1
        while dir_name2 == dir_name1:
            dir_name2 = self.rng.next_file_name(MAX_NAME_LEN)
        self.assertTrue(len(dir_name1) > 0)
        self.assertTrue(len(dir_name2) > 0)
        self.assertTrue(dir_name1 != dir_name2)
        return (dir_name1, dir_name2)

    def make_one_named_test_directory(self, name, depth, width):
        """
        Create a randomly named directory under tmp/, removing any
        existing directory of that name.
        """

        dir_path = "tmp/%s" % name
        if os.path.exists(dir_path):
            shutil.rmtree(dir_path)
        self.rng.next_data_dir(dir_path, depth, width, 32)
        return dir_path

    def make_two_test_directories(self, depth, width):
        """
        Generate two different names, using them to create subdirectories
        of tmp/.
        """
        dir_name1 = self.rng.next_file_name(MAX_NAME_LEN)
        dir_path1 = self.make_one_named_test_directory(dir_name1, depth, width)

        dir_name2 = dir_name1
        while dir_name2 == dir_name1:
            dir_name2 = self.rng.next_file_name(MAX_NAME_LEN)
        dir_path2 = self.make_one_named_test_directory(dir_name2, depth, width)

        return (dir_name1, dir_path1, dir_name2, dir_path2)

    def verify_leaf_sha(self, node, path_to_file, hashtype):
        """
        Verify that a MerkleLeaf correctly describes a file, given a hash type.i
        """
        check_hashtype(hashtype)
        self.assertTrue(os.path.exists(path_to_file))
        with open(path_to_file, "rb") as file:
            data = file.read()
        self.assertFalse(data is None)
        # pylint: disable=redefined-variable-type
        if hashtype == HashTypes.SHA1:
            sha = hashlib.sha1()
        elif hashtype == HashTypes.SHA2:
            sha = hashlib.sha256()
        elif hashtype == HashTypes.SHA3:
            # pylint: disable=no-member
            sha = hashlib.sha3_256()
        sha.update(data)
        hash_ = sha.digest()
        self.assertEqual(hash_, node.bin_hash)

    def verify_tree_sha(self, node, path_to_tree, hashtype):
        """
        Given a MerkleTree, verify that it correctly describes the
        directory whose path is passed.
        """
        # we assume that the node is a MerkleTree
        check_hashtype(hashtype)
        if node.nodes is None:
            self.assertEqual(None, node.bin_hash)
        else:
            hash_count = 0
            # pylint: disable=redefined-variable-type
            if hashtype == HashTypes.SHA1:
                sha = hashlib.sha1()
            elif hashtype == HashTypes.SHA2:
                sha = hashlib.sha256()
            elif hashtype == HashTypes.SHA3:
                # pylint: disable=no-member
                sha = hashlib.sha3_256()
            for node_ in node.nodes:
                path_to_node = os.path.join(path_to_tree, node_.name)
                if isinstance(node_, MerkleLeaf):
                    self.verify_leaf_sha(node_, path_to_node, hashtype)
                elif isinstance(node_, MerkleTree):
                    self.verify_tree_sha(node_, path_to_node, hashtype)
                else:
                    print("DEBUG: unknown node type!")
                    self.fail("unknown node type!")
                if node_.bin_hash is not None:
                    hash_count += 1
                    sha.update(node_.bin_hash)

            if hash_count == 0:
                self.assertEqual(None, node.bin_hash)
            else:
                self.assertEqual(sha.digest(), node.bin_hash)

    # actual unit tests #############################################

    def test_bound_flat_dirs(self):
        """test directory is single level, with four data files"""
        for hashtype in HashTypes:
            self.do_test_bound_flat_dirs(hashtype)

    def do_test_bound_flat_dirs(self, hashtype):
        """ Test two flat directories with the specified hash type. """

        (dir_name1, dir_path1, dir_name2, dir_path2) =\
            self.make_two_test_directories(ONE, FOUR)

        doc1 = MerkleDoc.create_from_file_system(dir_path1, hashtype)
        tree1 = doc1.tree
        self.assertTrue(isinstance(tree1, MerkleTree))
        # pylint: disable=no-member
        self.assertEqual(dir_name1, tree1.name)
        self.assertTrue(doc1.bound)
        self.assertEqual(("tmp/%s" % dir_name1), dir_path1)
        # pylint: disable=no-member
        nodes1 = tree1.nodes
        self.assertTrue(nodes1 is not None)
        self.assertEqual(FOUR, len(nodes1))
        self.verify_tree_sha(tree1, dir_path1, hashtype)

        doc2 = MerkleDoc.create_from_file_system(dir_path2, hashtype)
        tree2 = doc2.tree
        # pylint: disable=no-member
        self.assertEqual(dir_name2, tree2.name)
        self.assertTrue(doc2.bound)
        self.assertEqual(("tmp/%s" % dir_name2), dir_path2)
        # pylint: disable=no-member
        nodes2 = tree2.nodes
        self.assertTrue(nodes2 is not None)
        self.assertEqual(FOUR, len(nodes2))
        self.verify_tree_sha(tree2, dir_path2, hashtype)

        self.assertEqual(tree1, tree1)
        self.assertFalse(tree1 == tree2)
        self.assertFalse(tree1 is None)

        doc1_str = doc1.to_string()
        doc1_rebuilt = MerkleDoc.create_from_serialization(doc1_str, hashtype)
        # DEBUG
        #print("flat doc:\n" + doc1Str)
        #print("rebuilt flat doc:\n" + doc1Rebuilt.toString())
        # END
        self.assertTrue(doc1.equal(doc1_rebuilt))  # MANGO

    def test_bound_needle_dirs(self):
        """test directories four deep with one data file at the lowest level"""
        for hashtype in HashTypes:
            self.do_test_bound_needle_dirs(hashtype)

    def do_test_bound_needle_dirs(self, hashtype):
        """ Run tests on two deeper directories. """
        check_hashtype(hashtype)
        (dir_name1, dir_path1, dir_name2, dir_path2) =\
            self.make_two_test_directories(FOUR, ONE)
        doc1 = MerkleDoc.create_from_file_system(dir_path1, hashtype)
        tree1 = doc1.tree
        # pylint: disable=no-member
        self.assertEqual(dir_name1, tree1.name)
        self.assertTrue(doc1.bound)
        self.assertEqual(("tmp/%s" % dir_name1), dir_path1)
        # pylint: disable=no-member
        nodes1 = tree1.nodes
        self.assertTrue(nodes1 is not None)
        self.assertEqual(ONE, len(nodes1))
        self.verify_tree_sha(tree1, dir_path1, hashtype)

        doc2 = MerkleDoc.create_from_file_system(dir_path2, hashtype)
        tree2 = doc2.tree
        # pylint: disable=no-member
        self.assertEqual(dir_name2, tree2.name)
        self.assertTrue(doc2.bound)
        self.assertEqual(("tmp/%s" % dir_name2), dir_path2)
        # pylint: disable=no-member
        nodes2 = tree2.nodes
        self.assertTrue(nodes2 is not None)
        self.assertEqual(ONE, len(nodes2))
        self.verify_tree_sha(tree2, dir_path2, hashtype)

        self.assertTrue(doc1.equal(doc1))
        self.assertFalse(doc1.equal(doc2))

        doc1_str = doc1.to_string()
        doc1_rebuilt = MerkleDoc.create_from_serialization(doc1_str, hashtype)
#       # DEBUG
#       print "needle doc:\n" + doc1Str
#       print "rebuilt needle doc:\n" + doc1Rebuilt.toString()
#       # END
        self.assertTrue(doc1.equal(doc1_rebuilt))       # FOO


if __name__ == '__main__':
    unittest.main()
