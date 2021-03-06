# merkletree/__init__.py

"""
MerkleTree, a tree structure in which each component node as an SHA
hash associated with it.  If it is a leaf, this is the hash of its
contents.  If it is a tree or a document, it is the hash of the hashes
of its immediate children.
"""

import binascii
import os
import re
import sys
from stat import S_ISDIR

from xlattice import(SHA1_BIN_LEN, SHA1_BIN_NONE, SHA1_HEX_NONE,
                     SHA2_BIN_LEN, SHA2_BIN_NONE, SHA2_HEX_NONE,
                     SHA3_BIN_LEN, SHA3_BIN_NONE, SHA3_HEX_NONE,
                     BLAKE2B_256_BIN_LEN, BLAKE2B_256_BIN_NONE,
                     BLAKE2B_256_HEX_NONE,
                     HashTypes, check_hashtype)
from xlutil import make_ex_re, make_match_re
from xlcrypto import SP   # for getSpaces()
from xlcrypto.hash import XLSHA1, XLSHA2, XLSHA3, XLBLAKE2B_256
from xlu import(file_sha1bin, file_sha2bin, file_sha3bin, file_blake2b_256_bin)

__all__ = ['__version__', '__version_date__',
           # BELONGS IN xlattice_py:
           'get_hash_func',
           # classes
           'MerkleDoc', 'MerkleLeaf', 'MerkleTree', 'MerkleParseError', ]

__version__ = '5.4.0'
__version_date__ = '2018-07-26'

# -------------------------------------------------------------------


def get_hash_func(hashtype):
    """
    Given a HashType, return the appropriate library SHA hash function or
    None if there is no matching hash func.

    XXX THIS METHOD BELONGS IN xlcrypto_py
    """
    sha = None
    if hashtype == HashTypes.SHA1:
        sha = XLSHA1()
    elif hashtype == HashTypes.SHA2:
        sha = XLSHA2()
    elif hashtype == HashTypes.SHA3:
        sha = XLSHA3()
    elif hashtype == HashTypes.BLAKE2B_256:
        sha = XLBLAKE2B_256()
    else:
        raise NotImplementedError
    return sha


class MerkleParseError(RuntimeError):
    """ Class for MerkleTree/Doc parse errors. """
    pass


class MerkleNode(object):
    """
    Abstract class to which all Nodes in a MerkleDoc or MerkleTree
    belong.
    """

    # __slots__ = [ A PERFORMANCE ENHANCER ]

    def __init__(self, name, is_leaf=False, hashtype=HashTypes.SHA2):
        check_hashtype(hashtype)
        self._bin_hash = None
        if name is None:
            raise RuntimeError("MerkleNode: null MerkleNode name")
        self._name = name.strip()
        if not self._name:
            raise RuntimeError("MerkleNode: null or empty name")

        self._is_leaf = is_leaf
        self._hashtype = hashtype

    @property
    def hex_hash(self):
        """
        Return the hash associated with the MerkleNode as a hex value.
        """
        if self._bin_hash is None:
            if self._hashtype == HashTypes.SHA1:
                return SHA1_HEX_NONE
            elif self._hashtype == HashTypes.SHA2:
                return SHA2_HEX_NONE
            elif self._hashtype == HashTypes.SHA3:
                return SHA3_HEX_NONE
            elif self._hashtype == HashTypes.BLAKE2B_256:
                return BLAKE2B_256_HEX_NONE
            else:
                raise NotImplementedError
        else:
            return str(binascii.b2a_hex(self._bin_hash), 'ascii')

    @hex_hash.setter
    def hex_hash(self, value):
        """
        Set the hash associated with the MerkleNode as a hex value.
        """
        if self._bin_hash:
            raise RuntimeError('attempt to set non-null hash')
        self._bin_hash = bytes(binascii.a2b_hex(value))

#   def bind(self):             pass

    @property
    def bin_hash(self):
        """
        Return the hash associated with the MerkleNode as a binary value.
        """
        return self._bin_hash

    @bin_hash.setter
    def bin_hash(self, value):
        if self._bin_hash:
            raise RuntimeError('attempt to set non-null hash')
        self._bin_hash = value

#   def bound(self):
#       raise RuntimeError('not implemented')

    def __eq__(self, other):
        raise RuntimeError('subclass must implement')

    @property
    def is_leaf(self):
        """ Return whether this MerkleNode is a MerkleLeaf. """
        return self._is_leaf

    @property
    def name(self):
        """ Return the name associated with the MerkleNode. """
        return self._name

#   def path(self):
#       raise RuntimeError('not implemented')

    def __str__(self):
        raise RuntimeError('subclass must implement')

    def hashtype(self):
        """ Return the SHA hash type associated with the Node. """
        return self._hashtype

# -------------------------------------------------------------------


class MerkleDoc(MerkleNode):
    """
    The path to a tree, and the SHA hash of the path and the treehash.
    """

    __slots__ = ['_bound', '_ex_re', '_match_re', '_path',
                 '_tree', '_hashtype', ]

    # notice the terminating forward slash and lack of newlines or CR-LF
    # THIS PATTERN WON"T CATCH SOME ERRORS; eg it permits '///' in paths
    FIRST_LINE_RE_1 = re.compile(r'^([0-9a-f]{40}) ([a-z0-9_\-\./!:]+/)$',
                                 re.IGNORECASE)
    FIRST_LINE_RE_2 = re.compile(r'^([0-9a-f]{64}) ([a-z0-9_\-\./!:]+/)$',
                                 re.IGNORECASE)

    # XXX MUST ADD matchRE and exRE and test on their values at this level
    def __init__(self, path, hashtype=HashTypes.SHA2, binding=False,
                 tree=None,
                 ex_re=None,    # exclusions, which are Regular Expressions
                 match_re=None):   # matches, also Regular Expressions

        check_hashtype(hashtype)
        if path is None:
            raise RuntimeError("null MerkleDoc path")
        if tree:
            if not isinstance(tree, MerkleTree):
                raise RuntimeError('tree is not a MerkleTree')
            self._name = name = tree.name
        elif not binding:
            raise RuntimeError('null MerkleTree and not binding')
        else:
            raise RuntimeError("MerkleDoc binding not yet implemented")
        super().__init__(name, is_leaf=False, hashtype=hashtype)

        path = path.strip()
        if not path:
            raise RuntimeError("empty path")
        if not path.endswith('/'):
            path += '/'
        self._path = path
        self._tree = tree
        if tree:
            # DEBUG
            # print("MerkleDoc.__init__: usingSHA = %s" % str(usingSHA))
            # END
            sha = get_hash_func(hashtype)
            sha.update(bytes(tree.bin_hash))
            sha.update(path.encode('utf-8'))
            self._bin_hash = bytes(sha.digest())      # a binary value

        self._ex_re = ex_re
        self._match_re = match_re

        if binding:
            path_to_dir = os.path.join(path, tree.name)
            if not os.path.exists(path_to_dir):
                raise RuntimeError('no directory found at ' + path_to_dir)
            else:
                # XXX STUB: BIND THE TREE
                self._bound = True

    def __eq__(self, other):
        """ignore boundedness"""
        return isinstance(other, MerkleDoc) and \
            self._path == other.path and \
            self._bin_hash == other.bin_hash and \
            self._tree == other.tree

    @property
    def path(self):
        """
        Return the path (in the file system) associated with a MerkleDoc.
        """
        return self._path

    @path.setter
    def path(self, value):
        # XXX CHECK value
        """
        Set the path (in the file system) associated with a MerkleDoc.
        """
        self._path = value

    @property
    def tree(self):
        """ Return the MerkleTree associated with a MerkleDoc. """
        return self._tree

    @tree.setter
    def tree(self, value):
        # XXX CHECKS
        self._tree = value

    @property
    def bound(self):
        """ Whether a MerkleDoc is bound to a file. """
        return self._bound

    @bound.setter
    def bound(self, value):
        """ Set whether a MerkleDoc is bound to a file. """
        # XXX validate
        self._bound = value

    @property
    def hashtype(self):
        return self._hashtype

    # QUASI-CONSTRUCTORS ############################################
    @staticmethod
    def create_from_file_system(path_to_dir, hashtype=HashTypes.SHA2,
                                exclusions=None, matches=None):
        """
        Create a MerkleDoc based on the information in the directory
        at pathToDir.  The name of the directory will be the last component
        of pathToDir.  Return the MerkleTree.
        """
        check_hashtype(hashtype)
        if not path_to_dir:
            raise RuntimeError("cannot create a MerkleTree, no path set")
        if not os.path.exists(path_to_dir):
            raise RuntimeError(
                "MerkleTree: directory '%s' does not exist" % path_to_dir)
        path, _, _ = path_to_dir.rpartition('/')
        if path == '':
            raise RuntimeError("cannot parse inclusive path " + path_to_dir)
        path += '/'
        ex_re = None
        if exclusions:
            ex_re = make_ex_re(exclusions)
        match_re = None
        if matches:
            match_re = make_match_re(matches)
        tree = MerkleTree.create_from_file_system(path_to_dir, hashtype,
                                                  ex_re, match_re)
        # creates the hash
        doc = MerkleDoc(path, hashtype, False, tree, ex_re, match_re)
        doc.bound = True
        return doc

    @staticmethod
    def create_from_serialization(string, hashtype=HashTypes.SHA2):
        """
        Create a MerkleDoc from string serialization (such as a file).
        """
        check_hashtype(hashtype)
        if string is None:
            raise RuntimeError("MerkleDoc.createFromSerialization: no input")
        s_array = string.split('\n')                # note CR-LF
        return MerkleDoc.create_from_string_array(s_array, hashtype)

    @staticmethod
    def create_from_string_array(string, hashtype=HashTypes.SHA2):
        """
        The string array is expected to follow conventional indentation
        rules, with zero indentation on the first line and some number
        of leading spaces on all successive lines.
        """
        check_hashtype(hashtype)
        if string is None:
            raise RuntimeError('null argument')
        # XXX check TYPE - must be array of strings
        if not string:
            raise RuntimeError("empty string array")

        (doc_hash, doc_path) =\
            MerkleDoc.parse_first_line(string[0].rstrip())
        len_hash = len(doc_hash)
        if len_hash == SHA1_BIN_LEN:
            if hashtype != HashTypes.SHA1:
                raise RuntimeError("hash length %d inconsistent with %s" % (
                    len_hash, hashtype))
        elif len_hash != SHA2_BIN_LEN:
            raise RuntimeError("hash length %d inconsistent with %s" % (
                len_hash, hashtype))

        # DEBUG
        # print("MerkleDoc.createFromStringArray:")
        # print("    docHash = %s" % str(binascii.b2a_hex(docHash),'ascii'))
        # print("    docPath = %s" % docPath)
        # print("    usingSHA=%s" % str(usingSHA))
        # END

        tree = MerkleTree.create_from_string_array(string[1:], hashtype)

        # def __init__ (self, path, binding = False, tree = None,
        #    exRE    = None,    # exclusions, which are Regular Expressions
        #    matchRE = None):   # matches, also Regular Expressions
        doc = MerkleDoc(doc_path, hashtype=hashtype, tree=tree)
        return doc

    # CLASS METHODS #################################################
    @classmethod
    def first_line_re_1(cls):
        """
        Returns a reference to the regexp for SHA1 first lines.  A
        match finds (indent, treeHash, dirName), where indent is an
        integer, the treeHash is a hex string, and dirName may have a
        terminating slash.
        """
        return MerkleDoc.FIRST_LINE_RE_1

    @classmethod
    def first_line_re_2(cls):
        """
        Returns a reference to the regexp for SHA256 first lines.  A
        match finds (indent, treeHash, dirName), where indent is an
        integer, the treeHash is a hex string, and dirName may have a
        terminating slash.
        """
        return MerkleDoc.FIRST_LINE_RE_2

    @staticmethod
    def parse_first_line(line):
        """ returns binary docHash and string docPath"""
        line = line.rstrip()
        match_ = MerkleDoc.FIRST_LINE_RE_1.match(line)
        if match_ is None:
            match_ = MerkleDoc.FIRST_LINE_RE_2.match(line)
        if match_ is None:
            raise RuntimeError(
                "MerkleDoc first line <%s> does not match expected pattern" %
                line)
        doc_hash = bytes(binascii.a2b_hex(match_.group(1)))
        doc_path = match_.group(2)          # includes terminating slash
        return (doc_hash, doc_path)

    @staticmethod
    def make_ex_re(exclusions):
        """
        #############################################################
        THIS FUNCTION IS OBSOLETE AND SHOULD BE REPLACED WHEREVER USED
        WITH xlutil::makeExRE(), WHICH USES GLOBS.  This
        function uses regular expressions instead of globs.
        #############################################################

        Compile a regular expression which ORs exclusion patterns.
        """
        if exclusions is None:
            exclusions = []
        exclusions.append(r'^\.$')
        exclusions.append(r'^\.\.$')
        exclusions.append(r'^\.merkle$')
        exclusions.append(r'^\.svn$')            # subversion control data
        # some might disagree with these:
        exclusions.append(r'^junk')
        exclusions.append(r'^\..*\.swp$')        # vi editor files
        ex_pat = '|'.join(exclusions)
        return re.compile(ex_pat)

    @staticmethod
    def make_match_re(match_list):
        """
        #############################################################
        THIS FUNCTION IS OBSOLETE AND SHOULD BE REPLACED WHEREVER USED
        WITH xlutil::makeMatchRE(), WHICH USES GLOBS.  This
        function uses regular expressions instead of globs.
        #############################################################

        Compile a regular expression which ORs match patterns.
        """
        if match_list:
            match_pat = '|'.join(match_list)
            return re.compile(match_pat)
        return None

    # SERIALIZATION #################################################
    def __str__(self):
        return self.to_string()

    # XXX indent is not used
    def to_string(self, indent=0):
        """ Convert MerkleDoc to string form. """

        return ''.join([
            "%s %s\n" % (self.hex_hash, self.path),
            self._tree.to_string(indent)
        ])

# -------------------------------------------------------------------


class MerkleLeaf(MerkleNode):
    """ Leaf form of MerkleNode. """

    __slots__ = ['_name', '_hashtype', ]

    def __init__(self, name, hashtype=HashTypes.SHA1, hash_=None):
        super().__init__(name, is_leaf=True, hashtype=hashtype)

        # JUNK
        if name is None:
            raise RuntimeError("MerkleLeaf: null MerkleLeaf name")
        self._name = name.strip()
        if not self._name:
            raise RuntimeError("MerkleLeaf: null or empty name")
        # END JUNK

        # XXX VERIFY HASH IS WELL-FORMED
        if hash_:
            self._bin_hash = hash_
        else:
            self._bin_hash = None

    # IMPLEMENTATIONS OF ABSTRACT METHODS ###########################

    def __eq__(self, other):
        return isinstance(other, MerkleLeaf) and \
            self._name == other.name and \
            self._bin_hash == other.bin_hash

    def __str__(self):
        return self.to_string(0)        # that is, no indent

    # OTHER METHODS AND PROPERTIES ##################################

    @staticmethod
    def create_from_file_system(path_to_file, name, hashtype=HashTypes.SHA2):
        """
        Returns a MerkleLeaf.  The name is part of pathToFile, but is
        passed to simplify the code.
        """
        def report_io_error(exc):
            """ Report an I/O error to stdout. """
            print("error reading file %s: %s" % (
                path_to_file, exc), file=sys.stderr)

        if not os.path.exists(path_to_file):
            print(("INTERNAL ERROR: file does not exist: " + path_to_file))
        # XXX we convert from binary to hex and then right back to binary !!
        if hashtype == HashTypes.SHA1:
            try:
                hash_ = file_sha1bin(path_to_file)
            except OSError as exc:
                report_io_error(exc)
                hash_ = SHA1_BIN_NONE
        elif hashtype == HashTypes.SHA2:
            try:
                hash_ = file_sha2bin(path_to_file)
            except OSError as exc:
                report_io_error(exc)
                hash_ = SHA2_BIN_NONE
        elif hashtype == HashTypes.SHA3:
            try:
                hash_ = file_sha3bin(path_to_file)
            except OSError as exc:
                report_io_error(exc)
                hash_ = SHA3_BIN_NONE
        elif hashtype == HashTypes.BLAKE2B_256:
            try:
                hash_ = file_blake2b_256_bin(path_to_file)
            except OSError as exc:
                report_io_error(exc)
                hash_ = BLAKE2B_256_BIN_NONE
        else:
            raise NotImplementedError

        return MerkleLeaf(name, hashtype, hash_)

    def to_string(self, indent=0):
        """ Serialize MerkleLeaf as string . """
        if self._bin_hash is None:
            if self._hashtype == HashTypes.SHA1:
                hash_ = SHA1_HEX_NONE
            elif self._hashtype == HashTypes.SHA2:
                hash_ = SHA2_HEX_NONE
            elif self._hashtype == HashTypes.SHA3:
                hash_ = SHA3_HEX_NONE
            elif self._hashtype == HashTypes.BLAKE2B_256:
                hash_ = BLAKE2B_256_HEX_NONE
            else:
                raise NotImplementedError
        else:
            hash_ = self.hex_hash
        string = "%s%s %s\n" % (SP.get_spaces(indent), hash_, self.name)
        return string

    # THIS GETS REPLACED BY NLHTree XXX

    # PAIRLIST FUNCTIONS ############################################
    # def toPair(leaf):
    #     """
    #     Given a MerkleLeaf, return its name and binary hash as a pair
    #     """
    #     # DEBUG
    #     print("MerkleLeaf.toPair: %s %s" % (leaf.name, leaf.binHash))
    #     # END
    #     return (leaf.name, leaf.binHash)

    # @staticmethod
    # def createFromPair(p):
    #     """
    #     Given p, a name/hash pair, return a MerkleLeaf.
    #     """
    #     name = p[0];    hash = p[1]
    #     if len(hash) == SHA1_BIN_LEN:
    #         usingSHA = True
    #     elif len(hash) == SHA2_BIN_LEN:
    #         usingSHA = False
    #     else:
    #         raise RuntimeError('invalid SHA hash len')
    #     return MerkleLeaf(name, hash, usingSHA)

# -------------------------------------------------------------------


class MerkleTree(MerkleNode):
    """ Tree subclass of MerkleNode. """

    __slots__ = ['_bound', '_name', '_ex_re', '_bin_hash', '_match_re',
                 '_nodes', '_hashtype', ]

    # notice the terminating forward slash and lack of newlines or CR-LF
    FIRST_LINE_RE_1 = re.compile(
        r'^( *)([0-9a-f]{40}) ([a-z0-9_\-\.:]+/)$', re.IGNORECASE)
    OTHER_LINE_RE_1 = re.compile(
        r'^([ XYZ]*)([0-9a-f]{40}) ([a-z0-9_\$\+\-\.:~]+/?)$', re.IGNORECASE)
    FIRST_LINE_RE_2 = re.compile(
        r'^( *)([0-9a-f]{64}) ([a-z0-9_\-\.:]+/)$', re.IGNORECASE)
    OTHER_LINE_RE_2 = re.compile(
        r'^([ XYZ]*)([0-9a-f]{64}) ([a-z0-9_\$\+\-\.:_]+/?)$',
        re.IGNORECASE)

    #################################################################
    # exRE and matchRE must have been validated by the calling code
    #################################################################
    def __init__(self, name, hashtype=False,
                 ex_re=None,     # exclusions Regular Expression
                 match_re=None):    # matches Regular Expression

        super().__init__(name, is_leaf=False, hashtype=hashtype)

        self._ex_re = ex_re
        self._match_re = match_re
        self._nodes = []

    # IMPLEMENTATIONS OF ABSTRACT METHODS ###########################

    def __eq__(self, other):
        """
        This is quite wasteful.  Given the nature of the merkletree,
        it should only be necessary to compare top-level hashes.
        """
        if other is None:
            return False

        if (not isinstance(other, MerkleTree)) or \
                (self._name != other.name) or \
                self.hex_hash != other.hex_hash or \
                self.hashtype != other.hashtype:
            return False

        my_nodes = self.nodes
        other_nodes = other.nodes
        if len(my_nodes) != len(other_nodes):
            return False
        for ndx, my_node in enumerate(my_nodes):
            other_node = other_nodes[ndx]
            if not my_node.__eq__(other_node):    # RECURSES
                return False
        return True

    def __str__(self):
        return self.to_string(0)

    @property
    def hashtype(self):
        return self._hashtype

    #################################################################
    # METHODS LIFTED FROM bindmgr/bindlib/MerkleTree.py
    #################################################################
    @staticmethod
    def parse_first_line(line):
        """ returns indent, binary treeHash, and str dirName """
        line = line.rstrip()
        match_ = MerkleTree.FIRST_LINE_RE_1.match(line)
        if match_ is None:
            match_ = MerkleTree.FIRST_LINE_RE_2.match(line)
        if match_ is None:
            raise RuntimeError(
                "MerkleTree first line \"%s\" doesn't match expected pattern" %
                line)
        indent = len(match_.group(1))         # count of leading spaces
        tree_hash = bytes(binascii.a2b_hex(match_.group(2)))
        dir_name = match_.group(3)          # includes terminating slash
        dir_name = dir_name[0:len(dir_name) - 1]
        return (indent, tree_hash, dir_name)

    @staticmethod
    def parse_other_line(line):
        """ Parse a non-first line. """
        match_ = re.match(MerkleTree.OTHER_LINE_RE_1, line)
        if match_ is None:
            match_ = re.match(MerkleTree.OTHER_LINE_RE_2, line)
        if match_ is None:
            raise RuntimeError(
                "MerkleTree other line <%s> does not match expected pattern" %
                line)
        node_depth = len(match_.group(1))
        node_hash = bytes(binascii.a2b_hex(match_.group(2)))
        node_name = match_.group(3)
        if node_name.endswith('/'):
            node_name = node_name[0:len(node_name) - 1]
            is_dir = True
        else:
            is_dir = False
        return (node_depth, node_hash, node_name, is_dir)

    @staticmethod
    def create_from_string_array(strings, hashtype=HashTypes.SHA2):
        """
        The strings array is expected to follow conventional indentation
        rules, with zero indentation on the first line and some number
        of leading spaces on all successive lines.
        """

        # XXX should check TYPE - must be array of strings
        if not strings:
            raise RuntimeError("empty strings array")
        (indent, tree_hash, dir_name) =\
            MerkleTree.parse_first_line(strings[0].rstrip())
        len_hash = len(tree_hash)
        if len_hash == SHA1_BIN_LEN:
            if hashtype != HashTypes.SHA1:
                raise RuntimeError("hash length %d inconsistent with %s" % (
                    len_hash, hashtype))
        elif len_hash != SHA2_BIN_LEN:
            raise RuntimeError("hash length %d inconsistent with %s" % (
                len_hash, hashtype))

        root_tree = MerkleTree(dir_name, hashtype)    # an empty tree
        root_tree.bin_hash = tree_hash

        if indent != 0:
            print(("INTERNAL ERROR: initial line indent %d" % indent))

        stack = []
        stk_depth = 0
        cur_tree = root_tree
        stack.append(cur_tree)           # rootTree
        stk_depth += 1                  # always step after pushing tree

        for ndx in range(1, len(strings)):
            line = strings[ndx].rstrip()
            if not line:
                continue
            # XXX SHOULD/COULD CHECK THAT HASHES ARE OF THE RIGHT TYPE
            line_indent, hash_, name, is_dir = MerkleTree.parse_other_line(
                line)
            if line_indent < stk_depth:
                while line_indent < stk_depth:
                    stk_depth -= 1
                    stack.pop()
                cur_tree = stack[-1]
                if not stk_depth == line_indent:
                    print("ERROR: stkDepth != lineIndent")

            if is_dir:
                # create and set attributes of new node
                new_tree = MerkleTree(name, hashtype)  # , curTree)
                new_tree.bin_hash = hash_
                # add the new node into the existing tree
                cur_tree.add_node(new_tree)
                stack.append(new_tree)
                stk_depth += 1
                cur_tree = new_tree
            else:
                # create and set attributes of new node
                new_node = MerkleLeaf(name, hashtype, hash_)
                # add the new node into the existing tree
                cur_tree.add_node(new_node)
        return root_tree

    @staticmethod
    def create_from_serialization(string, hashtype=HashTypes.SHA2):
        """
        Create a MerkleTree by parsing its serialization (a single string),
        given the SHA hash type used to create the MerkleTree.
        """
        if string is None:
            raise RuntimeError("MerkleTree.createFromSerialization: no input")
        if not isinstance(string, str):
            string = str(string, 'utf-8')
        s_array = string.split('\n')                # note CR-LF
        return MerkleTree.create_from_string_array(s_array, hashtype)

    @staticmethod
    def create_from_file(path_to_file, hashtype=HashTypes.SHA2):
        """
        Create a MerkleTree by parsing its on-disk serialization,
        given the SHA hash type used to create the MerkleTree.
        """
        if not os.path.exists(path_to_file):
            raise RuntimeError(
                "MerkleTree.createFromFile: file '%s' does not exist" %
                path_to_file)
        with open(path_to_file, 'r') as file:
            text = file.read()
        return MerkleTree.create_from_serialization(text, hashtype)

    @staticmethod
    def create_from_file_system(path_to_dir, hashtype=HashTypes.SHA2,
                                ex_re=None, match_re=None):
        """
        Create a MerkleTree based on the information in the directory
        at pathToDir.  The name of the directory will be the last component
        of pathToDir.  Return the MerkleTree.
        """
        check_hashtype(hashtype)
        if not path_to_dir:
            raise RuntimeError("cannot create a MerkleTree, no path set")
        if not os.path.exists(path_to_dir):
            raise RuntimeError(
                "MerkleTree: directory '%s' does not exist" % path_to_dir)
        (path, _, name) = path_to_dir.rpartition('/')
        if not path:
            raise RuntimeError("can't parse inclusive path '%s'" % path_to_dir)

        tree = MerkleTree(name, hashtype, ex_re, match_re)
        tree.bin_hash = None
        sha = get_hash_func(hashtype)

        # Create data structures for constituent files and subdirectories
        # These MUST BE SORTED by the bare name to meet specs.
        files = sorted(os.listdir(path_to_dir))
        if files:
            sha_count = 0
            for file in files:
                # exclusions take priority over matches
                if ex_re and ex_re.search(file):
                    continue
                if match_re and not match_re.search(file):
                    continue
                node = None
                path_to_file = os.path.join(path_to_dir, file)
                string = os.lstat(path_to_file)        # ignores symlinks
                # os.path.isdir(path) follows symbolic links
                if S_ISDIR(string.st_mode):
                    node = MerkleTree.create_from_file_system(
                        path_to_file, hashtype, ex_re, match_re)
                # S_ISLNK(mode) is true if symbolic link
                # isfile(path) follows symbolic links
                elif os.path.isfile(path_to_file):        # S_ISREG(mode):
                    node = MerkleLeaf.create_from_file_system(
                        path_to_file, file, hashtype)
                # otherwise, just ignore it ;-)

                if node:
                    # update tree-level hash
                    if node.bin_hash:
                        # note empty file has null hash  XXX NOT TRUE
                        sha_count += 1
                        sha.update(node.bin_hash)
                    # SKIP NEXT TO EASE GARBAGE COLLECTION ??? XXX
                    # but that won't be a good idea if we are
                    # invoking toString()
                    tree.nodes.append(node)
            if sha_count:
                tree.bin_hash = bytes(sha.digest())

        return tree

    # OTHER METHODS AND PROPERTIES ##################################
    @classmethod
    def first_line_re_1(cls):
        """
        Returns a reference to the regexp for SHA1 first lines.  A
        match finds (indent, treeHash, dirName), where indent is an
        integer, the treeHash is a hex string, and dirName may have a
        terminating slash.
        """
        return MerkleTree.FIRST_LINE_RE_1

    @classmethod
    def first_line_re_2(cls):
        """
        Returns a reference to the regexp for SHA3 first lines.  A
        match finds (indent, treeHash, dirName), where indent is an
        integer, the treeHash is a hex string, and dirName may have a
        terminating slash.
        """
        return MerkleTree.FIRST_LINE_RE_2

    @property
    def nodes(self):
        """
        DANGEROUS: returns a reference to the MerkleTree's node list.
        """
        return self._nodes

    def add_node(self, node):
        """ Add a MerkleNode to a MerkleTree. """
        if node is None:
            raise RuntimeError("attempt to add null node")
        if not isinstance(node, MerkleTree)\
                and not isinstance(node, MerkleLeaf):
            raise RuntimeError("node being added not MerkleTree or MerkleLeaf")
        self._nodes.append(node)

    # SERIALIZATION #################################################
    def to_string_not_top(self, indent=0):
        """ indent is the indentation to be used for the top node"""
        string = []                             # a list of strings
        spaces = SP.get_spaces(indent)
        if self._bin_hash is None:
            if self._hashtype == HashTypes.SHA1:
                top = "%s%s %s/\n" % (spaces, SHA1_HEX_NONE, self.name)
            elif self._hashtype == HashTypes.SHA2:
                top = "%s%s %s/\n" % (spaces, SHA2_HEX_NONE, self.name)
            elif self._hashtype == HashTypes.SHA3:
                top = "%s%s %s/\n" % (spaces, SHA3_HEX_NONE, self.name)
            elif self._hashtype == HashTypes.BLAKE2B_256:
                top = "%s%s %s/\n" % (spaces, BLAKE2B_256_HEX_NONE, self.name)
            else:
                raise NotImplementedError
        else:
            top = "%s%s %s/\n" % (spaces, self.hex_hash, self.name)
        string.append(top)
        indent += 1              # <--- LEVEL 2+ NODE
        for node in self.nodes:
            if isinstance(node, MerkleLeaf):
                string.append(node.to_string(indent))
            else:
                # recurse
                string.append(node.to_string_not_top(indent))

        return ''.join(string)

    def to_string(self, indent=0):
        """
        indent is the initial indentation of the serialized list, NOT the
        extra indentation added at each recursion.
        Using code should take into account that the last line is CR-LF
        terminated, and so a split on CRLF will generate an extra blank line
        """
        string = []                             # a list of strings
        spaces = SP.get_spaces(indent)
        if self._bin_hash is None:
            if self._hashtype == HashTypes.SHA1:
                top = "%s%s %s/\n" % (spaces, SHA1_HEX_NONE, self.name)
            elif self._hashtype == HashTypes.SHA2:
                top = "%s%s %s/\n" % (spaces, SHA2_HEX_NONE, self.name)
            elif self._hashtype == HashTypes.SHA3:
                top = "%s%s %s/\n" % (spaces, SHA3_HEX_NONE, self.name)
            elif self._hashtype == HashTypes.BLAKE2B_256:
                top = "%s%s %s/\n" % (spaces, BLAKE2B_256_HEX_NONE, self.name)
            else:
                raise NotImplementedError
        else:
            top = "%s%s %s/\n" % (spaces, self.hex_hash, self.name)
        string.append(top)                       # <--- LEVEL 0 NODE
        my_indent = indent + 1               # <--- LEVEL 1 NODE
        for node in self.nodes:
            if isinstance(node, MerkleLeaf):
                string.append(node.to_string(my_indent))
            else:
                # recurse
                string.append(node.to_string_not_top(my_indent))

        return ''.join(string)
