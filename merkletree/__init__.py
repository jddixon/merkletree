# merkletree/__init__.py

import binascii, hashlib, os, re, sys
from stat import *

__all__ = [ '__version__',      '__version_date__', 
            'SHA1_NONE',        'SHA2_NONE', 
            # classes
            'MerkleDoc', 'MerkleLeaf', 'MerkleTree', 'MerkleParseError',
          ]

__version__      = '4.0.3'
__version_date__ = '2015-05-12'

#            ....x....1....x....2....x....3....x....4....x....5....x....6....
SHA1_NONE = '0000000000000000000000000000000000000000'
SHA2_NONE = '0000000000000000000000000000000000000000000000000000000000000000'

# -------------------------------------------------------------------
class MerkleParseError(RuntimeError):
    pass

class MerkleNode(object):
   
    #__slots__ = [ A PERFORMANCE ENHANCER ]

    def __init__(self, name, isLeaf=False, usingSHA1=False):
        self._hash = None
        if name == None:
            raise RuntimeError("MerkleNode: null MerkleNode name")
        self._name = name.strip()
        if len(self._name) == 0:
            raise RuntimeError("MerkleNode: null or empty name")
        self._name = name

        self._isLeaf = isLeaf
        self._usingSHA1 = usingSHA1

    @property
    def asciiHash(self):
        if self._hash == None:
            if self._usingSHA1:
                return SHA1_NONE;
            else:
                return SHA2_NONE;
        else:
            return str(binascii.b2a_hex(self._hash), 'ascii');
    @asciiHash.setter
    def asciiHash(self, value):
        if self._hash:
            raise RuntimeError('attempt to set non-null hash')
        self._hash = binascii.a2b_hex(value)
        # DEBUG
        #print("asciiHash setting %s\n" % value)
        # END

#   def bind(self):             pass

    @property
    def binHash(self):
        return self._hash
    @binHash.setter
    def binHash(self, value):
        if self._hash:
            raise RuntimeError('attempt to set non-null hash')
        self._hash = value
        # DEBUG
        #print("binHash setting %s\n" % self.asciiHash)
        # END


#   def bound(self):            
#       raise RuntimeError('not implemented')

    def equal(self, other):    
        raise RuntimeError('subclass must implement')

    @property
    def isLeaf(self):           return self._isLeaf

    @property
    def name(self):             return self._name

#   def path(self):             
#       raise RuntimeError('not implemented')

    def __str__(self):
        raise RuntimeError('subclass must implement')

    def usingSHA1(self):        return self._usingSHA1

# -------------------------------------------------------------------
class MerkleDoc(MerkleNode):
    """
    The path to a tree, and the SHA hash of the path and the treehash.
    """

    __slots__ = ['_bound', '_exRE', '_hash', '_matchRE', '_path', '_tree', '_usingSHA1', ]

    # notice the terminating forward slash and lack of newlines or CR-LF
    # THIS PATTERN WON"T CATCH SOME ERRORS; eg it permits '///' in paths
    FIRST_LINE_RE_1 = re.compile(r'^([0-9a-f]{40}) ([a-z0-9_\-\./!:]+/)$',
                                re.IGNORECASE)
    FIRST_LINE_RE_2 = re.compile(r'^([0-9a-f]{64}) ([a-z0-9_\-\./!:]+/)$',
                                re.IGNORECASE)

    # XXX MUST ADD matchRE and exRE and test on their values at this level
    def __init__ (self, path, usingSHA1 = False, binding = False, 
                        tree = None,
            exRE    = None,    # exclusions, which are Regular Expressions
            matchRE = None):   # matches, also Regular Expressions

        if path == None:
            raise RunTimeError("null MerkleDoc path")
        if tree:
            if not isinstance(tree, MerkleTree):
                raise RuntimeError('tree is not a MerkleTree')
            self._name = name = tree.name
        elif not binding:
            raise RuntimeError('null MerkleTree and not binding')
        else:
            raise RuntimeError("MerkleDoc binding not yet implemented")
        super().__init__(name, isLeaf=False, usingSHA1=usingSHA1)

        path = path.strip()
        if len(path) == 0:
            raise RuntimeError("empty path")
        if not path.endswith('/'):
            path += '/'
        self._path      = path
        self._tree      = tree
        if tree:
            # DEBUG
            #print("MerkleDoc.__init__: usingSHA1 = %s" % str(usingSHA1))
            # END
            if usingSHA1:
                sha1 = hashlib.sha1()
                sha1.update(tree.binHash)
                sha1.update(path.encode('utf-8'))
                self.binHash = sha1.digest()      # a binary value
            else:
                sha256 = hashlib.sha256()
                sha256.update(tree.binHash)
                sha256.update(path.encode('utf-8'))
                self.binHash = sha256.digest()    # that binary value

        self._exRE    = exRE
        self._matchRE = matchRE

        if (binding):
            pathToDir = os.path.join(path, tree.name)
            if not os.path.exists(pathToDir):
                raise RuntimeError('no directory found at ' + pathToDir)
            else:
                # XXX STUB: BIND THE TREE
                self._bound = True

    def equal(self, other):
        """ignore boundedness"""
        if isinstance(other, MerkleDoc)         and \
                self._path   == other._path     and \
                self._hash   == other._hash     and \
                self._tree.equal(other._tree)  :
            return True
        else:
            return False

    @property
    def path(self):
        """should return doc's path"""
        return self._path
    @path.setter
    def path(self, value):
        # XXX CHECK value
        self._path = value

    @property
    def tree(self):
        return self._tree
    @tree.setter
    def tree(self, value):
        # XXX CHECKS
        self._tree = value

    @property
    def bound(self):
        return self._bound

    @property
    def usingSHA1(self):
        return self._usingSHA1

    # QUASI-CONSTRUCTORS ############################################
    @staticmethod
    def createFromFileSystem(pathToDir, usingSHA1 = False, deltaIndent=' ',
                             exclusions = None, matches = None):
        """
        Create a MerkleDoc based on the information in the directory
        at pathToDir.  The name of the directory will be the last component
        of pathToDir.  Return the MerkleTree.
        """
        if not pathToDir:
            raise RuntimeError("cannot create a MerkleTree, no path set")
        if not os.path.exists(pathToDir):
            raise RuntimeError(
                "MerkleTree: directory '%s' does not exist" % pathToDir)
        (path, delim, name) = pathToDir.rpartition('/')
        if path == '':
            raise RuntimeError("cannot parse inclusive path " + pathToDir)
        path += '/'
        exRE = None
        if exclusions:
            exRE    = MerkleDoc.makeExRE(exclusions)
        matchRE = None
        if matches:
            matchRE = MerkleDoc.makeMatchRE(matches)
        tree = MerkleTree.createFromFileSystem(pathToDir, usingSHA1,
                                    deltaIndent, exRE, matchRE)
        # creates the hash
        doc  = MerkleDoc(path, usingSHA1, False, tree, exRE, matchRE)  
        doc._bound = True
        return doc

    @staticmethod
    def createFromSerialization(s, deltaIndent=' '):
        if s == None:
            raise RuntimeError ("MerkleDoc.createFromSerialization: no input")
        sArray = s.split('\r\n')                # note CR-LF
        return MerkleDoc.createFromStringArray(sArray, deltaIndent)

    @staticmethod
    def createFromStringArray(s, deltaIndent=' '):
        """
        The string array is expected to follow conventional indentation
        rules, with zero indentation on the first line and some multiple
        of deltaIndent spaces on all successive lines.
        """
        if s == None:
            raise RuntimeError('null argument')
        # XXX check TYPE - must be array of strings
        if len(s) == 0:
            raise RuntimeError("empty string array")

        (docHash, docPath) = \
                            MerkleDoc.parseFirstLine(s[0].rstrip())
        lenHash   = len(docHash)
        if lenHash == 20:           # 20 because it's binary, not ascii
            usingSHA1   = True
        elif lenHash == 32:
            usingSHA1 = False
        else:
            raise MerkleParseError('impossible hash length %d' % lenHash)

        # DEBUG
        #print("MerkleDoc.createFromStringArray:")
        #print("    docHash = %s" % str(binascii.b2a_hex(docHash),'ascii'))
        #print("    docPath = %s" % docPath)
        #print("    usingSHA1=%s" % str(usingSHA1))
        # END

        tree = MerkleTree.createFromStringArray( s[1:] , deltaIndent)

        #def __init__ (self, path, binding = False, tree = None,
        #    exRE    = None,    # exclusions, which are Regular Expressions
        #    matchRE = None):   # matches, also Regular Expressions
        doc = MerkleDoc( docPath, usingSHA1=usingSHA1, tree=tree )
        return doc

    # CLASS METHODS #################################################
    @classmethod
    def firstLineRE_1(cls):
        """ 
        Returns a reference to the regexp for SHA1 first lines.  A
        match finds (indent, treeHash, dirName), where indent is an
        integer, the treeHash is a hex string, and dirName may have a
        terminating slash.
        """
        return MerkleDoc.FIRST_LINE_RE_1

    @classmethod
    def firstLineRE_2(cls):
        """ 
        Returns a reference to the regexp for SHA256 first lines.  A
        match finds (indent, treeHash, dirName), where indent is an
        integer, the treeHash is a hex string, and dirName may have a
        terminating slash.
        """
        return MerkleDoc.FIRST_LINE_RE_2

    @staticmethod
    def parseFirstLine(line):
        """ returns binary docHash and string docPath"""
        line = line.rstrip()
        m = MerkleDoc.FIRST_LINE_RE_1.match(line)
        if m == None:
            m = MerkleDoc.FIRST_LINE_RE_2.match(line)
        if m == None:
            raise RuntimeError(
                    "MerkleDoc first line <%s> does not match expected pattern" %  line)
        docHash  = binascii.a2b_hex(m.group(1))
        docPath  = m.group(2)          # includes terminating slash
        return (docHash, docPath)

    @staticmethod
    def makeExRE(exclusions):
        """compile a regular expression which ORs exclusion patterns"""
        if exclusions == None:
            exclusions = []
        exclusions.append('^\.$')
        exclusions.append('^\.\.$')
        exclusions.append('^\.merkle$')
        exclusions.append('^\.svn$')            # subversion control data
        # some might disagree with these:
        exclusions.append('^junk')
        exclusions.append('^\..*\.swp$')        # vi editor files
        exPat = '|'.join(exclusions)
        return re.compile(exPat)

    @staticmethod
    def makeMatchRE(matchList):
        """compile a regular expression which ORs match patterns"""
        if matchList and len(matchList) > 0:
            matchPat = '|'.join(matchList)
            return re.compile(matchPat)
        else:
            return None

    # SERIALIZATION #################################################
    def __str__(self):
        return self.toString()

    def toString(self, indent='', deltaIndent=' '):
        return ''.join([
            "%s %s\r\n" % ( self.asciiHash, self.path),
            self._tree.toString('')
            ])

# -------------------------------------------------------------------
class MerkleLeaf(MerkleNode):

    __slots__ = ['_name', '_hash', '_usingSHA1', ]

    def __init__ (self, name, usingSHA1 = False, hash = None):
        super().__init__(name, isLeaf=True, usingSHA1=usingSHA1)

        # JUNK
        if name == None:
            raise RuntimeError("MerkleLeaf: null MerkleLeaf name")
        self._name = name.strip()
        if len(self._name) == 0:
            raise RuntimeError("MerkleLeaf: null or empty name")
        # END JUNK

        # XXX VERIFY HASH IS WELL-FORMED
        if hash:
            self.binHash = hash
        else:
            self.binHash = None

    # IMPLEMENTATIONS OF ABSTRACT METHODS ###########################

    def equal(self, other):
        if isinstance(other, MerkleLeaf)            and \
                self._name    == other._name        and \
                self.binHash  == other.binHash:
            return True
        else:
            return False

    def __str__(self):
        return self.toString('')        # that is, no indent

    # OTHER METHODS AND PROPERTIES ##################################
    @staticmethod
    def sha1File(pathToFile):
        """XXX no checks on file existence, etc"""
        with open(pathToFile, "rb") as f:
            # XXX should use buffer
            data = f.read()
        if data == None:
            return None
        sha1 = hashlib.sha1()
        sha1.update(data)
        d    = sha1.digest()        # a binary number
        return d

    @staticmethod
    def sha256File(pathToFile):
        """XXX no checks on file existence, etc"""
        with open(pathToFile, "rb") as f:
            # XXX should use buffer
            data = f.read()
        if data == None:
            return None
        # sha256 = sha256.SHA3256()
        sha256 = hashlib.sha256()
        sha256.update(data)
        return sha256.digest()            # a binary number

    @staticmethod
    def createFromFileSystem(pathToFile, name, 
                        usingSHA1 = False, deltaIndent=' '):
        """
        Returns a MerkleLeaf.  The name is part of pathToFile, but is
        passed to simplify the code.
        """
        if not os.path.exists(pathToFile):
            print(("INTERNAL ERROR: file does not exist: " + pathToFile))
        # XXX we convert from binary to hex and then right back to binary !!
        if usingSHA1:
            hash = MerkleLeaf.sha1File(pathToFile)
        else:
            hash = MerkleLeaf.sha256File(pathToFile)
        return MerkleLeaf(name, usingSHA1, hash)

    def toString(self, indent='', deltaIndent=' '):
        if self._hash == None:
            if self._usingSHA1:     h = SHA1_NONE
            else:                   h = SHA2_NONE
        else:
            h = self.asciiHash
        s = "%s%s %s\r\n" % (indent, h, self.name)
        return s

# -------------------------------------------------------------------
class MerkleTree(MerkleNode):

    __slots__ = ['_bound', '_name', '_exRE', '_hash', '_matchRE', '_nodes', '_usingSHA1', ]

    # notice the terminating forward slash and lack of newlines or CR-LF
    FIRST_LINE_RE_1 = re.compile(r'^( *)([0-9a-f]{40}) ([a-z0-9_\-\.]+/)$',
                                re.IGNORECASE)
    OTHER_LINE_RE_1 = re.compile(r'^([ XYZ]*)([0-9a-f]{40}) ([a-z0-9_\$\+\-\.~]+/?)$',
                                re.IGNORECASE)
    FIRST_LINE_RE_2 = re.compile(r'^( *)([0-9a-f]{64}) ([a-z0-9_\-\.]+/)$',
                                re.IGNORECASE)
    OTHER_LINE_RE_2 = re.compile(r'^([ XYZ]*)([0-9a-f]{64}) ([a-z0-9_\$\+\-\._]+/?)$',
                                re.IGNORECASE)
    

    #################################################################
    # exRE and matchRE must have been validated by the calling code
    #################################################################
    def __init__ (self, name, usingSHA1 = False,
            exRE    = None,     # exclusions Regular Expression
            matchRE = None):    # matches Regular Expression

        super().__init__(name, isLeaf=False, usingSHA1=usingSHA1)

        self._exRE      = exRE
        self._matchRE   = matchRE
        self._nodes     = []

    # IMPLEMENTATIONS OF ABSTRACT METHODS ###########################

    def equal(self, other):
        """
        This is quite wasteful.  Given the nature of the merkletree, 
        it should only be necessary to compare top-level hashes.
        """
        if other == None:
            return False
        if self == other:
            return True

        if (not isinstance(other, MerkleTree)) or \
           (self._name != other._name ):
            return False
        if self.asciiHash != other.asciiHash:
            return False
        if self.usingSHA1 != other.usingSHA1:
            return False

        myNodes    = self.nodes
        otherNodes = other.nodes
        if len(myNodes) != len(otherNodes):
            return False
        for i in range(len(myNodes)):
            myNode    = myNodes[i]
            otherNode = otherNodes[i]
            if not myNode.equal(otherNode):    # RECURSES
                return False
        return True

    def __str__(self):
        return self.toString('')

    @property
    def usingSHA1(self):    return self._usingSHA1

    #################################################################
    # METHODS LIFTED FROM bindmgr/bindlib/MerkleTree.py
    #################################################################
    @staticmethod
    def parseFirstLine(line):
        """ returns indent, binary treeHash, and str dirName """
        line = line.rstrip()
        m = MerkleTree.FIRST_LINE_RE_1.match(line)
        if m == None:
            m = MerkleTree.FIRST_LINE_RE_2.match(line)
        if m == None:
            raise RuntimeError(
                    "MerkleTree first line \"%s\" does not match expected pattern" %  line)
        indent    = len(m.group(1))         # count of leading spaces
        treeHash  = binascii.a2b_hex(m.group(2))
        dirName   = m.group(3)          # includes terminating slash
        dirName   = dirName[0:len(dirName) - 1]
        return (indent, treeHash, dirName)

    @staticmethod
    def parseOtherLine(line, deltaIndent):
        m = re.match(MerkleTree.OTHER_LINE_RE_1, line)
        if m == None:
            m = re.match(MerkleTree.OTHER_LINE_RE_2, line)
        if m == None:
            raise RuntimeError(
                    "MerkleTree other line <%s> does not match expected pattern" %  line)
        nodeDepth = len(m.group(1))/len(deltaIndent)    # XXX
        nodeHash  = binascii.a2b_hex(m.group(2))
        nodeName  = m.group(3)
        if nodeName.endswith('/'):
            nodeName = nodeName[0:len(nodeName) - 1]
            isDir = True
        else:
            isDir = False
        return (nodeDepth, nodeHash, nodeName, isDir)

    @staticmethod
    def createFromStringArray(s, deltaIndent=' '):
        """
        The string array is expected to follow conventional indentation
        rules, with zero indentation on the first line and some multiple
        of deltaIndent spaces on all successive lines.
        """
        if s == None:
            raise RuntimeError('null argument')

        # XXX should check TYPE - must be array of strings

        if len(s) == 0:
            raise RuntimeError("empty string array")
        (indent, treeHash, dirName) = \
                            MerkleTree.parseFirstLine(s[0].rstrip())
        lenHash = len(treeHash)
        if lenHash == 20:           # that many bytes
            usingSHA1 = True
        elif lenHash == 32:
            usingSHA1 = False
        else:
            raise MerkleParseError("impossible hash length %d" % lenHash)

        rootTree    = MerkleTree(dirName, usingSHA1)    # an empty tree
        rootTree.binHash = treeHash

        if indent != 0:
            print(("INTERNAL ERROR: initial line indent %d" % indent))

        stack      = []
        stkDepth   = 0
        curTree    = rootTree
        stack.append(curTree)           # rootTree
        stkDepth  += 1                  # always step after pushing tree
        lastWasDir = False

        # REMEMBER THAT PYTHON HANDLES LARGE RANGES BADLY
        for n in range(1, len(s)):
            line = s[n].rstrip()
            if len(line) == 0:
                n += 1
                continue
            # XXX SHOULD/COULD CHECK THAT HASHES ARE OF THE RIGHT TYPE
            (lineIndent, hash, name, isDir) = MerkleTree.parseOtherLine(line, deltaIndent)
            if lineIndent < stkDepth:
                while lineIndent < stkDepth:
                    stkDepth -= 1
                    stack.pop()
                curTree = stack[-1]
                if not stkDepth == lineIndent:
                    print("ERROR: stkDepth != lineIndent")

            if isDir:
                # create and set attributes of new node
                newTree = MerkleTree(name, usingSHA1)  # , curTree)
                newTree.binHash = hash
                # add the new node into the existing tree
                curTree.addNode(newTree)
                stack.append(newTree)
                stkDepth += 1
                curTree   = newTree
            else:
                # create and set attributes of new node
                newNode = MerkleLeaf(name, usingSHA1, hash)
                # add the new node into the existing tree
                curTree.addNode(newNode)
            n += 1
        return rootTree         # BAR

    @staticmethod
    def createFromSerialization(s, deltaIndent=' '):
        """ 
        """
        if s == None:
            raise RuntimeError ("MerkleTree.createFromSerialization: no input")
        if type(s) is not str:
            s = str(s, 'utf-8')
        sArray = s.split('\r\n')                # note CR-LF
        return MerkleTree.createFromStringArray(sArray, deltaIndent)

    @staticmethod
    def createFromFile(pathToFile, deltaIndent=' '):
        if not os.path.exists(pathToFile):
            raise RuntimeError(
                "MerkleTree.createFromFile: file '%s' does not exist" % pathToFile)
        with open(pathToFile, 'r') as f:
            line = f.readline()     # , 'utf-8')
            line = line.rstrip()
            m = MerkleTree.FIRST_LINE_RE_1.match(line)
            if m == None:
                m = MerkleTree.FIRST_LINE_RE_2.match(line)
                usingSHA1 = False
            else:
                usingSHA1 = True
            if m == None:
                raise RuntimeError(
                        "line '%s' does not match expected pattern" %  line)
            dirName = m.group(3)
            tree = MerkleTree(dirName, usingSHA1)
#           if m.group(3) != 'bind':
#               raise RuntimeError(
#                       "expected 'bind' in first line, found %s" % m.group(3))
            tree.binHash = m.group(2)
            line = f.readline()     # , 'utf-8')
            while line:
                line = line.rstrip()
                if line == '':
                    continue
                if usingSHA1:
                    m = re.match(MerkleTree.OTHER_LINE_RE_1, line)
                else:
                    m = re.match(MerkleTree.OTHER_LINE_RE_2, line)
                    
                if m == None:
                    raise RuntimeError(
                            "line '%s' does not match expected pattern" %  line)
                # 2014-06-24 next line as found:
                tree._add(m.group(3), m.group(2))
                line = f.readline()     # , 'utf-8')

        return tree

    @staticmethod
    def createFromFileSystem(pathToDir, usingSHA1 = False, deltaIndent=' ',
                                        exRE = None, matchRE = None):
        """
        Create a MerkleTree based on the information in the directory
        at pathToDir.  The name of the directory will be the last component
        of pathToDir.  Return the MerkleTree.
        """
        if not pathToDir:
            raise RuntimeError("cannot create a MerkleTree, no path set")
        if not os.path.exists(pathToDir):
            raise RuntimeError(
                "MerkleTree: directory '%s' does not exist" % pathToDir)
        (path, junk, name) = pathToDir.rpartition('/')
        if path == '':
            raise RuntimeError("cannot parse inclusive path " + pathToDir)

        tree = MerkleTree(name, usingSHA1, exRE, matchRE)

        # Create data structures for constituent files and subdirectories
        # These are sorted by the bare name
        files = os.listdir(pathToDir)  # empty if you just append .sort()
        files.sort()                    # sorts in place
        tree._hash = None
        if usingSHA1:
            shaX = hashlib.sha1()
        else:
            shaX = hashlib.sha256()
        if files:
            shaXCount = 0
            for file in files:
                # exclusions take priority over matches
                if exRE and exRE.search(file):
                    continue
                if matchRE and not matchRE.search(file):
                    continue
                node = None
                pathToFile = os.path.join(pathToDir, file)
                s = os.lstat(pathToFile)        # ignores symlinks
                mode = s.st_mode
                # os.path.isdir(path) follows symbolic links
                if S_ISDIR(mode):
                    node = MerkleTree.createFromFileSystem(
                            pathToFile, usingSHA1, deltaIndent,exRE, matchRE)
                # S_ISLNK(mode) is true if symbolic link
                # isfile(path) follows symbolic links
                elif os.path.isfile(pathToFile):        # S_ISREG(mode):
                    node = MerkleLeaf.createFromFileSystem(
                                pathToFile, file, usingSHA1, deltaIndent)
                # otherwise, just ignore it ;-)

                if node:
                    # update tree-level hash
                    if node.binHash is not None:
                        # note empty file has null hash
                        shaXCount += 1
                        shaX.update(node.binHash)
                    # SKIP NEXT TO EASE GARBAGE COLLECTION ??? XXX
                    # but that won't be a good idea if we are
                    # invoking toString()
                    tree._nodes.append(node)
            if shaXCount:
                tree._hash = shaX.digest()
#       else:           # WE SEE THIS ERROR
#           # this must be an error; . and .. are always present
#           msg = "directory '%s' contains no files" % pathToDir
#           raise RuntimeError(msg)

        return tree

    # OTHER METHODS AND PROPERTIES ##################################
    @classmethod
    def firstLineRE_1(cls):
        """ 
        Returns a reference to the regexp for SHA1 first lines.  A
        match finds (indent, treeHash, dirName), where indent is an
        integer, the treeHash is a hex string, and dirName may have a
        terminating slash.
        """
        return MerkleTree.FIRST_LINE_RE_1

    @classmethod
    def firstLineRE_2(cls):
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

    def addNode(self, node):
        if node == None:
            raise RuntimeError("attempt to add null node")
        if not isinstance(node, MerkleTree) \
                and not isinstance(node, MerkleLeaf):
            raise RuntimeError("node being added not MerkleTree or MerkleLeaf")
        self._nodes.append(node)

    # SERIALIZATION #################################################
    def toStringNotTop(self, indent='', deltaIndent=' '):
        """ indent is the indentation to be used for the top node"""
        s      = []                             # a list of strings
        if self._hash == None:
            if self._usingSHA1:
                top = "%s%s %s/\r\n" % (indent, SHA1_NONE, self.name)
            else:
                top = "%s%s %s/\r\n" % (indent, SHA2_NONE, self.name)
        else:
            top = "%s%s %s/\r\n" % (indent, self.asciiHash, self.name)
        s.append(top)
        indent = indent + deltaIndent              # <--- LEVEL 2+ NODE
        for node in self.nodes:
            if isinstance(node, MerkleLeaf):
                s.append( node.toString(indent, deltaIndent) )
            else:
                # recurse
                s.append( node.toStringNotTop(indent, deltaIndent) )

        return ''.join(s)

    def toString(self, indent='', deltaIndent=' '):
        """
        indent is the initial indentation of the serialized list, NOT the
        extra indentation added at each recursion, which is deltaIndent.
        Using code should take into account that the last line is CR-LF
        terminated, and so a split on CRLF will generate an extra blank line
        """
        s      = []                             # a list of strings
        if self._hash == None:
            if self._usingSHA1:
                top = "%s%s %s/\r\n" % (indent, SHA1_NONE, self.name)
            else:
                top = "%s%s %s/\r\n" % (indent, SHA2_NONE, self.name)
        else:
            top = "%s%s %s/\r\n" % (indent, self.asciiHash, self.name)    
        s.append(top)                       # <--- LEVEL 0 NODE
        myIndent = indent + deltaIndent     # <--- LEVEL 1 NODE
        for node in self.nodes:
            if isinstance (node, MerkleLeaf):
                s.append(node.toString(myIndent, deltaIndent))
            else:
                # recurse
                s.append( node.toStringNotTop(myIndent, deltaIndent) )

        return ''.join(s)
