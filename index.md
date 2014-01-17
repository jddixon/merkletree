merkletree
==========

# What It Does

Merkletree is a Python package for creating a Merkle tree for a 
directory structure.  This is a representation of the contents 
of the directory and its subdirectories in terms of SHA1 or SHA3
(Keccak-256) hashes.  A file is represented by the hash of its 
contents.  A directory is represented by the hash of the hashes
of its members, sorted.  This makes it very easy to verify the
contents of a directory:

    merkleize -i . -x 

outputs a single hash, a hexadecimal number.  If any file in the
directory structure has been changed, the output from the above 
command will also change.

# What It's Used For

Verifying the integrity of file systems, of directory structures.


# Command Line

	usage: merkleize [options]
	where the options are
	  -h, --help           to see this very useful message
	  -1, --usingSHA1      use SHA1 hash instead of default SHA3-256
	  -d  --outDir DIR     write serialized merkletree here
	  -i, --inDir DIR      where DIR names directory being scanned
	  -j, --justShow       list options and exit
	  -m  --showTree       output the merkletree hash/filename pairs
	  -o, --outFile NAME   write output to this file name
	  -P, --match PAT      include ONLY files with matching names
	  -t, --showTimestamp  output UTC timestamp to command line
	  -v, --verbose        verbose: whether the program is chatty
	  -V, --version        show version information
	  -x, --hashOutput     whether to output the top level hash
	  -X, --exclude PAT    don't include files with matching names
	The default output file name is the UTC timestamp.


# Relationships

Merkletree was implemented as part of the [XLattice](http://www.xlattice.org) 
project.  A Go language implementation forms part of 
[xlattice_go](https://gibhub.com/jddixon/xlattice_go).
