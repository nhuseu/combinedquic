# CombinedQUIC

## Basic Information

### Authors 
nhu(nhu@seu.edu.cn)  hwu(hwu@seu.edu.cn) hyzhao(hyzhao@seu.edu.cn) ssni(ssni@seu.edu.cn) gcheng(chengguang@seu.edu.cn)  

### Brief 
This repository only intends to help researchers understand and reproduce the main results in our paper, "Breaking Through the Diversity: Encrypted Video Identification Attack Based on QUIC
Features", for encrypted QUIC video identification attacks in combined transmission scenarios.

## Files introduction

__/bin/win/__: Make_db.exe, QUIC _data.exe, match_mdb.exe and some supporting files for building a key-value structured real fingerprint database, correcting and restoring transmitted fingerprints, and matching fingerprints for identification.

__/src/ folder__: The source code.

__/include/__ and __/lib/__: Support source code compilation.

## Getting Started
These instructions will get you a copy of the project up and running on your local machine for development and testing purposes.

### Cloning the repository

Clone the project to have a copy in your desired local repository

git clone https://github.com/nhuseu/combinedquic.git [LOCAL_DIRECTORY_PATH]

### Usage

1: Change the relevant paths in __/bin/win/data.cfg__ to your local directory where PCAP files are stored and the location of the fingerprint file (.csv).

2: Make sure the __data.cfg__ and the four __.dll__ files are in the same folder as the __.exe__. 

* Run __make_db.exe__ from the command line to create the real fingerprint daatbase.

* Run __QUIC_data.exe__ to correct the transmission fingerprints.

* Run __match_mdb.exe__ to implement video identification through multi-threaded fingerprint matching.

## Results


