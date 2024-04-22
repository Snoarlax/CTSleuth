#!/bin/python3
import requests
import random
import json
import base64
import ctl_parser
from OpenSSL import crypto

# TODO: I should make this multithreaded

# CTSleuth
#https://ct.googleapis.com/logs/argon2020/ct/v1/get-entries?start=0&end=10
CTL_ENDPOINT="https://ct.googleapis.com/logs/argon2020/ct/v1"
SHARD_SIZE=31
CTL_LOG_SIZE=961984010

class x509Name_hashable():
    def __init__(self, x509Name_object, shard_offset=0):
        self.shard_offset = shard_offset
        self.object = x509Name_object

    def __hash__(self):
        return self.object.hash()


def get_shards(offset, size=SHARD_SIZE):
    params = {
        'start': str(offset),
        'end': str(offset+size),
    }

    response = requests.get(CTL_ENDPOINT+"/get-entries", params=params)
    return json.loads(response.text)['entries']

def parse_entry(entry):
    
    leaf_cert = ctl_parser.MerkleTreeHeader.parse(base64.b64decode(entry['leaf_input']))
    chain = []
    if leaf_cert.LogEntryType == "X509LogEntryType":
        cert_data_string = ctl_parser.Certificate.parse(leaf_cert.Entry).CertData
        chain = [crypto.load_certificate(crypto.FILETYPE_ASN1, cert_data_string)]

        extra_data = ctl_parser.CertificateChain.parse(base64.b64decode(entry['extra_data']))
        for cert in extra_data.Chain:
            chain.append(crypto.load_certificate(crypto.FILETYPE_ASN1, cert.CertData))
    else:
        extra_data = ctl_parser.PreCertEntry.parse(base64.b64decode(entry['extra_data']))
        chain = [crypto.load_certificate(crypto.FILETYPE_ASN1, extra_data.LeafCert.CertData)]

        for cert in extra_data.Chain:
            chain.append(
                crypto.load_certificate(crypto.FILETYPE_ASN1, cert.CertData)
            )

    return chain

def x509_extract(x509_object):
    # This can extract whatever information you want from the x509 object. By default, it will extract the issuing CA
    return x509_object.get_issuer()

def print_features(features):
    print("CTL_ENDPOINT: {0}".format(CTL_ENDPOINT))
    print("SHARD_SIZE: {0}".format(SHARD_SIZE))
    for f in features:
        out = str(f.shard_offset) + ": " + ",".join(["=".join(str(e) for e in t) for t in f.object.get_components()])
        print(out)

def main():
    features = set()
    no_shards = int(input("How many shards would you like to look through? "))
    random_mode = input("Would you like to enable random mode? ").lower() in ['y','yes']
    if not random_mode:
        # TODO: would be usefull to do a "merge sort" style approach to finding treasure
        starting_offset=int(input("which offset would you like to start off with? ")) 
        print("Random mode disabled - looking for {0} shards starting from {1}".format(no_shards, starting_offset))
        for i in range(no_shards):
            offset = starting_offset + i*SHARD_SIZE
            entries = get_shards(offset)
            for entry in entries:
                entry = parse_entry(entry)
                for x509_object in entry:
                    feature = x509Name_hashable(x509_extract(x509_object), offset)
                    features.add(feature)
    else:
        print("Random mode enabled - looking for {0} shards from 0 to tree size {1}".format(no_shards, CTL_LOG_SIZE))
        for i in range(no_shards):
            offset = random.randint(0, CTL_LOG_SIZE)
            entries = get_shards(offset)
            for entry in entries:
                entry = parse_entry(entry)
                for x509_object in entry:
                    feature = x509Name_hashable(x509_extract(x509_object), offset)
                    features.add(feature)
    print_features(features)
    

if __name__== "__main__":
    main()



