#!/bin/python3
import requests
import json
import base64
import ctl_parser
from OpenSSL import crypto

# TODO: it would be better if i chose random entries instead of going in order... implement a random mode because i doubt people will search through the whole thing anyways
# TODO: I should make this multithreaded

# CTSleuth
#https://ct.googleapis.com/logs/argon2020/ct/v1/get-entries?start=0&end=10
CTL_ENDPOINT="https://ct.googleapis.com/logs/argon2020/ct/v1"
SHARD_SIZE=31

class x509Name_hashable(crypto.X509Name):
    def __init__(self, x509Name_object):
        super().__init__(x509Name_object)

    def __hash__(self):
        return self.hash()


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
    for f in features:
        out = ",".join(["=".join(str(e) for e in t) for t in f.get_components()])
        print(out)

def main():
    print("CTSleuth")
    features = set()
    for i in range(100):
        entries = get_shards(i*SHARD_SIZE)
        for entry in entries:
            entry = parse_entry(entry)
            for x509_object in entry:
                feature = x509Name_hashable(x509_extract(x509_object))
                features.add(feature)
    print_features(features)
    

if __name__== "__main__":
    main()



