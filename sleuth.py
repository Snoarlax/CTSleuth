#!/usr/bin/env python3
import random
import asyncio
import math
import json
import base64
import ctl_parser
import httpx
from OpenSSL import crypto

# TODO: use argparse library to make it a proper CLI tool

# CTSleuth
CTL_ENDPOINT="https://ct.googleapis.com/logs/argon2020/ct/v1"
SHARD_SIZE=31
DEFAULT_ASYNC_SHARDS=10
CTL_LOG_SIZE=961984010

class x509Name_hashable():
    def __init__(self, x509Name_object, shard_offset=0):
        self.shard_offset = shard_offset
        self.object = x509Name_object

    def __hash__(self):
        return self.object.hash()


def get_shards(offsets, size=SHARD_SIZE):
    shards = []
    responses = asyncio.run(get_shards_responses(offsets,size))
    for response in responses:
        shards += json.loads(response.text)['entries']
    return shards

async def get_shards_responses(offsets, size=SHARD_SIZE):
    responses = []
    async with httpx.AsyncClient() as client:
        for offset in offsets:
            params = {
                'start': str(offset),
                'end': str(offset+size),
            }
            responses += [await client.get(CTL_ENDPOINT+"/get-entries", params=params)]

    return responses

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
    total_shards = int(input("How many shards would you like to look through? "))
    features = set()
    # TODO: would be usefull to do a "merge sort" style approach to finding treasure
    print("looking for {0} shards from 0 to tree size {1}".format(total_shards, CTL_LOG_SIZE))
    for i in range(math.ceil(total_shards/DEFAULT_ASYNC_SHARDS)):
        async_shards = min(total_shards, DEFAULT_ASYNC_SHARDS)
        offsets = [random.randint(0, CTL_LOG_SIZE) for _ in range(async_shards)]
        entries = get_shards(offsets)
        total_shards -= DEFAULT_ASYNC_SHARDS
        for entry in entries:
            entry = parse_entry(entry)
            for x509_object in entry:
                # The offsets is wrong, just a temporary fix
                feature = x509Name_hashable(x509_extract(x509_object), offsets[0])
                features.add(feature)
    print_features(features)
    

if __name__== "__main__":
    main()



