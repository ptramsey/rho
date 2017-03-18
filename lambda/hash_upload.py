"""
Hash files uploaded to a given bucket in s3.

This file should compile in both python 2.7 and 3.4+
"""

from __future__ import print_function, absolute_import, division, unicode_literals

import hashlib
import logging
import os
import sys
from contextlib import closing

import boto3

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)


DEFAULT_S3_BUCKET = "fivestars-receipt-test"
DEFAULT_HASH_FUNCTION = "sha256"


def chunks(fp, chunk_size=4096):
    chunk = fp.read(chunk_size)
    while chunk:
        yield chunk
        chunk = fp.read(chunk_size)


def handler(event, context):
    s3 = boto3.resource('s3')

    bucket = os.environ.get("S3_BUCKET", DEFAULT_S3_BUCKET)
    hash_function = os.environ.get("HASH_FUNCTION", DEFAULT_HASH_FUNCTION)

    if hash_function not in hashlib.algorithms_available:
        raise ValueError("{} is not a recognized hash function".format(hash_function))

    for record in event["Records"]:
        if not record["eventName"].startswith("ObjectCreated"):
            continue

        key = record["s3"]["object"]["key"]
        if key.endswith(".{}".format(hash_function)):
            continue

        s3_object = s3.Object(bucket, key)

        try:
            response = s3_object.get()
            hasher = hashlib.new(hash_function)
            with closing(response["Body"]) as body:
                for chunk in chunks(body):
                    hasher.update(chunk)

        except s3.meta.client.exceptions.NoSuchKey:
            continue

        file_hash = hasher.hexdigest()
        logger.info("Hashed s3://{}/{} to {}".format(bucket, key, file_hash))

        (s3.Object(bucket, "{}.{}".format(key, hash_function))
                .put(Body="{}\n".format(file_hash).encode('utf8')))


if __name__ == "__main__":
    try:
        from configparser import ConfigParser
    except ImportError:
        from ConfigParser import ConfigParser

    logging.basicConfig()

    os.environ["S3_BUCKET"] = "fivestars-receipt-test"

    event = {
        "Records": [{
            "eventName": "ObjectCreated:put",
            "s3": {
                "object": {
                    "key": "foofile.txt",
                },
            },
        }],
    }

    handler(event, None)

