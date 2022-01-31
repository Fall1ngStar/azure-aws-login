import base64
from functools import cached_property
import hmac
import json
import logging
import re
import struct
import sys
import time
import zlib
from argparse import ArgumentParser
from base64 import b64encode
from datetime import datetime
from time import sleep
from urllib import parse
from uuid import uuid4

import boto3
from selenium.webdriver import Keys
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.common.by import By
from seleniumwire import webdriver

AWS_SAML_ENDPOINT = "https://signin.aws.amazon.com/saml"

logging.basicConfig()
LOGGER = logging.getLogger("azure-aws-login")


def hotp(key, counter, digits=6, digest="sha1"):
    key = base64.b32decode(key.upper() + "=" * ((8 - len(key)) % 8))
    counter = struct.pack(">Q", counter)
    mac = hmac.new(key, counter, digest).digest()
    offset = mac[-1] & 0x0F
    binary = struct.unpack(">L", mac[offset : offset + 4])[0] & 0x7FFFFFFF
    return str(binary)[-digits:].zfill(digits)


def totp(key, time_step=30, digits=6, digest="sha1"):
    return hotp(key, int(time.time() / time_step), digits, digest)


def deflate(data, compresslevel=9):
    compress = zlib.compressobj(
        compresslevel,  # level: 0-9
        zlib.DEFLATED,  # method: must be DEFLATED
        -zlib.MAX_WBITS,  # window size in bits:
        #   -15..-8: negate, suppress header
        #   8..15: normal
        #   16..30: subtract 16, gzip header
        zlib.DEF_MEM_LEVEL,  # mem level: 1..8/9
        0  # strategy:
        #   0 = Z_DEFAULT_STRATEGY
        #   1 = Z_FILTERED
        #   2 = Z_HUFFMAN_ONLY
        #   3 = Z_RLE
        #   4 = Z_FIXED
    )
    deflated = compress.compress(data)
    deflated += compress.flush()
    return deflated


class AzureAWSLogin:
    def __init__(self):
        self._saml_response = None
        self.should_stop = False

    @cached_property
    def args(self):
        parser = ArgumentParser(description="Login to AWS with Azure AD")
        parser.add_argument("--tenant-id", required=True, dest="tenant_id")
        parser.add_argument("--app-id", required=True, dest="app_id")
        parser.add_argument("--username", required=True, dest="username")
        parser.add_argument("--password", required=True, dest="password")
        parser.add_argument("--totp-secret", required=True, dest="totp_secret")
        parser.add_argument("--gui", action="store_true", dest="gui")
        parser.add_argument(
            "--log-level",
            choices=["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"],
            default="WARNING",
            dest="log_level",
        )
        return parser.parse_args()

    @cached_property
    def login_url(self):
        uuid = str(uuid4())
        saml_request = f"""
            <samlp:AuthnRequest xmlns="urn:oasis:names:tc:SAML:2.0:metadata" ID="id{uuid}" Version="2.0" IssueInstant="{datetime.now().isoformat()[:-3]}Z" IsPassive="false" AssertionConsumerServiceURL="{AWS_SAML_ENDPOINT}" xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol">
                <Issuer xmlns="urn:oasis:names:tc:SAML:2.0:assertion">{self.args.app_id}</Issuer>
                <samlp:NameIDPolicy Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"></samlp:NameIDPolicy>
            </samlp:AuthnRequest>
        """
        saml_base64 = b64encode(deflate(saml_request.encode()))
        quoted = parse.quote(saml_base64)
        url = f"https://login.microsoftonline.com/{self.args.tenant_id}/saml2?SAMLRequest={quoted}"
        LOGGER.debug(f"Login URL: {url}")
        return url

    def interceptor(self, request):
        if request.url == AWS_SAML_ENDPOINT:
            self._saml_response = request.params["SAMLResponse"]
            self.should_stop = True

    @cached_property
    def saml_response(self):
        chrome_options = Options()
        if not self.args.gui:
            chrome_options.add_argument("--headless")

        LOGGER.debug("Start web driver")
        driver = webdriver.Chrome(options=chrome_options)
        driver.implicitly_wait(5)
        driver.request_interceptor = self.interceptor

        LOGGER.debug("Go to login URL")
        driver.get(self.login_url)

        LOGGER.debug("Send username")
        elem = driver.find_element(
            by=By.CSS_SELECTOR, value='input[name="loginfmt"]:not(.moveOffScreen)'
        )
        elem.send_keys(self.args.username, Keys.RETURN)

        LOGGER.debug("Send password")
        elem = driver.find_element(
            by=By.CSS_SELECTOR,
            value='input[name="Password"]:not(.moveOffScreen),input[name="passwd"]:not(.moveOffScreen)',
        )
        elem.send_keys(self.args.password, Keys.RETURN)

        LOGGER.debug("Send TOTP code")
        elem = driver.find_element(
            by=By.CSS_SELECTOR, value="input[name=otc]:not(.moveOffScreen)"
        )
        elem.send_keys(totp(self.args.totp_secret), Keys.RETURN)

        LOGGER.debug("Wait for AWS console to load")
        while not self.should_stop:
            sleep(0.25)
        if not self._saml_response:
            LOGGER.error("No SAML response found")
            sys.exit(1)

        return self._saml_response

    @cached_property
    def aws_credentials(self):
        decoded = base64.b64decode(self.saml_response).decode()
        provider = re.search(r"arn:aws:iam::\d+:saml-provider/[a-zA-Z0-9\-]+", decoded)
        arn = re.search(r"arn:aws:iam::\d+:role/\w+", decoded).group(0)
        sts = boto3.client("sts")
        result = sts.assume_role_with_saml(
            RoleArn=arn,
            SAMLAssertion=self.saml_response,
            PrincipalArn=provider.group(0),
        )
        credentials = result["Credentials"]
        credentials["Version"] = 1
        credentials["Expiration"] = credentials["Expiration"].isoformat()
        return json.dumps(credentials)


def cli():
    print(AzureAWSLogin().aws_credentials)


if __name__ == "__main__":
    cli()
