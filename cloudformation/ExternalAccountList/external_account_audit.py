#!/usr/bin/env python
#
# Copyright (c) 2013, 2014, 2015, 2016, 2017. Evident.io (Evident). All Rights Reserved.
#
#   Evident.io shall retain all ownership of all right, title and interest in and to
#   the Licensed Software, Documentation, Source Code, Object Code, and API's ("Deliverables"),
#   including (a) all information and technology capable of general application to Evident.io's
#   customers; and (b) any works created by Evident.io prior to its commencement of any
#   Services for Customer.
#
# Upon receipt of all fees, expenses and taxes due in respect of the relevant Services,
#   Evident.io grants the Customer a perpetual, royalty-free, non-transferable, license to
#   use, copy, configure and translate any Deliverable solely for internal business operations
#   of the Customer as they relate to the Evident.io platform and products, and always
#   subject to Evident.io's underlying intellectual property rights.
#
# IN NO EVENT SHALL EVIDENT.IO BE LIABLE TO ANY PARTY FOR DIRECT, INDIRECT, SPECIAL,
#   INCIDENTAL, OR CONSEQUENTIAL DAMAGES, INCLUDING LOST PROFITS, ARISING OUT OF
#   THE USE OF THIS SOFTWARE AND ITS DOCUMENTATION, EVEN IF EVIDENT.IO HAS BEEN HAS BEEN
#   ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
#
# EVIDENT.IO SPECIFICALLY DISCLAIMS ANY WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
#   THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE.
#   THE SOFTWARE AND ACCOMPANYING DOCUMENTATION, IF ANY, PROVIDED HEREUNDER IS PROVIDED "AS IS".
#   EVIDENT.IO HAS NO OBLIGATION TO PROVIDE MAINTENANCE, SUPPORT, UPDATES, ENHANCEMENTS,
#   OR MODIFICATIONS.
#
# ---
#
# This script dumps a list of ESP users for an organization to a csv file called,
# "esp_users_report.csv" in the same directory that the script is executed in.
# Alternatively, you can simply list ESP users in json format to the screen.
#
# Requirements:
#
# * Python3 (Tested with version 3.6.1)
#   `python --version`
#
# * Install the ESP Python SDK
#   https://github.com/EvidentSecurity/esp-sdk-python2
#
# * Valid ESP credentials / API keys
#   https://esp.evident.io/settings/api_keys
#   export ESP_ACCESS_KEY_ID=<your_access_key>
#   export ESP_SECRET_ACCESS_KEY=<your_secret_access_key>
#

import esp_sdk
import csv
import os
import json
import sys
import argparse
import boto3
import time

config = esp_sdk.Configuration()
config.access_key_id = os.environ.get("AccessKeyId", None)
config.secret_access_key = os.environ.get("SecretAccessKey", None)

s3_bucket = os.environ.get("TargetS3Bucket", None)

def create_eaccounts_report(eaccounts):
    """ Build a external account report """

    report = []
    for e, externalaccount in enumerate(eaccounts):
        account_number = esp_sdk.ExternalAccountsAmazonApi().show(externalaccount.id).account if externalaccount.provider == 'amazon' else 'NotAmazon'
        report_info = {
          'Sub-Organization'   : externalaccount.team.sub_organization.name,
          'Team'               : externalaccount.team.name,
          'ExternalAccount'    : externalaccount.name,
          'Account Number'     : account_number
        }

        report.append(report_info)

    return report


def create_csv_file(csv_file_name, report):
    """ Create csv formatted file """

    try:
        with open(csv_file_name, 'w') as f:
            head = [ 'Sub-Organization', 'Team', 'ExternalAccount','Account Number' ]
            writer = csv.DictWriter(f, fieldnames=head)
            writer.writeheader()
            for row in report:
                writer.writerow(row)
    except:
        pass

    if os.path.exists(csv_file_name) == True and os.stat(csv_file_name).st_size > 0:
        result = 'Success: Created ESP csv externalaccount report, ' + csv_file_name +'.'
    else:
        result = 'Error: Failed to create csv file, ' + csv_file_name +'.'

    return result

def upload_csv_file(filename, key):
    """Upload generated file to S3 Bucket"""
    s3 = boto3.resource('s3')
    bucket = s3.Bucket(s3_bucket)
    bucket.upload_file(filename, key)

def main(event, context):
    """ Run checks and do the work """

    try:
        eaccounts_api = esp_sdk.ExternalAccountsApi()
        eaccounts = eaccounts_api.list(include='team.sub_organization,team', page='{:number=>1,+:size=>1000}')
    except esp_sdk.rest.ApiException as e:
        if str(e.status) == '401':
            print('Error: Please check your ESP credentials / API keys.')
        else:
            print(e)
        sys.exit(1)
    csv_file_name = '/tmp/esp_eaccounts_report.csv'
    report = create_eaccounts_report(eaccounts)
    result = create_csv_file(csv_file_name, report)
    upload = upload_csv_file(csv_file_name, 'accountlist-%s.csv' % time.strftime("%d-%m-%Y"))
    print(result)

