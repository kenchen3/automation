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
# This script reads from a csv file containing a list of ESP users and attempts to create each one.
# It looks for a file called "esp_users_delete.csv" is the same directory the script is executed in.
#
# CSV File Format:
#
# Email,
# jimmy@example.com
# randy@example.com
# eric@example.com
# Requirements:
# 
#
# * Python3 (Tested with version 3.6.1)
#   `python --version`
#
# * Install the ESP Python SDK
#   https://github.com/EvidentSecurity/esp-sdk-python
# 
# * Valid ESP credentials / API keys
#   https://esp.evident.io/settings/api_keys
#   export ESP_ACCESS_KEY_ID=<your_access_key>
#   export ESP_SECRET_ACCESS_KEY=<your_secret_access_key>
#

csv_delimiter = ','
req_fields = 1

import esp_sdk
import csv
import os
import json
import sys
import argparse
config = esp_sdk.Configuration()
config.access_key_id = os.environ["ESP_ACCESS_KEY_ID"]
config.secret_access_key = os.environ["ESP_SECRET_ACCESS_KEY"]

def read_user_data(csv_file_name):
    """ Read ESP users csv file """

    emailusers = []
    with open(csv_file_name, 'r') as csvUserData:
        csvReader = csv.reader(csvUserData, delimiter = csv_delimiter)
        for row in csvReader:
            user = row[0] 
            emailusers.append(user)

    return emailusers

def get_user_list_complete():
    users_api = esp_sdk.UsersApi()
    users = users_api.list()
    id_email_users = {}
    for u, user in enumerate(users): id_email_users[user.email] = user.id
    return id_email_users

def delete_users(id_email_users,emailusers):
    users_api = esp_sdk.UsersApi()
    users = users_api.list()
    for i in emailusers:
      try: 
        result =  users_api.delete(id_email_users[i])
        print(result)
      except KeyError:
        print("User does not exist")


def main(csv_file_name):
    """ Run checks and do the work """

    if os.path.exists(csv_file_name) != True:
        print("Error: Can't find file, " + csv_file_name + '.')
        exit(1)

    emailusers  = read_user_data(csv_file_name)
    id_email_users = get_user_list_complete()
    result = delete_users(id_email_users,emailusers)


if __name__ == "__main__":
  
  main(csv_file_name = 'esp_users_delete.csv')
