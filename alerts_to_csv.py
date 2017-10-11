from __future__ import print_function
from wsgiref.handlers import format_date_time
from datetime import datetime
from time import mktime
from hashlib import sha1

import uuid
import pycurl
import json
import md5
import base64
import cStringIO
import hmac
import time
import certifi

#=== Description ===
# Output the latest alerts into a CSV file.
#
# Instructions:
# 1. Enter your ESP API Public Key and Secret Key
# 2. (Optional) Enter which attributes you want to output. The attribute name can be anything from:
# a. Alert (http://api-docs.evident.io/#attributes)
# b. Signature (http://api-docs.evident.io/#attributes112)
# Note: See example for formatting
# 3. (Optional) Modify the CSV parameters
#
# Note: Non-ASCII characters will be dropped from final output
#
#=== End Description ===

#=== Configuration ===

# ESP API Access Key Credentials

public = <public key>
secret = <secret key>

# Alert attributes to output
ATTRIBUTES = ['alert.id', 'alert.created_at', 'alert.ended_at', 'signature.name', 'alert.status', 'region.code', 'external_account.name', 'signature.identifier', 'alert.risk_level', 'service.name', 'signature.description', 'signature.resolution' , 'suppression.id', 'suppression.created_at', 'suppression.reason', 'alert.resource'  ]

# no data: metadata.data regions.code region.code suppression.id suppression.created_at suppression.reason
# unicode error: signature.description signature.resolution

# CSV file parameters
DELIMITER = ','
CSV_FILENAME = 'alerts.csv'
OUTPUT_TO_CSV = True

#=== End Configuration ===

#=== Helper Methods ===

def call_api(action, url, data, count = 0):
    # Construct ESP API URL
    ev_create_url = 'https://api.evident.io%s' % (url)
    
    # Create md5 hash of body
    m = md5.new()
    m.update(data.encode('utf-8'))
    data_hash = base64.b64encode(m.digest())
    #print(data_hash)
    
    # Find Time
    now = datetime.now()
    stamp = mktime(now.timetuple())
    #print(format_date_time(stamp))
    
    # Create Authorization Header
    canonical = '%s,application/vnd.api+json,%s,%s,%s' % (action, data_hash, url, format_date_time(stamp))
    #print(canonical)
    
    hashed = hmac.new(secret, canonical, sha1)
    auth = hashed.digest().encode("base64").rstrip('\n')
    
    # Create Curl request
    buf = cStringIO.StringIO()
    c = pycurl.Curl()
    c.setopt(pycurl.CAINFO, certifi.where())
    c.setopt(pycurl.URL, str(ev_create_url))
    c.setopt(pycurl.HTTPHEADER, [
        'Date: %s' % format_date_time(stamp),
        'Content-MD5: %s' % data_hash,
        'Content-Type: application/vnd.api+json', 
        'Accept: application/vnd.api+json',
        'Authorization: APIAuth %s:%s' % (public, auth)])
    c.setopt(c.WRITEFUNCTION, buf.write)
    
    if action == 'POST':
        c.setopt(pycurl.POST, 1)
        c.setopt(pycurl.POSTFIELDS, data)
    elif action == 'PATCH':
        c.setopt(c.CUSTOMREQUEST, 'PATCH')
        c.setopt(pycurl.POSTFIELDS, data)
    elif action == 'DELETE':
        c.setopt(c.CUSTOMREQUEST, 'DELETE')
        c.setopt(pycurl.POSTFIELDS, data)
    c.perform()
    ev_response = buf.getvalue()
    buf.close()
    c.close()
    ev_response_json = json.loads(ev_response)
    
    # Handle rate-limit exceptions
    if 'errors' in ev_response_json:
        for error in ev_response_json['errors']:
            print(error)
            if int(error['status']) == 429:
                if count < 5:
                    # Wait 60 seconds for every retry
                    time.sleep(60 * (count + 1))
                    count += 1
                    print("retry - %s" % count)
                    return call_api(action, url, data, count)
                else:
                    # Give-up after 5 retries
                    return false
            else:
                # Throw Exception and end script if any other error occurs
                raise Exception('%d - %s' % (int(error['status']), error['title']))
    
    return ev_response_json

# Get id from relationship link
# Example: http://test.host/api/v2/signatures/1003.json
# Should return '1003'
def get_id(link):
    a = link.split("/")
    b = a[len(a) - 1].split(".")
    return b[0]

# Retrieve list of items of specified type
def get_items(item_type):
    items = {}
    page_num = 1
    has_next = True
    while has_next:
        ev_create_url = '/api/v2/%s?page[number]=%d&amp;amp;page[size]=100' % (item_type, page_num)
        data = ''
        ev_response_json = call_api('GET', ev_create_url, data)
        if 'data' in ev_response_json:
            for item in ev_response_json['data']:
                item['attributes']['id'] = item['id']
                items[item['id']] = item
        page_num += 1
        has_next = ('next' in ev_response_json['links'])
        ev_response_json = call_api('GET', ev_create_url, data)
    return items

# Retrieve latest alerts for given external account ID
def find_latest_alerts(external_account_id):
    data = ''
    ev_create_url = '/api/v2/reports?filter[external_account_id_eq]=%s' % external_account_id
    ev_response_json = call_api('GET', ev_create_url, data)
    for report in ev_response_json['data']:
        if 'status' in report['attributes'] and report['attributes']['status'] == 'complete':
            alerts = []
            page_num = 1
            has_next = True
            while has_next:
                print(' Getting page %d' % page_num)
                ev_create_url = '/api/v2/reports/%s/alerts.json?page[number]=%d&amp;amp;page[size]=100' % (report['id'], page_num)
                ev_response_json = call_api('GET', ev_create_url, data)
                alerts += ev_response_json['data']
                page_num += 1
                has_next = ('next' in ev_response_json['links'])
                break
                
            # Retrieve suppressed alerts
            page_num = 1
            has_next = True
            while has_next:
                print(' Getting page %d' % page_num)
                ev_create_url = '/api/v2/reports/%s/alerts.json?page[number]=%d&amp;amp;page[size]=100&amp;amp;filter[suppressed]=true' % (report['id'], page_num)
                ev_response_json = call_api('GET', ev_create_url, data)
                alerts += ev_response_json['data']
                page_num += 1
                has_next = ('next' in ev_response_json['links'])
                
            return alerts

def get_signature_id(alert):
    if alert['relationships']['signature']['links']['related'] is not None:
        return get_id(alert['relationships']['signature']['links']['related'])
    elif alert['relationships']['custom_signature']['links']['related'] is not None:
        return get_id(alert['relationships']['custom_signature']['links']['related'])
    return -1
        
def is_standard_sig(alert):
    if alert['relationships']['signature']['links']['related'] is not None:
        return True
    elif alert['relationships']['custom_signature']['links']['related'] is not None:
        return False
    return -1

# Retrieve and process all external accounts
def get_all_alerts():
    latest_alerts = []
    page_num = 1
    has_next = True
    while has_next:
        data = ''
        ev_create_url = '/api/v2/external_accounts?page[number]=%d&amp;amp;page[size]=100' % page_num
        ev_response_json = call_api('GET', ev_create_url, data)
        for external_account in ev_response_json['data']:
            print('Retrieving alerts for %s' % external_account['id'])
            latest_alerts += find_latest_alerts(external_account['id'])
        page_num += 1
        has_next = ('next' in ev_response_json['links'])
        ev_response_json = call_api('GET', ev_create_url, data)
    return latest_alerts

def get_output():
    print('Retrieving standard signatures')
    signatures = get_items('signatures')

    print('Retrieving custom signatures')
    custom_signatures = get_items('custom_signatures')
    
    print('Retrieving services')
    services = get_items('services')
    
    print('Retrieving regions')
    regions = get_items('regions')

    print('Retrieving external accounts')
    external_accounts = get_items('external_accounts')
    
    print('Retrieving suppressions')
    suppressions = get_items('suppressions')
    
    latest_alerts = get_all_alerts()

    # Generate string in CSV format
    output = ''
    for attribute in ATTRIBUTES:
        output += attribute + ','
    output = output[:(len(output) - 1)] + '\n'

    for alert in latest_alerts:    
        if is_standard_sig(alert):
            signature = signatures[get_signature_id(alert)]
            service = services[get_id(signature['relationships']['service']['links']['related'])]
        else:
            signature = custom_signatures[get_signature_id(alert)]
            service = None
        
        region = regions[get_id(alert['relationships']['region']['links']['related'])]
        external_account = external_accounts[get_id(alert['relationships']['external_account']['links']['related'])]
        if alert['relationships']['suppression']['links']['related'] is not None:
            suppression = suppressions[get_id(alert['relationships']['suppression']['links']['related'])]
        else:
            suppression = None

        for attribute in ATTRIBUTES:
            att_type, attribute = attribute.split(".")
            if att_type == 'alert' and attribute in alert and alert[attribute] is not None:
                output += alert[attribute]
            elif att_type == 'alert' and attribute in alert['attributes'] and alert['attributes'][attribute] is not None:
                output += alert['attributes'][attribute]
            elif att_type == 'signature' and attribute in signature['attributes'] and signature['attributes'][attribute] is not None:
                output += signature['attributes'][attribute].encode('ascii',errors='ignore')
            elif att_type == 'region' and attribute in region['attributes'] and region['attributes'][attribute] is not None:
                output += region['attributes'][attribute]
            elif att_type == 'service' and service is not None and attribute in service['attributes'] and service['attributes'][attribute] is not None:
                output += service['attributes'][attribute]
            elif att_type == 'external_account' and attribute in external_account['attributes'] and external_account['attributes'][attribute] is not None:
                output += external_account['attributes'][attribute]
            elif att_type == 'suppression' and suppression is not None and attribute in suppression['attributes'] and suppression['attributes'][attribute] is not None:
                output += suppression['attributes'][attribute]
                
            output += DELIMITER
        output = output[:(len(output) - 1)] + '\n'
            
    return output

def save_to_file(output):
    with open(CSV_FILENAME, 'w') as f: 
        f.write(output) 
        
#=== End Helper Methods ===
        
# === Main Script ===

output = get_output()
#print(output)

if OUTPUT_TO_CSV:
    save_to_file(output)

# === End Main Script ===