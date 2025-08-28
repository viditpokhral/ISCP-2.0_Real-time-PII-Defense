#!/usr/bin/env python3

import csv
import json
import re
import sys

def is_email(text):
    if '@' in text and '.' in text:
        return True
    return False

def is_phone(text):
    digits = ''.join(c for c in text if c.isdigit())
    return len(digits) == 10

def is_aadhar(text):
    digits = ''.join(c for c in text if c.isdigit())
    return len(digits) == 12

def is_passport(text):
    text = text.strip()
    if len(text) == 8:
        return text[0].isalpha() and text[1:].isdigit()
    return False

def is_upi(text):
    return '@' in text and len(text.split('@')) == 2

def is_ip_address(text):
    parts = text.split('.')
    if len(parts) == 4:
        try:
            for part in parts:
                num = int(part)
                if num < 0 or num > 255:
                    return False
            return True
        except:
            return False
    return False

def mask_text(text, keep_first=1, keep_last=1):
    if len(text) <= keep_first + keep_last:
        return 'X' * len(text)
    else:
        return text[:keep_first] + 'X' * (len(text) - keep_first - keep_last) + text[-keep_last:]

def mask_email(email):
    parts = email.split('@')
    if len(parts) == 2:
        username = parts[0]
        domain = parts[1]
        if len(username) > 2:
            masked_username = username[:2] + 'X' * (len(username) - 2)
        else:
            masked_username = 'XX'
        return masked_username + '@' + domain
    return email

def check_if_pii(data):
    pii_count = 0
    has_name = False

    if 'phone' in data and is_phone(str(data['phone'])):
        return True
    if 'contact' in data and is_phone(str(data['contact'])):
        return True
    if 'aadhar' in data and is_aadhar(str(data['aadhar'])):
        return True
    if 'passport' in data and is_passport(str(data['passport'])):
        return True
    if 'upi_id' in data and is_upi(str(data['upi_id'])):
        return True

    if 'name' in data and data['name']:
        name_parts = str(data['name']).split()
        if len(name_parts) >= 2:
            has_name = True
            pii_count += 1

    if 'first_name' in data and 'last_name' in data:
        if data['first_name'] and data['last_name']:
            has_name = True
            pii_count += 1

    if 'email' in data and is_email(str(data['email'])):
        pii_count += 1

    has_pin = False
    has_location = False

    if 'pin_code' in data and data['pin_code']:
        has_pin = True
    if 'address' in data and data['address']:
        has_location = True
    if 'city' in data and data['city']:
        has_location = True

    if has_pin and has_location:
        pii_count += 1

    if has_name or ('email' in data and is_email(str(data['email']))):
        if 'device_id' in data and data['device_id']:
            pii_count += 1
        elif 'ip_address' in data and is_ip_address(str(data['ip_address'])):
            pii_count += 1

    return pii_count >= 2

def redact_data(data, is_pii_data):
    if not is_pii_data:
        return data

    result = {}
    for key, value in data.items():
        result[key] = value

    if 'phone' in result and is_phone(str(result['phone'])):
        phone = str(result['phone'])
        digits = ''.join(c for c in phone if c.isdigit())
        result['phone'] = digits[:2] + 'XXXXXX' + digits[-2:]

    if 'contact' in result and is_phone(str(result['contact'])):
        phone = str(result['contact'])
        digits = ''.join(c for c in phone if c.isdigit())
        result['contact'] = digits[:2] + 'XXXXXX' + digits[-2:]

    if 'aadhar' in result and is_aadhar(str(result['aadhar'])):
        aadhar = str(result['aadhar'])
        digits = ''.join(c for c in aadhar if c.isdigit())
        result['aadhar'] = 'XXXX XXXX ' + digits[-4:]

    if 'passport' in result and is_passport(str(result['passport'])):
        result['passport'] = mask_text(str(result['passport']), 1, 2)

    if 'upi_id' in result and is_upi(str(result['upi_id'])):
        upi = str(result['upi_id'])
        parts = upi.split('@')
        username = parts[0]
        if len(username) > 2:
            masked = username[:2] + 'X' * (len(username) - 2)
        else:
            masked = 'XX'
        result['upi_id'] = masked + '@' + parts[1]

    if 'name' in result:
        name = str(result['name']).strip()
        if name:
            words = name.split()
            masked_words = []
            for word in words:
                if word:
                    masked_words.append(word[0] + 'X' * (len(word) - 1))
            result['name'] = ' '.join(masked_words)

    if 'first_name' in result and result['first_name']:
        name = str(result['first_name'])
        result['first_name'] = name[0] + 'X' * (len(name) - 1)

    if 'last_name' in result and result['last_name']:
        name = str(result['last_name'])
        result['last_name'] = name[0] + 'X' * (len(name) - 1)

    if 'email' in result and is_email(str(result['email'])):
        result['email'] = mask_email(str(result['email']))

    if 'address' in result and result['address']:
        result['address'] = '[REDACTED_PII]'

    if 'city' in result and result['city']:
        result['city'] = '[REDACTED_PII]'

    if 'pin_code' in result:
        result['pin_code'] = '[REDACTED_PII]'

    if 'ip_address' in result and is_ip_address(str(result['ip_address'])):
        ip = str(result['ip_address'])
        parts = ip.split('.')
        parts[-1] = 'x'
        result['ip_address'] = '.'.join(parts)

    if 'device_id' in result and result['device_id']:
        device = str(result['device_id']).replace(' ', '')
        if len(device) > 4:
            result['device_id'] = 'X' * (len(device) - 4) + device[-4:]
        else:
            result['device_id'] = 'XXXX'

    return result

def main():
    if len(sys.argv) < 2:
        print("Please provide input CSV file")
        return

    input_file = sys.argv[1]
    output_file = "redacted_output_vidit_pokhral.csv"

    results = []

    with open(input_file, 'r', encoding='utf-8') as f:
        reader = csv.DictReader(f)
        for row in reader:
            try:
                record_id = row.get('record_id', '')
                data_json_str = row.get('Data_json', '') or row.get('data_json', '')

                try:
                    data = json.loads(data_json_str)
                except:
                    data = {}

                is_pii_data = check_if_pii(data)

                redacted_data = redact_data(data, is_pii_data)

                results.append({
                    'record_id': record_id,
                    'redacted_data_json': json.dumps(redacted_data),
                    'is_pii': str(is_pii_data)
                })

            except Exception as e:
                results.append({
                    'record_id': row.get('record_id', ''),
                    'redacted_data_json': '{}',
                    'is_pii': 'False'
                })

    with open(output_file, 'w', encoding='utf-8', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=['record_id', 'redacted_data_json', 'is_pii'])
        writer.writeheader()
        for result in results:
            writer.writerow(result)

    print(f"Done! Output saved to {output_file}")

if __name__ == "__main__":
    main()
