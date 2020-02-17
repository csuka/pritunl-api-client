#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import requests, time, uuid, hmac, hashlib, base64, sys, json, random, yaml, pprint, ipaddress, collections

print("Executed script at " + time.ctime())
pp = pprint.PrettyPrinter(indent=4)

# Ignore the SSL warnings
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

# Load pritunl settings from the yaml file
with open("pritunl_settings.yml", "r") as pset:
    try:
        setting = yaml.load(pset, Loader=yaml.FullLoader)
    except yaml.YAMLError as error:
        print('could not load settings file, exiting')
        print(error)
        exit(1)

BASE_URL = 'https://example.org'
API_TOKEN = ''
API_SECRET = ''

if API_TOKEN == '':
  print('please provide an API token, exiting')
  exit(1)
if API_SECRET == '':
  print('Please provide the API secret, exiting')
  exit(1)

# Creating the authentication headers for the API
def auth_request(method, path):
  auth_timestamp = str(int(time.time()))
  auth_nonce = uuid.uuid4().hex
  auth_string = '&'.join([API_TOKEN, auth_timestamp, auth_nonce, method.upper(), path])
  auth_signature = base64.b64encode(hmac.new(
  API_SECRET.encode('utf-8'), auth_string.encode('utf-8'), hashlib.sha256).digest())

  auth_headers = {
        'Auth-Token': API_TOKEN,
        'Auth-Timestamp': auth_timestamp,
        'Auth-Nonce': auth_nonce,
        'Auth-Signature': auth_signature,
        'Content-Type': 'application/json'
  }
  return auth_headers

# function to call the API, provide a method and path, template is optional
def request(method, path, template=None):
  return requests.request(method, BASE_URL + path,
                          headers=auth_request(method, path), 
                          verify=False, data=json.dumps(template))

# function to stop/start the server
def operation(server_id, operation):
  request('PUT', "/server/" + server_id + "/operation/" + operation)


#################################
### Ensure settings are valid ###
#################################
def checks():
  ip_check = ipaddress.ip_network

  # check if keys are not empty
  if not setting['organizations']:
    print('No organization is defined, exiting')
    exit(1)
  if not setting['users']:
    print('No user is defined, exiting')
    exit(1)
  if not setting['servers']:
    print('No server is defined, exiting')
    exit(1)
  if not setting['routes']:
    print('No route is defined, exiting')
    exit(1)
  if not setting['org_to_server']:
    print('No org_to_server is defined, exiting')
    exit(1)
  
  # check whether servers[groups] is defined 
  for item in setting['servers']:
    try:
      item['groups']
    except KeyError:
      print("No servers[groups] is defined for name: '" + item['name'] + "', exiting")
      exit(1)
  
  # check if IP adres is valid network, e.g. 10.0.0.0/24
  for item in setting['servers']:
    ip_check(item['network'])

  for item in setting['routes']:
    for ip in item['network']:
      ip_check(ip)

  # check if organizations match the ones provided users and servers
  for item in setting['users']:
    if item['organization_name'] not in setting['organizations']:
      print("users[organization_name]: '" + item['organization_name'] + "' is not in present in the organizations list, exiting")
      exit(1)

  # check if route server names match actual server names
  server_names = []
  for item in setting['servers']:
    server_names.append(item['name'])
  for item in setting['routes']:
    if item['server'] not in server_names:
        print("routes[server]: '" + item['server']  +  "' is not present in servers[name], please check, exiting")
        exit(1)
  for item in setting['org_to_server']:
    if item['server'] not in server_names:
        print("org_to_server[server]: '" + item['server']  +  "' is not present in servers[name], please check, exiting")
        exit(1)

  # check if a server network is stated as a route network
  for item in setting['servers']:
    for network in setting['routes']:
      if item['name'] == network['server']:
        if item['network'] not in network['network']:
          print("servers[network]: '" + item['network'] + "' is not present in routes[network], please check, exiting")
          exit(1)

  # check if port is valid
  for item in setting['servers']:
    if not 1024 <= item['port'] <= 65535:
      print("Port range: '" + str(item['port']) + "' is not valid for server: '" + item['name'] + "', set it between 1024 and 65535, exiting")
      exit(1)

  print('All pre-checks passed, moving on...\n')


def settings():
  updated = False
  settings = {}
  r = request('GET', '/settings')
  y = r.content
  x = y.decode('utf8').replace("'", '"')
  # Load the JSON to a Python list & dump it back out as formatted JSON
  data = json.loads(x)
  s = json.dumps(data, indent=4, sort_keys=True)
#  print(s)

  template_settings = {
    "acme_domain": None,
    "ap_east_1_access_key": None,
    "ap_east_1_secret_key": None,
    "ap_northeast_1_access_key": None,
    "ap_northeast_1_secret_key": None,
    "ap_northeast_2_access_key": None,
    "ap_northeast_2_secret_key": None,
    "ap_south_1_access_key": None,
    "ap_south_1_secret_key": None,
    "ap_southeast_1_access_key": None,
    "ap_southeast_1_secret_key": None,
    "ap_southeast_2_access_key": None,
    "ap_southeast_2_secret_key": None,
    "auditing": None,
    "auth_api": True,
    "ca_central_1_access_key": None,
    "ca_central_1_secret_key": None,
    "client_reconnect": True,
    "cloud_provider": "none",
    "cn_north_1_access_key": None,
    "cn_north_1_secret_key": None,
    "cn_northwest_1_access_key": None,
    "cn_northwest_1_secret_key": None,
    "default": True,
    "disabled": False,
    "email_from": "k.csuka@viriciti.com",
    "email_password": "a_password",
    "email_server": "email-smtp.eu-west-1.amazonaws.com",
    "email_username": "a_username",
    "eu_central_1_access_key": None,
    "eu_central_1_secret_key": None,
    "eu_north_1_access_key": None,
    "eu_north_1_secret_key": None,
    "eu_west_1_access_key": None,
    "eu_west_1_secret_key": None,
    "eu_west_2_access_key": None,
    "eu_west_2_secret_key": None,
    "eu_west_3_access_key": None,
    "eu_west_3_secret_key": None,
    "id": "some_id",
    "influxdb_uri": None,
    "monitoring": None,
    "oracle_public_key": "",
    "oracle_user_ocid": None,
    "otp_auth": True,
    "otp_secret": "",
    "pin_mode": "optional",
    "public_address": "",
    "public_address6": None,
    "restrict_import": False,
    "reverse_proxy": False,
    "route53_region": None,
    "route53_zone": None,
    "routed_subnet6": None,
    "sa_east_1_access_key": None,
    "sa_east_1_secret_key": None,
    "secret": "",
    "server_cert": "",
    "server_key": "",
    "server_port": 443,
    "sso": "google",
    "sso_authzero_app_id": None,
    "sso_authzero_app_secret": None,
    "sso_authzero_domain": None,
    "sso_azure_app_id": None,
    "sso_azure_app_secret": None,
    "sso_azure_directory_id": None,
    "sso_cache": False,
    "sso_client_cache": False,
    "sso_duo_host": None,
    "sso_duo_mode": None,
    "sso_duo_secret": None,
    "sso_duo_token": None,
    "sso_google_email": "",
    "sso_google_key": "",
    "sso_match": [
        "viriciti.com"
    ],
    "sso_okta_app_id": None,
    "sso_okta_mode": "",
    "sso_okta_token": None,
    "sso_onelogin_app_id": None,
    "sso_onelogin_id": None,
    "sso_onelogin_mode": "",
    "sso_onelogin_secret": None,
    "sso_org": "",
    "sso_radius_host": None,
    "sso_radius_secret": None,
    "sso_saml_cert": None,
    "sso_saml_issuer_url": None,
    "sso_saml_url": None,
    "sso_yubico_client": None,
    "sso_yubico_secret": None,
    "super_user": True,
    "theme": "dark",
    "token": "",
    "us_east_1_access_key": None,
    "us_east_1_secret_key": None,
    "us_east_2_access_key": None,
    "us_east_2_secret_key": None,
    "us_gov_east_1_access_key": None,
    "us_gov_east_1_secret_key": None,
    "us_gov_west_1_access_key": None,
    "us_gov_west_1_secret_key": None,
    "us_west_1_access_key": None,
    "us_west_1_secret_key": None,
    "us_west_2_access_key": None,
    "us_west_2_secret_key": None,
    "username": "kevin",
    "yubikey_id": None
}

  # put settings
#  r = request('PUT', '/settings', template_settings)
#  print(r.content)


def update_org():
  updated = False
  org_list = {}
  
  # call the API via the request function
  r = request('GET', '/organization')
  # get all organization from pritunl and put the values in the org_list dict
  for item in json.loads(r.content):
    org_list[item['name']] = item['id']
  
  # if an organzation is not present in the config file, add it to pritunl
  for org in setting['organizations']:
    if org not in org_list.keys():
      org_template = {
        'name': org,
        'auth_api': False,
        'auth_token': None,
        'auth_secret': None
      }
      request('POST', '/organization', org_template)
      print("Organization added: '" + org + "'\n")
      updated = True
  if not updated:
    print("No organization added\n")

  # delete the org if its not in the config file   
  for org in org_list.keys():
    if org not in setting['organizations']:
      request('DELETE', '/organization/' + org_list[org])
      print("Organization deleted :'" + org + "'\n")
    else:
      print("No organization deleted\n")
      break


def update_routes():
  deleted = False
  updated = False
  server_list = {}
  pritunl_list = {}
  config_list = {}
 
  r = request('GET', '/server')
  for item in json.loads(r.content):
    server_list[item['name']] = item['id']
 
  for server in setting['routes']:
    config_list[server_list[server['server']]] = server['network']
  
  # building pritunl list
  for key, value in server_list.items():
    routes_r = request('GET', '/server/' + value + "/route")
    for item in json.loads(routes_r.content):
      if item['server'] not in pritunl_list:
        pritunl_list[item['server']] = []
      pritunl_list[item['server']].append([item['network'], item['id']])
  
  # delete routes from server
  for server, routes in pritunl_list.items():
    for route in routes:
      if route[0] not in config_list[server]:
        print("Deleted route: '" + str(route[0]) + "'\n")
        operation(server, 'stop')
        request('DELETE', '/server/' + server + "/route/" + route[1])
        operation(server, 'start')
        deleted = True
  if not deleted:
    print('No routes deleted\n')

  pritunl_list = {}
 
  # building pritunl list
  for key, value in server_list.items():
    routes_r = request('GET', '/server/' + value + "/route")
    for item in json.loads(routes_r.content):
      if item['server'] not in pritunl_list:
        pritunl_list[item['server']] = []
      pritunl_list[item['server']].append(item['network'])

  # Adding the routes
  for server in setting['routes']:
    for route in server['network']:
      if route not in pritunl_list[server_list[server['server']]]:
        template_routes = {
          "network": route,
          "comment": None,
          "metric": None,
          "nat": False, 
          "nat_interface": None,
          "nat_netmap": None,
          "advertise": None,
          "vpc_region": None,
          "vpc_id": None,
          "net_gateway": False
        }
        serverId = server_list[server['server']]
        operation(serverId, 'stop')
        request('POST', '/server/' + serverId + "/route", template_routes)
        print("Added route: '" + str(route) + "' to server: '" + server['server'] + "'\n")
        operation(serverId, 'start')
        updated = True
  if not updated:
    print('No routes added\n')
      
def org_to_server():
  updated = False
  deleted = False
  pritunl_server_list = {}
  config_server_list = {}
  org_list = {}
  server_id_name = {}
  server_name_id = {}

  r = request('GET', '/server')
  for item in json.loads(r.content):
    server_name_id[item['name']] = item['id']
    server_id_name[item['id']] = item['name']

  for key, value in server_name_id.items():
    server_r = request('GET', "/server/" + value + "/organization")
    for item in json.loads(server_r.content):
      if item['server'] not in pritunl_server_list:
        pritunl_server_list[item['server']] = []
      pritunl_server_list[item['server']].append(item['name'])

  r = request('GET', '/organization')
  for item in json.loads(r.content):
    org_list[item['name']] = item['id']

  for server in setting['org_to_server']:
    config_server_list[server['server']] = server['org']
  
  for server in config_server_list:
    for org in config_server_list[server]:
      if server_name_id[server] not in pritunl_server_list.keys():
        serverId = server_name_id[server]
        operation(serverId, 'stop')
        request('PUT', '/server/' + serverId + "/organization/" + org_list[org])
        print("Attached organization: '" + org + "' to server: '" + server + "'\n")
        operation(serverId, 'start')
        updated = True
      elif org not in pritunl_server_list[server_name_id[server]]:
        serverId = server_name_id[server]
        operation(serverId, 'stop')
        request('PUT', '/server/' + serverId + "/organization/" + org_list[org])
        print("Attached organization: '" + org + "' to server: '" + server + "'\n")
        operation(serverId, 'start')
        updated = True
  if not updated:
    print('No organization attached to a server\n')


  for server in pritunl_server_list:
    for org in pritunl_server_list[server]:
      if org not in config_server_list[server_id_name[server]]:
        operation(server, 'stop')
        request('DELETE', '/server/' + server + "/organization/" + org_list[org])
        print("Deleted organization: '" + org + "' from server: '" + server_id_name[server] + "'\n")
        operation(server, 'start')
        deleted = True
  if not deleted:
    print('No organization deleted from a server\n')
 

def update_user():
  updated = False
  deleted = False
  created = False
  user_list = {}
  second_user_list = {}
  org_list = {}

  org_r = request('GET', '/organization')

  # get all organizations from pritunl and put the values in the org_list dict
  for item in json.loads(org_r.content):
    org_list[item['name']] = item['id']
  
  # for every organization ID, get all the users and their UserId
  for key, v in org_list.items():
    user_r = request('GET', '/user/' + v)
    for item in json.loads(user_r.content):
      user_list[item['name']] = [item['id'], item['organization']]
  
  pritunl_users = []
  for item in setting['users']:
    pritunl_users.append(item['name'])
  
  # update users
  server_users = []
  for key, v in org_list.items():
    user_r = request('GET', '/user/' + v)
    x = (json.loads(user_r.content))
    for item in x:
      server_users.append(item)

  for user in server_users:
    if user['name'] in pritunl_users:
      for config in setting['users']:
        if config['name'] == user['name']:
          for option in config:
            if collections.Counter(config['groups']) == collections.Counter(user['groups']):
              config['groups'] = user['groups']
            try:
              config['dns_servers']
              if collections.Counter(config['dns_servers']) == collections.Counter(user['dns_servers']):
                config['dns_servers'] = user['dns_servers']
            except KeyError:
              pass
            if user[option] != config[option]:
              if option == 'organization_name':
                request('DELETE', '/user/' + user_list[user['name']][1] + "/" + user_list[user['name']][0])     
              else:
                print("User: '" + user['name'] + "' with option: '" + option + "' had value '" + str(user[option]) + "'\n")
                user[option] = config[option]
                print("Now has updated value: '" + str(user[option]) + "'\n")
                updated = True
      request('PUT', '/user/' + user_list[user['name']][1] + "/" + user_list[user['name']][0], user)
  if not updated:
    print('No users updated\n')

  # delete users
  for item in user_list.keys():
    if item not in pritunl_users:
      print("Deleted user: '" + item + "'\n")
      request('DELETE', '/user/' + user_list[item][1] + "/" + user_list[item][0])
      deleted = True
  if not deleted:
    print('No users deleted\n')

  # again, retrieve the all the users and their UserIds, because one might be deleted if it
  # switched from organization_name
  for key, v in org_list.items():
    user_r = request('GET', '/user/' + v)
    for item in json.loads(user_r.content):
      second_user_list[item['name']] = [item['id'], item['organization']]

  # add users, with refreshed user ids
  for key in setting['users']:
    if key['name'] not in second_user_list:
      user_template = {
             "name": "test",
             "email": "someone@domain.com",
             "auth_type": "local",
             "yubico_id": None,
             "groups": ['a_group', 'b_group'],
             "pin": "123456",
             "disabled": False,
             "network_links": [],
             "bypass_secondary": False,
             "client_to_client": False,
             "dns_servers": ["10.1.0.2"],
             "dns_suffix": "a_suffix",
             "port_forwarding": []
        }
      user_template.update(key)
      for org_name, org_id in org_list.items():
        if user_template['organization_name'] == org_name:
          print("Added user: '" + key['name'] + "' to organization: '" + user_template['organization_name'] + "'\n")
          del user_template['organization_name']
          request('POST', '/user/' + org_id, user_template)
          user_template.update(key)
          created = True
  if not created:
    print('No users created\n')


def update_servers():
  updated = False
  deleted = False
  created = False
  server_list = {}

  # place the name + id in dict server_list
  r = request('GET', '/server')
  for item in json.loads(r.content):
    server_list[item['name']] = item['id']

  #add servers
  for serv in setting['servers']:
    server_template = {
                'name': "test",
                'network': '10.1.1.0/24',
                'groups': ['a_group'],
                'network_mode': 'tunnel',
                'network_start': None,
                'network_end': None,
                'restrict_routes': True,
                'ipv6': False,
                'ipv6_firewall': True,
                'bind_address': None,
                'port': 1027,
                'protocol': 'tcp',
                'dh_param_bits': 1536,
                'multi_device': False,
                'dns_servers': ['8.8.8.8'],
                'search_domain': '',
                'inter_client': True,
                'otp_auth': False,
                'cipher': 'aes128',
                'hash': 'sha1',
                'jumbo_frames': False,
                'lzo_compression': False,
                'inter_client': True,
                'ping_interval': 10,
                'ping_timeout': 60,
                'link_ping_interval': 1,
                'link_ping_timeout': 5,
                'inactive_timeout': 259200, #disconnect users after x seconds of inactivity
                'allowed_devices': 'Any',
                'max_clients': 100,
                'replica_count': 1,
                'vxlan': True,
                'dns_mapping': False,
                'debug': False,
                'policy': None,
                'block_outside_dns': False,
                'pre_connect_msg': 'hi',
                'mss_fix': '',
      }
    if serv['name'] not in server_list.keys():
      for param in serv:
        server_template[param] = serv[param]

      add_server = request('POST', '/server', server_template).content.decode(encoding='UTF-8')
      if "error_msg" in add_server:
        print("There was an error by adding server: '" + serv['name'] + "'")
        print(add_server)
        print('Ensure the settings are valid, exiting')
        exit(1)
      print("Server added: '" + serv['name'] + "'\n")
      created = True
  if not created:
    print('No server created\n')

  # delete server if its not present in the config file
  server_name = [] 
  for item in setting['servers']:
    server_name.append(item['name'])
  
  for serv in server_list.keys():
    if serv not in server_name:
      request('DELETE', '/server/' + server_list[serv])
      print("Server deleted: '" + serv + "'\n")
      deleted = True
  if not deleted:
    print('No server deleted\n')

  # update settings
  # again request servers, because a server could be deleted/added
  r = request('GET', '/server')
  pritunl_server_values = json.loads(r.content)
  for server in pritunl_server_values:
    if server['name'] in server_name:
      for config in setting['servers']:
        if config['name'] == server['name']:
           for option in config:
             if collections.Counter(config['groups']) == collections.Counter(server['groups']):
               config['groups'] = server['groups']
             try:
               config['dns_servers']
               if collections.Counter(config['dns_servers']) == collections.Counter(server['dns_servers']):
                 config['dns_servers'] = server['dns_servers']
             except KeyError:
               pass
             if server[option] != config[option]:
               print("For server name: '" + server['name'] + "' with option: '" + option + "' had value: '" + str(server[option]) + "'")
               server[option] = config[option]
               print("Now has updated value: '" + str(server[option]) + "'\n")
               for ids in pritunl_server_values:
                 operation(ids['id'], 'stop')
                 request('PUT', '/server/' + ids['id'], server)
                 operation(ids['id'], 'start')
                 updated = True
  if not updated:
    print('No servers updated\n')


checks()
#settings()
update_org()
update_user()
update_servers()
org_to_server()
update_routes()

print('Done, good job!')

