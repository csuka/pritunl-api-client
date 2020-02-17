Pritunl management
------------------

Developed an API client for Pritunl, written in Python3.
Tested to work with Pritunl v1.29.2276.91 (Feb 2020)

It manages:
 - organizations
 - users
 - servers
 - organizations to servers
 - routes

We chose not to manage administrators, because a password has to be provided.
This isn't feasible in a shared enviroment.

The script *does not* manage firewall rules on the host, since that is outside the scope of the API.

## Installation

In Pritunl Enterprise, go to 'Administrators' => Click on an admin user. Enable API access, copy the Token & Secret.

 - Python3 (only default libraries are used)
 - Pritunl Enterprise (for API access)
 - Set the URL, Token and Secret in `pritunl_api_client.py`

## Configuration

The configuration is set in `pritunl_settings.yml`.

We created several checks to validate the configuration.
The checks aren't 100% fail proof, but should cover the most common misconfigurations.

Route 0.0.0.0/0 is always deleted, unless specified.

Important: *When an object has an update, e.g. servers settings are updated, the server will stop, update the settings, and start again*

The following configuration file covers the basics. 
All the possible settings can be found on the [pritunl API handlers repository](https://github.com/pritunl/pritunl-web/tree/master/handlers):



```yaml
---
organizations:
  - test_org_one
  - test_org_two

users:
  - name: mynameisjeff
    groups: ['somegroup']
    email: "jeff@yes.com"
    disabled: False
    client_to_client: False
    organization_name: test_org_one
  - name: mynameissomeone
    groups: ['a_group_for_me', 'someone']
    email: "yesyes@me.com"
    disabled: False
    organization_name: test_org_two

# If a server is updated for its settings,
# it will be stopped -> update settings -> started
servers:
  - name: server_for_dev
    groups: ['a_group_for_me', 'somegroup']
    port: 26743
    network: '10.75.0.0/24'
  - name: server_for_me
    groups: ['a_group_for_me']
    port: 39472
    network: '10.80.0.0/24'
    dns_servers: ['8.9.10.1', '10.69.5.0']

# Route 0.0.0.0/0 is always deleted, unless specified
# If a route is updated or added to a server,
# it will be stopped -> routes updated -> started
routes:
  - server: server_for_dev
    network:
      - "10.75.0.0/24"
      - "10.69.69.0/24"
      - "10.69.0.0/24"
  - server: server_for_me
    network:
      - "10.80.0.0/24"
      - "10.0.108.0/24"

# If an organization is updated for a server,
# It will be stopped -> org. is updated -> started
org_to_server:
  - server: server_for_dev
    org: ['test_org_one']
  - server: server_for_me
    org: ['test_org_one', 'test_org_two']
```


Example output:

```bash
[username@hostname-1 ~]$ ./pritunl_api_client.py 
Executed script at Fri Feb  7 09:57:05 2020
All pre-checks passed, moving on...

Organization added: 'test_org_one'

Organization added: 'test_org_two'

Organization deleted :'first_org'

Organization deleted :'just'

Organization deleted :'oui'

Organization deleted :'second_org'

No users updated

No users deleted

Added user: 'mynameisjeff' to organization: 'test_org_one'

Added user: 'mynameissomeone' to organization: 'test_org_two'

Server added: 'server_for_dev'

Server added: 'server_for_me'

Server deleted: 'server_one'

Server deleted: 'server_two'

No servers updated

Attached organization: 'test_org_one' to server: 'server_for_dev'

Attached organization: 'test_org_one' to server: 'server_for_me'

Attached organization: 'test_org_two' to server: 'server_for_me'

No organization deleted from a server

Deleted route: '0.0.0.0/0'

Deleted route: '0.0.0.0/0'

Added route: '10.69.69.0/24' to server: 'server_for_dev'

Added route: '10.69.0.0/24' to server: 'server_for_dev'

Added route: '10.0.108.0/24' to server: 'server_for_me'

Done, good job!
```

## TODO

 - Solve an issue when no correct users settings are set, e.g. set a pin
 - Ensure extra org options are included
 - Org update(PUT) instead of del/add
 - include settings
 - send mail when user is created
 - extend API client with more objects, e.g. serverhost(GET|PUT|DELETE)
