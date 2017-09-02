# django-whois
#### Standalone whois app

This app is using server list from https://github.com/whois-server-list/whois-server-list,
for getting root whois server for given domain name.
All root domain names and whois-servers are stored in the db, so it helps reduce queries.

# Installation
* `git clone https://github.com/kantorv/django-whois.git && cd django-whois`
* `virtualenv env`
* `. env/bin/activate`
* `pip install -r requirements.txt`
* `./manage.py makemigrations && manage.py migrate`
* `./manage.py runserver 8080` then point the browser to http://localhost:8080

# USAGE
1:  Parsing XML list and inserting data to db (sqlite in provided sample)
* download xml file to `engine/data/whois-server-list.xml`
* populate the data by calling `engine.utils.parse_data()` 

2:  Performing query to whois server: `engine.utils.get_whois_data(domain_name)`

# Example
* Sample app is included in the repo


# Requirements
* `xmltodict`: for parsing xml data (whois-servers-list.xml)
* `pythonwhois`: just for parsing received data, not for making queries 
* `json2html`: making nice table output for provided json 
* `python-dateutil`: parsing dates helper


# TODO:
* Tests
* Python3 compability
* Move loading and parsing initial xml into separate management command 
* Make it reusable Django app



# License
* MIT

# Donatations
* Please provide your/company.organization name, (and link if needed), otherwise it will be listed as anonimous donatation 

[![paypal](https://www.paypalobjects.com/en_US/i/btn/btn_donateCC_LG.gif)](https://www.paypal.com/cgi-bin/webscr?cmd=_s-xclick&hosted_button_id=EVKMDKQT2WFHG)