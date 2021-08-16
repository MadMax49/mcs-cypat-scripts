import sys
import string
from bs4 import BeautifulSoup
from urllib.request import urlopen

illegal_chars = string.ascii_uppercase + ':()'

def get_list(link, get_type):
  url = link
  html = urlopen(url).read().decode("utf-8")
  soup = BeautifulSoup(html, "html.parser")
  users = soup.find('pre').get_text().split()
  services = soup.find('ul').get_text().strip().split('\n')
  admins = []
  auth_users = []
  is_admin = True
  for thing in users:
    if('users' in thing.lower()):
      is_admin = False
    for char in thing:
      if char in illegal_chars:
        break
    else:
      if(is_admin):
        admins.append(thing)
      else:
        auth_users.append(thing)
  services = [thing.lower() for thing in services]
  if(get_type == 'admins'):
    return ';'.join(admins)
  elif(get_type == 'users'):
    return ';'.join(auth_users)
  elif(get_type == 'services'):
    return ';'.join(services)
  else:
    return 0

if __name__ == '__main__':
  link = sys.argv[1]
  get_type = sys.argv[2]
  print(get_list(link, get_type))