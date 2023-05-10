from PyQt5 import QtCore, QtGui, QtWidgets
from PyQt5.QtCore import Qt
from tkinter import *
from tkinter.ttk import *
from tkinter import messagebox
import psycopg2 as ps
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from pathlib import Path
import logging
import concurrent.futures
import getopt
import sys
import os

class ProjectFile(Tk):
	def __init__(self):
		super().__init__()
		# self.wm_attributes('-toolwindow', 'True')
		self.protocol('WM_DELETE_WINDOW', self.on_closing)
		style = Style()
		style.configure('TButton', font = ('calibri', 11, 'bold', 'underline'), foreground = 'blue')
		self.title('Iş sahypasy')
		self.geometry('700x400')
		self.tk_setPalette('#345')
		self.menubar = Menu(bg = 'skyblue', fg = 'white')
		self.file = Menu(self.menubar, tearoff = False, background = 'white', foreground = 'brown')
		self.edit = Menu(self.menubar, tearoff = False, background = 'white', foreground = 'brown')
		self.aboutus = Menu(self.menubar, tearoff = 0, background = 'white', foreground = 'brown')
		self.file.add_command(label = 'Şifrlenen we Deşifrirlenen faýyllaryň ýeri', command = lambda: messagebox.showinfo('Faýyllaryň ýeri', 'Siziň faýyllaryňyz "C:\Program Files\File Encrypter" adresinde saklanýar! '))
		self.file.add_separator()
		self.file.add_command(label = 'Çykmak', command = self.on_closing)
		self.edit.add_command(label = 'Kömek', command = self.help_me)
		self.edit.add_command(label = 'Bu programma hakynda', command = self.about_program)
		self.menubar.add_cascade(label = 'Sazlamalar', menu = self.file)
		self.aboutus.add_command(label = 'Habarlaşmak', command = self.tell_me)
		self.menubar.add_cascade(label = 'Programmma barada', menu = self.edit)
		self.menubar.add_cascade(label = 'Biz barada', menu = self.aboutus)
		self.combo = Label(text = '\nAşakdaky gutudan faýlyň formatyny saýlaň!', font = 'Times 12 italic', foreground = 'white', background = '#345').pack()
		st = StringVar()
		self.formatchoosen = Combobox(self, width = 30, textvariable = st, background = 'skyblue', foreground = 'red')
		self.formatchoosen['values'] = ('pdf',
										'doc docx',
										'xls xlsx',
										'ppt pptx',
										'txt',
										'vcf',
										'mp3',
										'mp4',
										'jpg',
										'png',
										'ico',
										'exe',
										'deb',
										'iso',
										'apk',
										'rar',
										'db',
										'csv',
										'dll')
		self.formatchoosen.pack(expand = True) 
		self.formatchoosen.current(1)
		self.clothe = Label(text = 'Faýyllary şifrlemek ýa-da deşifrirlemek üçin parol ýazyň!', font = 'Times 12 italic', foreground = 'white', background = '#345').pack()
		self.input_text = StringVar()
		self.style = Style()
		self.style.configure('TEntry', foreground = 'green')
		self.give_password = Entry(self, textvariable = self.input_text, justify = CENTER, font = ('courier', 10, 'bold'), width = 35)
		self.give_password.pack(expand = True)
		self.space = Label(text = 'Eger-de faýllary şifrlemek isleseňiz degişli papka faýllary kopýalaň we Şifrlemek düwmesine basyň!\n(Hökman format saýlamaly!)', font = 'Times 12 italic', foreground = 'white', background = '#345').pack()
		self.decodebtn = Button(self, text = 'Şifrlemek', cursor = 'hand2', style = 'TButton', command = self.encrypt_files0)
		self.decodebtn.pack(expand = True)
		self.space2 = Label(text = 'Eger-de faýllary deşifrirlemek isleseňiz degişli papka faýllary kopýalaň we Deşifrirlemek düwmesine basyň!\n(format saýlamak gerek däl.)', font = 'Times 12 italic', foreground = 'white', background = '#345').pack()
		self.encodebtn = Button(self, text = 'Deşifrirlemek', cursor = 'hand2', style = 'TButton',command = self.decrypt_files0)
		self.encodebtn.pack(expand = True)
		self.config(menu = self.menubar)

	def on_closing(self):
		if messagebox.askokcancel('Çykyş', 'Programmadan çykmak isleýäňizmi?'):
			self.destroy()

	def mixed_password(self):
		self.cipher = '' 
		for i in self.give_password.get():
			self.cipher += (chr(ord(i) + 9))
		return self.cipher

	def encrypt_files0(self):
		BLOCK_SIZE = 16
		BLOCK_MULTIPLIER = 100

		global ALPHABET
		ALPHABET = "ABCÇDEÄFGHIJKLMNŇOÖPQRSŞTUÜVWXYÝZabcçdeäfghijklmnňoöpqrsştuüvwxyýz.1234567890"

		maxWorker = 10

		def generateKey(length, key):
		    retKey = str()
		    for i in range(length):
		        retKey += key[i % len(key)]
		    return retKey

		def vencrypt(msg, key):
		    key = generateKey(len(msg), key)
		    ciphertext = "E"
		    for index, char in enumerate(msg):
		        ciphertext += ALPHABET[(ALPHABET.find(key[index]) + ALPHABET.find(char)) % len(ALPHABET)]
		    return ciphertext

		def vdecrypt(ciphertext, key):
		    key = generateKey(len(ciphertext), key)
		    msg = str()
		    ciphertext = ciphertext[1:]
		    for index, char in enumerate(ciphertext):
		        msg += ALPHABET[(ALPHABET.find(char) - ALPHABET.find(key[index])) % len(ALPHABET)]
		    return msg

		def encryptFile(filePath, password):
		    try:
		        logging.info("Started encoding: " + filePath.resolve().as_posix())
		        hashObj = SHA256.new(password.encode('utf-8'))
		        hkey = hashObj.digest()
		        encryptPath = Path(filePath.parent.resolve().as_posix() + "/" + vencrypt(filePath.name, password) + ".enc")
		        if encryptPath.exists():
		            encryptPath.unlink()
		        with open(filePath, "rb") as input_file, encryptPath.open("ab") as output_file:
		            content = b''
		            content = input_file.read(BLOCK_SIZE*BLOCK_MULTIPLIER)

		            while content != b'':
		                output_file.write(encrypt(hkey, content))
		                content = input_file.read(BLOCK_SIZE*BLOCK_MULTIPLIER)

		            logging.info("Encoded " + filePath.resolve().as_posix())
		            logging.info("To " +encryptPath.resolve().as_posix())
		    except Exception as e:
		        print(e)

		def decryptFile(filePath, password):
		    logging.info("Started decoding: " + filePath.resolve().as_posix())
		    try:
		        hashObj = SHA256.new(password.encode('utf-8'))
		        hkey = hashObj.digest()
		        decryptFilePath = Path(filePath.parent.resolve().as_posix() + "/" + vdecrypt(filePath.name, password)[:-4])
		        if decryptFilePath.exists():
		            decryptFilePath.unlink()
		        with filePath.open("rb") as input_file, decryptFilePath.open("ab") as output_file:
		            values = input_file.read(BLOCK_SIZE*BLOCK_MULTIPLIER)
		            while values != b'':
		                output_file.write(decrypt(hkey, values))
		                values = input_file.read(BLOCK_SIZE*BLOCK_MULTIPLIER)

		        logging.info("Decoded: " + filePath.resolve().as_posix()[:-4])
		        logging.info("TO: " + decryptFilePath.resolve().as_posix() )

		    except Exception as e:
		        print(e)

		def pad(msg, BLOCK_SIZE, PAD):
		    return msg + PAD * ((BLOCK_SIZE - len(msg) % BLOCK_SIZE) % BLOCK_SIZE)

		def encrypt(key, msg):
		    PAD = b'\0'
		    cipher = AES.new(key, AES.MODE_ECB)
		    result = cipher.encrypt(pad(msg, BLOCK_SIZE, PAD))
		    return result

		def decrypt(key, msg):
		    PAD = b'\0'
		    decipher = AES.new(key, AES.MODE_ECB)
		    pt = decipher.decrypt(msg)
		    for i in range(len(pt)-1, -1, -1):
		        if pt[i] == PAD:
		            pt = pt[:i]
		        else:
		            break
		    return pt

		def getMaxLen(arr):
		    maxLen = 0
		    for elem in arr:
		        if len(elem) > maxLen:
		            maxLen = len(elem)
		    return maxLen

		def getTargetFiles(fileExtension):
		    fileExtensions = []
		    if len(fileExtension) == 0:
		        fileExtensions.append("*")
		    else:
		        for Extension in fileExtension:
		            fileExtensionFormatted = "*."
		            for char in Extension:
		                fileExtensionFormatted += "[" + char + "]"
		            fileExtensions.append(fileExtensionFormatted)

		    return fileExtensions

		def generateEncryptThreads(fileExtensions, password, removeFiles, path):
		    fileExtensionFormatted = getTargetFiles(fileExtensions)
		    filePaths = []
		    for fileExtension in fileExtensionFormatted:
		        filePaths = filePaths + list(Path(path).rglob(fileExtension))

		    with concurrent.futures.ThreadPoolExecutor(max_workers=maxWorker) as executor:
		        for filePath in filePaths:
		            executor.submit(encryptFile, *(filePath, password))
		    if removeFiles:
		        for filePath in filePaths:
		            filePath.unlink()

		def generateDecryptThreads(password, removeFiles, path):
		    filePaths = list(Path(path).rglob("*.[eE][nN][cC]"))
		    with concurrent.futures.ThreadPoolExecutor(max_workers=maxWorker) as executor:
		        for filePath in filePaths:
		            executor.submit(decryptFile, *(filePath, password))
		    if removeFiles:
		        for filePath in filePaths:
		            filePath.unlink()

		def removeEncryptedFiles(path):
		    filePaths = list(Path(path).rglob("*.[eE][nN][cC]"))
		    for filePath in filePaths:
		            filePath.unlink()

		def removeExFiles(fileExtensions, path):
		    fileExtensionFormatted = getTargetFiles(fileExtensions)
		    filePaths = []
		    for fileExtension in fileExtensionFormatted:
		        filePaths = filePaths + list(Path(path).rglob(fileExtension))
		    for filePath in filePaths:
		        filePath.unlink()

		if 1 == 1:
		    format = "%(asctime)s: %(message)s"
		    logging.basicConfig(format=format, level=logging.INFO,
		                        datefmt="%H:%M:%S")
		    if len(sys.argv[1:]) < 1:
		        mode = 1
		        password = self.mixed_password()
		        passwordConfirm = self.mixed_password()
		        if mode == 1 or mode == 2:
		            password = self.mixed_password()
		            passwordConfirm = self.mixed_password()
		        if password != passwordConfirm:
		            logging.error("Passwords not matching")
		            exit()
		        if mode == 1 and len(self.give_password.get()) != 0:
		            fileExtension = self.formatchoosen.get()
		            fileExtensions = fileExtension.split()
		            removeFiles = 'n'
		            if removeFiles[0].upper() == 'Y':
		                removeFiles = True
		            else:
		                removeFiles = False
		            my_path = r'C:\Program Files\File Encrypter'
		            path = my_path
		            generateEncryptThreads(fileExtensions, password, removeFiles, path)
		            messagebox.showinfo('Düşündiriş', 'Faýyllaryňyz üstünlikli ýagdaýda şifrlendi!')
		        elif mode == 2 or len(self.give_password.get()) == 0:
		            messagebox.showinfo('Düşündiriş', 'Faýyllary şifrlemek üçin parol ýazyň we ony ýatda saklaň!')
		            removeFiles = 'n'
		            if removeFiles[0].upper() == 'Y':
		                removeFiles = True
		            else:
		                removeFiles = False
		            my_path = r'C:\Program Files\File Encrypter'
		            path = my_path
		            generateDecryptThreads(password, removeFiles, path)
		        elif mode == 3:
		            path = my_path
		            removeEncryptedFiles(path)
		        elif mode == 4:
		            extensions = self.formatchoosen.get()
		            fileExtensions = extensions.split()
		            path = my_path
		            removeExFiles(fileExtensions, path)
		    else:
		        removeFiles = False
		        password = ""
		        mode = 0
		        opts, args = getopt.getopt(sys.argv[1:], "rm:p:w:vd:h")

		        for opt, arg in opts:
		            if opt == '-r':
		                removeFiles = True
		            elif opt == '-m':
		                mode = int(arg)
		            elif opt == '-w':
		                maxWorker = int(arg)
		            elif opt == '-p':
		                password = arg
		            elif opt == '-d':
		                path = arg
		            elif opt == '-h':
		                pass
		                exit()
		        if mode == 0 or (password == "" and mode in (1,2,5)):
		            print("Missing arguments!\nType -h as argument to get help Page.")
		            exit()
		        if mode == 1:
		            generateEncryptThreads(args, password, removeFiles, path)
		        elif mode == 2:
		            generateDecryptThreads(password, removeFiles, path)
		        elif mode == 3:
		            removeEncryptedFiles()
		        elif mode == 4:
		            # print(args)
		            if args == []:
		                filePaths = list(Path(path).rglob("*.*"))
		                removePaths = list()
		                for index, filePath in enumerate(filePaths):
		                    if not ".enc" in filePath.name and not ".py" in filePath.name:
		                        removePaths.append(filePath)
		                try:
		                    for removeFilePath in removePaths:
		                        removeFilePath.unlink()
		                except Exception as e:
		                    print(e)
		            else:
		                removeExFiles(args)
		        elif mode == 5:
		            encryptFile(Path(args), password)

	def decrypt_files0(self):
		BLOCK_SIZE = 16
		BLOCK_MULTIPLIER = 100

		global ALPHABET
		ALPHABET = "ABCÇDEÄFGHIJKLMNŇOÖPQRSŞTUÜVWXYÝZabcçdeäfghijklmnňoöpqrsştuüvwxyýz.1234567890"

		maxWorker = 10

		def generateKey(length, key):
		    retKey = str()
		    for i in range(length):
		        retKey += key[i % len(key)]
		    return retKey

		def vencrypt(msg, key):
		    key = generateKey(len(msg), key)
		    ciphertext = "E"
		    for index, char in enumerate(msg):
		        ciphertext += ALPHABET[(ALPHABET.find(key[index]) + ALPHABET.find(char)) % len(ALPHABET)]
		    return ciphertext

		def vdecrypt(ciphertext, key):
		    key = generateKey(len(ciphertext), key)
		    msg = str()
		    ciphertext = ciphertext[1:]
		    for index, char in enumerate(ciphertext):
		        msg += ALPHABET[(ALPHABET.find(char) - ALPHABET.find(key[index])) % len(ALPHABET)]
		    return msg

		def encryptFile(filePath, password):
		    try:
		        logging.info("Started encoding: " + filePath.resolve().as_posix())
		        hashObj = SHA256.new(password.encode('utf-8'))
		        hkey = hashObj.digest()
		        encryptPath = Path(filePath.parent.resolve().as_posix() + "/" + vencrypt(filePath.name, password) + ".enc")
		        if encryptPath.exists():
		            encryptPath.unlink()
		        with open(filePath, "rb") as input_file, encryptPath.open("ab") as output_file:
		            content = b''
		            content = input_file.read(BLOCK_SIZE*BLOCK_MULTIPLIER)

		            while content != b'':
		                output_file.write(encrypt(hkey, content))
		                content = input_file.read(BLOCK_SIZE*BLOCK_MULTIPLIER)

		            logging.info("Encoded " + filePath.resolve().as_posix())
		            logging.info("To " +encryptPath.resolve().as_posix())
		    except Exception as e:
		        print(e)

		def decryptFile(filePath, password):
		    logging.info("Started decoding: " + filePath.resolve().as_posix())
		    try:
		        hashObj = SHA256.new(password.encode('utf-8'))
		        hkey = hashObj.digest()
		        decryptFilePath = Path(filePath.parent.resolve().as_posix() + "/" + vdecrypt(filePath.name, password)[:-4])
		        if decryptFilePath.exists():
		            decryptFilePath.unlink()
		        with filePath.open("rb") as input_file, decryptFilePath.open("ab") as output_file:
		            values = input_file.read(BLOCK_SIZE*BLOCK_MULTIPLIER)
		            while values != b'':
		                output_file.write(decrypt(hkey, values))
		                values = input_file.read(BLOCK_SIZE*BLOCK_MULTIPLIER)

		        logging.info("Decoded: " + filePath.resolve().as_posix()[:-4])
		        logging.info("TO: " + decryptFilePath.resolve().as_posix() )

		    except Exception as e:
		        print(e)

		def pad(msg, BLOCK_SIZE, PAD):
		    return msg + PAD * ((BLOCK_SIZE - len(msg) % BLOCK_SIZE) % BLOCK_SIZE)

		def encrypt(key, msg):
		    PAD = b'\0'
		    cipher = AES.new(key, AES.MODE_ECB)
		    result = cipher.encrypt(pad(msg, BLOCK_SIZE, PAD))
		    return result

		def decrypt(key, msg):
		    PAD = b'\0'
		    decipher = AES.new(key, AES.MODE_ECB)
		    pt = decipher.decrypt(msg)
		    for i in range(len(pt)-1, -1, -1):
		        if pt[i] == PAD:
		            pt = pt[:i]
		        else:
		            break
		    return pt

		def getMaxLen(arr):
		    maxLen = 0
		    for elem in arr:
		        if len(elem) > maxLen:
		            maxLen = len(elem)
		    return maxLen

		def getTargetFiles(fileExtension):
		    fileExtensions = []
		    if len(fileExtension) == 0:
		        fileExtensions.append("*")
		    else:
		        for Extension in fileExtension:
		            fileExtensionFormatted = "*."
		            for char in Extension:
		                fileExtensionFormatted += "[" + char + "]"
		            fileExtensions.append(fileExtensionFormatted)

		    return fileExtensions

		def generateEncryptThreads(fileExtensions, password, removeFiles, path):
		    fileExtensionFormatted = getTargetFiles(fileExtensions)
		    filePaths = []
		    for fileExtension in fileExtensionFormatted:
		        filePaths = filePaths + list(Path(path).rglob(fileExtension))

		    with concurrent.futures.ThreadPoolExecutor(max_workers=maxWorker) as executor:
		        for filePath in filePaths:
		            executor.submit(encryptFile, *(filePath, password))
		    if removeFiles:
		        for filePath in filePaths:
		            filePath.unlink()

		def generateDecryptThreads(password, removeFiles, path):
		    filePaths = list(Path(path).rglob("*.[eE][nN][cC]"))
		    with concurrent.futures.ThreadPoolExecutor(max_workers=maxWorker) as executor:
		        for filePath in filePaths:
		            executor.submit(decryptFile, *(filePath, password))
		    if removeFiles:
		        for filePath in filePaths:
		            filePath.unlink()

		def removeEncryptedFiles(path):
		    filePaths = list(Path(path).rglob("*.[eE][nN][cC]"))
		    for filePath in filePaths:
		            filePath.unlink()

		def removeExFiles(fileExtensions, path):
		    fileExtensionFormatted = getTargetFiles(fileExtensions)
		    filePaths = []
		    for fileExtension in fileExtensionFormatted:
		        filePaths = filePaths + list(Path(path).rglob(fileExtension))
		    for filePath in filePaths:
		        filePath.unlink()

		if 1 == 1:
		    format = "%(asctime)s: %(message)s"
		    logging.basicConfig(format=format, level=logging.INFO,
		                        datefmt="%H:%M:%S")
		    if len(sys.argv[1:]) < 1:
		        mode = 2
		        password = self.mixed_password()
		        passwordConfirm = self.mixed_password()
		        if mode == 1 or mode == 2:
		            password = self.mixed_password()
		            passwordConfirm = self.mixed_password()
		        if password != passwordConfirm:
		            logging.error("Passwords not matching")
		            exit()
		        if mode == 1:
		            fileExtension = self.formatchoosen.get()
		            fileExtensions = fileExtension.split()
		            removeFiles = 'n'
		            if removeFiles[0].upper() == 'Y':
		                removeFiles = True
		            else:
		                removeFiles = False
		            my_path = r'C:\Program Files\File Encrypter'
		            path = my_path
		            generateEncryptThreads(fileExtensions, password, removeFiles, path)
		        elif mode == 2 and len(self.give_password.get()) != 0:
		            removeFiles = 'n'
		            if removeFiles[0].upper() == 'Y':
		                removeFiles = True
		            else:
		                removeFiles = False
		            my_path = r'C:\Program Files\File Encrypter'
		            path = my_path
		            generateDecryptThreads(password, removeFiles, path)
		            messagebox.showinfo('Düşündiriş', 'Faýyllaryňyz üstünlikli ýagdaýda deşifrirlendi!')
		        elif mode == 3 or len(self.give_password.get()) == 0:
		            messagebox.showinfo('Düşündiriş', 'Faýyllary deşifrirlemek üçin şifrlän wagtyňyzdaky paroluňyzy ýazyň!')
		            my_path = r'C:\Program Files\File Encrypter'
		            path = my_path
		            removeEncryptedFiles(path)
		        elif mode == 4:
		            extensions = self.formatchoosen.get()
		            fileExtensions = extensions.split()
		            path = my_path
		            removeExFiles(fileExtensions, path)
		    else:
		        removeFiles = False
		        password = ""
		        mode = 0
		        opts, args = getopt.getopt(sys.argv[1:], "rm:p:w:vd:h")

		        for opt, arg in opts:
		            if opt == '-r':
		                removeFiles = True
		            elif opt == '-m':
		                mode = int(arg)
		            elif opt == '-w':
		                maxWorker = int(arg)
		            elif opt == '-p':
		                password = arg
		            elif opt == '-d':
		                path = arg
		            elif opt == '-h':
		                pass
		                exit()
		        if mode == 0 or (password == "" and mode in (1,2,5)):
		            print("Missing arguments!\nType -h as argument to get help Page.")
		            exit()
		        if mode == 1:
		            generateEncryptThreads(args, password, removeFiles, path)
		        elif mode == 2:
		            generateDecryptThreads(password, removeFiles, path)
		        elif mode == 3:
		            removeEncryptedFiles()
		        elif mode == 4:
		            # print(args)
		            if args == []:
		                filePaths = list(Path(path).rglob("*.*"))
		                removePaths = list()
		                for index, filePath in enumerate(filePaths):
		                    if not ".enc" in filePath.name and not ".py" in filePath.name:
		                        removePaths.append(filePath)
		                try:
		                    for removeFilePath in removePaths:
		                        removeFilePath.unlink()
		                except Exception as e:
		                    print(e)
		            else:
		                removeExFiles(args)
		        elif mode == 5:
		            encryptFile(Path(args), password)

	def help_me(self):
		messagebox.showinfo('Kömek', 'Bu programmada mesele ýüze çykan halatynda\n "Security@gmail.com" adresinden habarlaşyp bilersiňiz!')

	def about_program(self):
		messagebox.showinfo('Bu programma hakynda!', 'Bu Programma elektron maglumatlaryň\nhowpsuzlygyny üpjün etmek maksatly döredilendir!\nÝüze çykyp biljek soraglaryňyzy we teklipleriňizi "Security@gmail.com" adresine ýazyp bilersiňiz!')

	def tell_me(self):
		messagebox.showinfo('Habarlaşmak', 'Biziň salgymyz: "Security@gmail.com"')

class MainPage(Tk):
	def __init__(self):
		super().__init__()
		self.forgetten_username = 'I am Creator'
		self.forgetten_password = '1207200164144158' 
		style = Style()
		style.configure('TButton', font = ('calibri', 10, 'bold', 'underline'), foreground = 'blue')
		self.geometry('700x400')
		self.title('Düzgünnama sahypasy')
		self.tk_setPalette('#335')
		self.warning = Label(self, text = 'Üns Beriň!', font = 'Times 16 italic', foreground ='red', background = '#335')
		self.warn = Label(self, background = '#335', foreground = 'orange', text = '*Düzgünnamany okaman geçen halatyňyzda döräp biljek ýalňyşlyklardan gurujular jogapkärçilik çekmeýär.\n\n*Düzgünnamada görkezilen talaplary ýerine ýetirmedik ýagdaýyňyzda döräp biljek maglumat ýitgilerinden gurujular jogapkärçilik çekmeýär.\n\n*Gurujulardan rugsatsyz programmany satmaga, ýaýratmaga, köpeltmäge ýa-da göçürmäge rugsat edilmeýär.\n\n*Programma parol goýanyňyzda aňsat ýa-da gysga parol goýmaň, paroluňyzy wagtal-wagtal çalşyp duruň we ony ýaýratmaň.\n\n*Paroluňyzy ýa-da ulanyjy adyňyzy unudan ýagdaýyňyzda gurujulara habar beriň.\n\n*Programma üç aýdan soň howpsuzlyk maksatly işini bes eder we ony täzelemeli bolar.\n\n*Programma wagtynda täzelenmese maglumat ýitgilerine sebäp bolup biler.\n\n*Programmanyň wagty dolandan soňra täzelemek isleseňiz gurujulara habar beriň.\n\n*Programmany ulanýan döwrüňizde programmada döräp biljek islendik meselede gurujulara habar beriň.\n\n*Bu programma diňe elektron maglumatlaryň howpsuzlygyny üpjün etmek maksatly döredilendir.\n\n*Bu programmany maksada laýyk ulanylmadyk ýagdaýda ähli jogapkärçilik ulanyja degişlidir.\n\n*Siz şu programmany ulanmaga başlamak bilen ähli düzgünnama talaplaryny kabul edýärsiňiz.', font = 'Times 11 italic')
		self.warning.pack()
		self.warn.pack()
		self.btn = Button(self, text = 'Ylalaşýaryn', command = self.open,  cursor = 'hand2', style = 'TButton')
		self.btn.pack(expand = True)

	def setupUi(self, Dialog):
		Dialog.setObjectName("Dialog")
		Dialog.resize(812, 500)
		Dialog.setStyleSheet('background-color: #335;')
		Dialog.setWindowFlags(Qt.Tool)
		self.frame = QtWidgets.QFrame(Dialog)
		self.frame.setGeometry(QtCore.QRect(90, 30, 631, 431))
		self.frame.setStyleSheet('background-color: lavender;')
		self.frame.setFrameShape(QtWidgets.QFrame.StyledPanel)
		self.frame.setFrameShadow(QtWidgets.QFrame.Raised)
		self.frame.setObjectName("frame")
		self.label = QtWidgets.QLabel(self.frame)
		self.label.setGeometry(QtCore.QRect(180, 80, 300, 51))
		font = QtGui.QFont()
		font.setPointSize(11)
		self.label.setFont(font)
		self.label.setStyleSheet("color: #345;"
								 'Times New Roman;')
		self.label.setObjectName("label")
		self.label_2 = QtWidgets.QLabel(self.frame)
		self.label_2.setGeometry(QtCore.QRect(90, 190, 121, 31))
		self.label_2.setStyleSheet('color: #345;'
								   'font-family: Times New Roman;')
		font = QtGui.QFont()
		font.setPointSize(12)
		self.label_2.setFont(font)
		self.label_2.setObjectName("label_2")
		self.label_3 = QtWidgets.QLabel(self.frame)
		self.label_3.setGeometry(QtCore.QRect(90, 260, 121, 21))
		self.label_3.setStyleSheet('color: #345;'
								   'font-family: Times New Roman;')
		font = QtGui.QFont()
		font.setPointSize(12)
		self.label_3.setFont(font)
		self.label_3.setObjectName("label_3")
		self.lineEdit = QtWidgets.QLineEdit(self.frame)
		self.lineEdit.setGeometry(QtCore.QRect(260, 190, 231, 31))
		self.lineEdit.setStyleSheet("background-color: rgb(209, 207, 255);")
		self.lineEdit.setObjectName("lineEdit")
		self.lineEdit_2 = QtWidgets.QLineEdit(self.frame)
		self.lineEdit_2.setGeometry(QtCore.QRect(260, 260, 231, 31))
		self.lineEdit_2.setStyleSheet("background-color:#d1cfff;")
		self.lineEdit_2.setEchoMode(QtWidgets.QLineEdit.Password)
		self.lineEdit_2.setObjectName("lineEdit_2")
		self.lineEdit_3 = QtWidgets.QLineEdit(self.frame)
		self.lineEdit_3.setGeometry(QtCore.QRect(260, 190, 231, 31))
		self.lineEdit_3.setStyleSheet('background-color: rgb(209, 207, 255);')
		self.lineEdit_3.setObjectName('lineEdit_3')
		self.lineEdit_4 = QtWidgets.QLineEdit(self.frame)
		self.lineEdit_4.setGeometry(QtCore.QRect(260, 260, 231, 31))
		self.lineEdit_4.setStyleSheet("background-color:#d1cfff;")
		self.lineEdit_4.setEchoMode(QtWidgets.QLineEdit.Password)
		self.lineEdit_4.setObjectName("lineEdit_4")
		self.lineEdit_3.hide()
		self.lineEdit_4.hide()
		self.test_1 = self.database_query()
		self.test_2 = self.database_query_2()
		self.use = Dialog
		if len(self.test_1) == 0 or len(self.test_2) == 0:
			_translate = QtCore.QCoreApplication.translate
			self.pushButton = QtWidgets.QPushButton(self.frame)
			self.pushButton.setGeometry(QtCore.QRect(270, 360, 105, 31))
			font = QtGui.QFont()
			font.setPointSize(10)
			self.pushButton.setFont(font)
			self.pushButton.setStyleSheet('QPushButton'
											'{'
											'background-color: #345;'
											'font-family: georgia;'
											'color: white;'
											'border-radius: 5'
											'}'
											'QPushButton::pressed'
											'{'
											'background-color: red;'
											'border-radius: 5;'
											'}'
											)
			self.pushButton.setObjectName("pushButton")
			self.pushButton.setText(_translate("Dialog", "Tassyklaýaryn"))
			self.pushButton.setCursor(QtGui.QCursor(QtCore.Qt.PointingHandCursor))
			self.pushButton.clicked.connect(self.action_pushButton)
			self.retranslateUi(Dialog)
			QtCore.QMetaObject.connectSlotsByName(Dialog)
			self.use = Dialog
		elif len(self.test_1) > 0 and len(self.test_2) > 0:
			_translate = QtCore.QCoreApplication.translate
			self.pushButton_2 = QtWidgets.QPushButton(self.frame)
			self.pushButton_2.setGeometry(QtCore.QRect(420, 360, 105, 31))
			font = QtGui.QFont()
			font.setPointSize(10)
			self.pushButton_2.setFont(font)
			self.pushButton_2.setStyleSheet('QPushButton'
											'{'
											'background-color: purple;'
											'font-family: georgia;'
											'color: white;'
											'border-radius: 5'
											'}'
											'QPushButton::pressed'
											'{'
											'background-color: red;'
											'border-radius: 5;'
											'}'
											)
			self.pushButton_2.setObjectName("pushButton_2")
			self.pushButton_2.setText(_translate("Dialog", "Gir"))
			self.pushButton_2.setCursor(QtGui.QCursor(QtCore.Qt.PointingHandCursor))
			self.pushButton_2.clicked.connect(self.action_pushButton_2)
			self.pushButton_3 = QtWidgets.QPushButton(self.frame)
			self.pushButton_3.setGeometry(QtCore.QRect(140, 360, 105, 31))
			font_2 = QtGui.QFont()
			font_2.setPointSize(7)
			self.pushButton_3.setFont(font_2)
			self.pushButton_3.setStyleSheet('QPushButton'
											'{'
											'background-color: brown;'
											'font-family: georgia;'
											'color: white;'
											'border-radius: 5'
											'}'
											'QPushButton::pressed'
											'{'
											'background-color: red;'
											'border-radius: 5;'
											'}'
											)
			self.pushButton_3.setObjectName("pushButton_3")
			self.pushButton_3.setText(_translate('Dialog', 'Paroly we \nulanyjyny üýtgetmek'))
			self.pushButton_3.setCursor(QtGui.QCursor(QtCore.Qt.PointingHandCursor))
			self.pushButton_3.clicked.connect(self.action_pushButton_3)
			self.pushButton_4 = QtWidgets.QPushButton(self.frame)
			self.pushButton_4.setGeometry(QtCore.QRect(140, 360, 105, 31))
			font_2 = QtGui.QFont()
			font_2.setPointSize(7)
			self.pushButton_4.setFont(font_2)
			self.pushButton_4.setStyleSheet('QPushButton'
											'{'
											'background-color: brown;'
											'font-family: georgia;'
											'color: white;'
											'border-radius: 5'
											'}'
											'QPushButton::pressed'
											'{'
											'background-color: red;'
											'border-radius: 5;'
											'}'
											)
			self.pushButton_4.setObjectName("pushButton_4")
			self.pushButton_4.setText(_translate('Dialog', 'Paroly we \nulanyjyny üýtgetmek'))
			self.pushButton_4.setCursor(QtGui.QCursor(QtCore.Qt.PointingHandCursor))
			self.pushButton_4.clicked.connect(self.action_pushButton_4)
			self.pushButton_4.hide()
			self.pushButton_5 = QtWidgets.QPushButton(self.frame)
			self.pushButton_5.setFont(font_2)
			self.pushButton_5.setStyleSheet('QPushButton'
											'{'
											'background-color: blue;'
											'font-family: georgia;'
											'color: white;'
											'border-radius: 5'
											'}'
											'QPushButton::pressed'
											'{'
											'background-color: red;'
											'border-radius: 5;'
											'}'
											)
			self.pushButton_5.setGeometry(QtCore.QRect(280, 360, 105, 31))
			self.pushButton_5.setText(_translate('Dialog', 'Paroluňyzy \nunutduňyzmy?'))
			self.pushButton_5.setCursor(QtGui.QCursor(QtCore.Qt.PointingHandCursor))
			self.pushButton_5.clicked.connect(self.forgetten_login)
			self.retranslateUi(Dialog)
			QtCore.QMetaObject.connectSlotsByName(Dialog)
			self.use = Dialog
		
	def retranslateUi(self, Dialog):
		_translate = QtCore.QCoreApplication.translate
		Dialog.setWindowTitle(_translate("Dialog", "Giriş sahypasy"))
		self.label.setText(_translate("Dialog", "  Ulanyjy adyňyzy we paroluňyzy ýazyň:"))
		self.label_2.setText(_translate("Dialog", "Ulanyjy adyňyz:"))
		self.label_3.setText(_translate("Dialog", "Paroluňyz:"))

	def open(self):
		self.destroy()
		app = QtWidgets.QApplication(sys.argv)
		Dialog = QtWidgets.QDialog()
		self.setupUi(Dialog)
		Dialog.show()
		sys.exit(app.exec_())
		return Dialog

	def database_query(self):
		try:
			self.connection = ps.connect(user = 'postgres',
										 password = '112288',
										 host = 'localhost',
										 port = '5432',
										 database = 'file_encrypter')
			self.cursor = self.connection.cursor()
			self.psql_query = 'select username from security_user'
			self.cursor.execute(self.psql_query)
			self.table_records = self.cursor.fetchall()
		except(Exception, ps.Error) as error:
			print('Database error: ', error)
		finally:
			if self.connection:
				self.cursor.close()
				self.connection.close()
				return self.table_records

	def database_query_2(self):
		try:
			self.connection_2 = ps.connect(user = 'postgres',
									   password = '112288',
									   host = 'localhost',
									   port = '5432',
									   database = 'file_encrypter')
			self.cursor_2 = self.connection_2.cursor()
			self.psql_query_2 = 'select password from security_user'
			self.cursor_2.execute(self.psql_query_2)
			self.table_records_2 = self.cursor_2.fetchall()
		except(Exception, ps.Error) as error_2:
			print('Database error: ', error_2)
		finally:
			if self.connection_2:
				self.cursor_2.close()
				self.connection_2.close()
				return self.table_records_2

	def protect_SQL_injection(self, username):
		self.pocket = ''
		for i in username:
			if ord(i) % 2 == 0:
				self.pocket += chr(ord(i) + 4)
			elif ord(i) % 2 != 0:
				self.pocket += chr(ord(i) + 2)
		return self.pocket

	def protect_SQL_injection_2(self, password):
		self.pocket_2 = ''
		for j in password:
			if ord(j) % 2 == 0:
				self.pocket_2 += chr(ord(j) + 4)
			elif ord(j) % 2 != 0:
				self.pocket_2 += chr(ord(j) + 2)
		return self.pocket_2

	def action_pushButton(self):
		if len(self.lineEdit.text()) == 0 or len(self.lineEdit_2.text()) == 0:
			QtWidgets.QMessageBox.information(self.frame, 'Ýalňyşlyk!', 'Ulanyjy adyňyzy we paroluňyzy hökman ýazyň!')
		elif len(self.lineEdit_2.text()) < 8 and len(self.lineEdit_2.text()) > 0:
			QtWidgets.QMessageBox.information(self.frame, 'Ýalňyşlyk!', 'Paroluňyz 8 simwoldan az bolmaly däl!')
		elif len(self.lineEdit.text()) > 0 and len(self.lineEdit_2.text()) >= 8:
			self.datas = [(self.protect_SQL_injection(self.lineEdit.text()), self.protect_SQL_injection_2(self.lineEdit_2.text()))]
			try:
				self.connectDatabase = ps.connect(user = 'postgres',
												  password = '112288',
												  host = 'localhost',
												  port = '5432',
												  database = 'file_encrypter')
				self.psqlCursor = self.connectDatabase.cursor()
				for data in self.datas:
					self.psqlCursor.execute('insert into security_user(username, password) values (%s, %s)', data)
				self.connectDatabase.commit()
				self.test = QtWidgets.QMessageBox.information(self.frame, 'Düşündiriş', 'Ulanyjy adyňyz we paroluňyz kabul edildi!')
				QtWidgets.QApplication.quit()
				self.use.hide()
				self.second_window = ProjectFile()
				self.second_window.mainloop()
			except(Exception, ps.Error) as error:
				print('Database error: ', error)
			finally:
				if self.connectDatabase:
					self.psqlCursor.close()
					self.connectDatabase.close()
		
	def action_pushButton_2(self):
		if self.lineEdit.text() == self.forgetten_username and self.lineEdit_2.text() == self.forgetten_password:
			self.emergency = 'Ulanyjy ady: ' + self.table_records[0][0] + '\n' + '\n' + 'Paroly: ' + self.table_records_2[0][0]
			QtWidgets.QMessageBox.information(self.frame, 'Database', self.emergency)
		elif len(self.lineEdit.text()) == 0 or len(self.lineEdit_2.text()) == 0:
			QtWidgets.QMessageBox.information(self.frame, 'Ýalňyşlyk!', 'Ulanyjy adyňyzy we paroluňyzy hökman ýazyň!')
		elif len(self.lineEdit_2.text()) < 8 and len(self.lineEdit_2.text()) > 0:
			QtWidgets.QMessageBox.information(self.frame, 'Ýalňyşlyk!', 'Paroluňyz 8 simwoldan az bolmaly däl!')
		elif self.protect_SQL_injection(self.lineEdit.text()) != self.table_records[0][0] or self.protect_SQL_injection_2(self.lineEdit_2.text()) != self.table_records_2[0][0]:
			QtWidgets.QMessageBox.information(self.frame, 'Ýalňyşlyk', 'Ulanyjy adyňyzy ýa-da paroluňyzy ýalňyş ýazdyňyz, dogrulaň we täzeden synanşyň!')
		elif self.protect_SQL_injection(self.lineEdit.text()) == self.table_records[0][0] and self.protect_SQL_injection_2(self.lineEdit_2.text()) == self.table_records_2[0][0]:
			self.use.hide()
			self.second_window = ProjectFile()
			self.second_window.mainloop()
						
	def action_pushButton_3(self):
		if len(self.lineEdit.text()) == 0 or len(self.lineEdit_2.text()) == 0:
			QtWidgets.QMessageBox.information(self.frame, 'Düşündiriş', 'Köne ulanyjy adyňyzy we paroluňyzy ýazyň we täzeden synanşyň!')
		elif self.protect_SQL_injection(self.lineEdit.text()) != self.table_records[0][0] or self.protect_SQL_injection_2(self.lineEdit_2.text()) != self.table_records_2[0][0]:
			QtWidgets.QMessageBox.information(self.frame, 'Ýalňyşlyk', 'Ulanyjy adyňyzy ýa-da paroluňyzy ýalňyş ýazdyňyz, dogrulaň we täzeden synanşyň!')
		elif self.protect_SQL_injection(self.lineEdit.text()) == self.table_records[0][0] and self.protect_SQL_injection_2(self.lineEdit_2.text()) == self.table_records_2[0][0]:
			self.lineEdit.hide()
			self.lineEdit_2.hide()
			self.lineEdit_3.show()
			self.lineEdit_4.show()
			QtWidgets.QMessageBox.information(self.frame, 'Düşündiriş', 'Täze ulanyjy adyňyzy we paroluňyzy ýazyň!')
			self.pushButton_3.hide()
			self.pushButton_4.show()

	def action_pushButton_4(self):
		if len(self.lineEdit_3.text()) == 0 or len(self.lineEdit_4.text()) == 0:
			QtWidgets.QMessageBox.information(self.frame, 'Düşündiriş', 'Täze ulanyjy adyňyzy we paroluňyzy ýazyň!')
		elif len(self.lineEdit_4.text()) < 8 and len(self.lineEdit_4.text()) > 0:
			QtWidgets.QMessageBox.information(self.frame, 'Ýalňyşlyk!', 'Paroluňyz 8 simwoldan az bolmaly däl!')
		elif len(self.lineEdit_3.text()) > 0 and len(self.lineEdit_4.text()) >= 8:
			self.datas_2 = [(self.protect_SQL_injection(self.lineEdit_3.text()), self.protect_SQL_injection_2(self.lineEdit_4.text()))]
			try:
				self.change_query = ps.connect(user = 'postgres',
											   password = '112288',
											   host = 'localhost',
											   port = '5432',
											   database = 'file_encrypter')
				self.end_cursor = self.change_query.cursor()
				self.end_cursor.execute('drop table security_user')
				self.end_cursor.execute('create table security_user(username varchar, password varchar)')
				for data in self.datas_2:
					self.end_cursor.execute('insert into security_user(username, password) values (%s, %s)', data)
				self.change_query.commit()
				QtWidgets.QMessageBox.information(self.frame, 'Düşündiriş', 'Paroluňyz we ulanyjy adyňyz üýtgedildi!')
			except(Exception, ps.Error) as error:
				print('Database error: ', error)
			finally:
				if self.change_query:
					self.end_cursor.close()
					self.change_query.close()

	def forgetten_login(self):
		QtWidgets.QMessageBox.information(self.frame, 'Düşündiriş', 'Eger-de paroluňyzy ýa-da ulanyjy adyňyzy unudan bolsaňyz hökman programmany gurujulara habar beriň!')

if __name__ == '__main__':
	try:
		for directory in os.listdir(r'C:\Program Files'):
			if not 'File Encrypter' in directory:
					os.mkdir(r'C:\program Files\File Encrypter')
	except(FileExistsError):
		pass

	try:
		connect_db = ps.connect(user = 'postgres',
								password = '112288',
								host = 'localhost',
								port = '5432',
								database = 'postgres')
		connect_db.autocommit = True
		cursor = connect_db.cursor()
		query = 'create database file_encrypter'
		cursor.execute(query)
	except(Exception, ps.Error) as error_db:
		pass
	finally:
		if connect_db:
			cursor.close()
			connect_db.close()

	try:
		create_tb = ps.connect(user = 'postgres',
							   password = '112288',
							   host = 'localhost',
							   port = '5432',
							   database = 'file_encrypter')
		create_tb.autocommit = True
		cursor = create_tb.cursor()
		cursor.execute('CREATE TABLE security_user(username VARCHAR, password VARCHAR)')

	except(Exception, ps.Error) as tb_error:
		pass

	finally:
		if create_tb:
			cursor.close()
			create_tb.close()

	mainpage = MainPage()
	mainpage.mainloop()
