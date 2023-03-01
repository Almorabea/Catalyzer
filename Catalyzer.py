import base64
import os
import sys
import argparse
import hashlib
import zipfile
import random
import filetype
import json
import pefile
import pyzipper
import re
import binary2strings as b2s


outputTXT = []

def Interesting (file):
    global  outputTXT
    interesting = ["cmd", "powershell", "wmi", "http", "shell", "hta", "mshta","dos","program","invoke","base64","echo","@echo"]
    try:
        print()
        outputTXT.append("**********Start Of Interesting Information**********\n")
        print("**********Start Of Interesting Information**********")
        with open(file, "rb") as f:
            n = 0
            b = f.read(16)
            evidences = []
            while b:
                s1 = " ".join([f"{i:02x}" for i in b])  # hex string
                s1 = s1[0:23] + " " + s1[23:]  # insert extra space between groups of 8 hex values
                s2 = "".join([chr(i) if 32 <= i <= 127 else "." for i in b])  # ascii string; chained comparison
                counter = 0
                for val in interesting:
                    if(val in s2.replace(".","").lower()):
                        evidences.append(f"{n * 16:08x}")
                        str = hex(int(f"{n * 16:08x}", 16) + int("100", 16)) # just a simple hex calculation where I add 100 to the hex value
                        strlen = 8 - len(str[2:])
                        cut(file,f"{n * 16:08x}", strlen*"0"+str[2:] ) #padding

                        counter = counter + 1
                        print("*********************************")
                        outputTXT.append("*********************************\n")
                n += 1
                b = f.read(16)
            print("Offsets found below:")
            outputTXT.append("Offsets found below:\n")
            print(evidences)
            for value in evidences:
                outputTXT.append(value+ "\n")

            print("We've got {} findings\n".format(len(evidences)))
            print("**********End Of Interesting Information**********")
            outputTXT.append("We've got {} findings\n".format(len(evidences)))
            outputTXT.append("**********End Of Interesting Information**********\n")
    except Exception as e:
        print(__file__, ": ", type(e).__name__, " - ", e, sep="", file=sys.stderr)


def dump (file,startoffset = "00000000" ,endoffset = "00000100",format = hex):
    global outputTXT
    dump = ""

    print("")
    print("**********Start Of DUMP Portion**********")
    outputTXT.append("**********Start Of DUMP Portion**********\n")
    try:
        with open(file, "rb") as f:
            n = 0
            b = f.read(16)
            ary = []
            while b:

                s1 = " ".join([f"{i:02x}" for i in b])  # hex string

                s1 = s1[0:23] + " " + s1[23:]  # insert extra space between groups of 8 hex values

                s2 = "".join([chr(i) if 32 <= i <= 127 else "." for i in b])  # ascii string; chained comparison

                temp = f"{n * 16:08x}  {s1:<48}  |{s2}|"
                ary.append(temp)
                n += 1
                b = f.read(16)

            first = ary.index([s for s in ary if startoffset in s][0])
            last= ary.index([s for s in ary if endoffset in s][0])
            count = first
            for value in ary:
                #print(ary[count])
                dump +=ary[count][10:len(ary[count])-20]


                if count == last:
                    break
                else:
                    count += 1
            dump = dump.replace(" ", "")
            if format == "hex":
                print(dump)
                outputTXT.append(dump)
            elif format == "base64":
                data = bytearray.fromhex(dump).decode()
                base = base64.b64encode(data.encode("ASCII"))
                print(str(base,'utf-8'))
                outputTXT.append(str(base,'utf-8'))
            else:
                print ("format not supported")
                outputTXT.append("format not supported")
                exit()
                #print()
                #outputTXT.append(dump)
            print("")
            print("**********End Of DUMP Portion**********")
    except Exception as e:
        print(__file__, ": ", type(e).__name__, " - ", e, sep="", file=sys.stderr)


def cut (file,startoffset = "00000000" ,endoffset = "00000100"):
    global outputTXT
    try:
        with open(file, "rb") as f:
            n = 0
            b = f.read(16)
            ary = []
            while b:

                s1 = " ".join([f"{i:02x}" for i in b])  # hex string

                s1 = s1[0:23] + " " + s1[23:]  # insert extra space between groups of 8 hex values

                s2 = "".join([chr(i) if 32 <= i <= 127 else "." for i in b])  # ascii string; chained comparison

                #print(f"{n * 16:08x}  {s1:<48}  |{s2}|")
                temp = f"{n * 16:08x}  {s1:<48}  |{s2}|"
                ary.append(temp)
                n += 1
                b = f.read(16)

            first = ary.index([s for s in ary if startoffset in s][0])
            last= ary.index([s for s in ary if endoffset in s][0])
            count = first
            for value in ary:
                print(ary[count])
                outputTXT.append(str(ary[count]) + "\n")
                if count == last:
                    break
                else:
                    count += 1

    except Exception as e:
        print(__file__, ": ", type(e).__name__, " - ", e, sep="", file=sys.stderr)

def GeneralInfo (filex):
    outputTXT.append("**********Start Of General Information**********\n")
    print("**********Start Of General Information**********")
    try:
        print("[+] FileName/Path:  " + filex)
        outputTXT.append("[+] FileName/Path:  " + filex + "\n")
        file_stats = os.stat(filex)
        print("[+] "+f'File Size in Bytes is {file_stats.st_size}')
        print("[+] "+f'File Size in MegaBytes is {file_stats.st_size / (1024 * 1024)}')
        outputTXT.append("[+] "+f'File Size in Bytes is {file_stats.st_size}' + "\n")
        outputTXT.append("[+] "+f'File Size in MegaBytes is {file_stats.st_size / (1024 * 1024)}' + "\n")

        try:
            pe = pefile.PE(filex)
            print("[+] e_magic : " + hex(pe.DOS_HEADER.e_magic))  # Prints the e_magic field of the DOS_HEADER
            print("[+] e_lfnew : " + hex(pe.DOS_HEADER.e_lfanew))  # Prints the e_lfnew field of the DOS_HEADER
            outputTXT.append("[+] e_magic : " + str(hex(pe.DOS_HEADER.e_magic)) + "\n")
            outputTXT.append("[+] e_lfnew : " + str(hex(pe.DOS_HEADER.e_lfanew)) + "\n")
        except Exception as e:
            print("[+] No magic field found of the DOS_HEADER")
            outputTXT.append("[+] No magic field found of the DOS_HEADER" + "\n")
        with open(filex, "rb") as f:
            n = 0
            b = f.read(16)
            ary = []
            header = ''
            while b:

                s1 = " ".join([f"{i:02x}" for i in b])  # hex string
                if n ==0:
                   header =  str(s1[0:23])
                s1 = s1[0:23] + " " + s1[23:]  # insert extra space between groups of 8 hex values


                s2 = "".join([chr(i) if 32 <= i <= 127 else "." for i in b])  # ascii string; chained comparison

                #print(f"{n * 16:08x}  {s1:<48}  |{s2}|")
                temp = f"{n * 16:08x}  {s1:<48}  |{s2}|"
                ary.append(temp)
                n += 1
                b = f.read(16)

            kind = filetype.guess(filex)
            extension = ''
            try:
                if kind is not None:
                    print('[+] File extension: %s' % kind.extension)
                    print('[+] File MIME type: %s' % kind.mime)
                    outputTXT.append('[+] File extension: %s' % kind.extension + "\n")
                    outputTXT.append('[+] File MIME type: %s' % kind.mime +  "\n")

                else:
                    header = header.replace(" ", "")
                    file = open('magic_data.json')
                    file_opened = json.load(file)

                    for val in file_opened['headers']:
                        if val[0] == header:
                            print("[+] File Type: " + val[4])
                            outputTXT.append("[+] File Type: " + val[4] + "\n")
                            extension = val[2]
            except Exception as e:
                print(__file__, ": ", type(e).__name__, " - ", e, sep="", file=sys.stderr)

            print("[+] Extension: " + extension)
            outputTXT.append("[+] Extension: " + extension + "\n")
            if len([s for s in ary if "MZ.." in s]) == 1 and kind is None:
                print("[+] This file could contains Executable file inside,check the offset below:")
                print([s for s in ary if "MZ.." in s])
                outputTXT.append("[+] This file could contains Executable file inside,check the offset below:" + "\n")
                outputTXT.append(str([s for s in ary if "MZ.." in s]) + "\n")

    except Exception as e:
        print(__file__, ": ", type(e).__name__, " - ", e, sep="", file=sys.stderr)

    hashes(filex)
    print("**********End Of General Information**********\n")
    outputTXT.append("**********End Of General Information**********" + "\n")

    print("**********Start Of Strings in UTF-8**********")
    outputTXT.append("**********Start Of Strings in UTF-8**********" + "\n")
    with open(filex, "rb") as i:
        data = i.read()
        for (string, type, span, is_interesting) in b2s.extract_all_strings(data, only_interesting=True):
            print(f"{string}")
            outputTXT.append(f"{string}\n")

    print("**********End Of Strings in UTF-8**********\n")
    outputTXT.append("**********End Of Strings in UTF-8**********" + "\n")

def hashes(file):
    # BUF_SIZE is totally arbitrary, change for your app!
    BUF_SIZE = 65536  # let's read stuff in 64kb chunks!

    md5 = hashlib.md5()
    sha1 = hashlib.sha1()
    sha256 = hashlib.sha256()
    with open(file, 'rb') as f:
        while True:
            data = f.read(BUF_SIZE)
            if not data:
                break
            md5.update(data)
            sha1.update(data)
            sha256.update(data)

    print("[+] MD5: {0}".format(md5.hexdigest()))
    print("[+] SHA1: {0}".format(sha1.hexdigest()))
    print("[+] SHA2: {0}".format(sha256.hexdigest()))
    outputTXT.append("[+] MD5: {0}".format(md5.hexdigest())+"\n")
    outputTXT.append("[+] SHA1: {0}".format(sha1.hexdigest())+"\n")
    outputTXT.append("[+] SHA2: {0}".format(sha256.hexdigest())+"\n")

def scanfolder(path,ext):
    res = []
    if (ext == ""):
        for file in os.listdir(path):
            if (os.path.isdir(path+"/"+file) == False):
                res.append(file)

    else:
        ext = ext.split(",")
        for value in ext:
            for file in os.listdir(path):
                if (os.path.isdir(path+"/"+file) == False):
                    if file.endswith(value):
                        res.append(file)
    return res

def Main():
    parser = argparse.ArgumentParser()
    parser.add_argument('-f', '--file', help='The name of the file that you wish to work with',required=False)
    parser.add_argument('-c', '--cut', help='Display portion of the file like hex : 00000:00100 without 0x (not required)', required=False)
    parser.add_argument('-d', '--dump', help='Dump specified portion of the working file into a new file (not required)', required=False)
    parser.add_argument('-p', '--password', help='Protected ZIP file password', required=False, default="infected")
    parser.add_argument('-fu', '--folder', help='Analyze the full folder', required=False)
    parser.add_argument('-s', '--format', help='The format of the dump data (hex, base64)', required=False)
    args = parser.parse_args()


    #print(args.file)
    fullpath = ""
    foldername = ""
    print('''

		 ██████╗ █████╗ ████████╗ █████╗ ██╗  ██╗   ██╗███████╗███████╗██████╗ 
		██╔════╝██╔══██╗╚══██╔══╝██╔══██╗██║  ╚██╗ ██╔╝╚══███╔╝██╔════╝██╔══██╗
		██║     ███████║   ██║   ███████║██║   ╚████╔╝   ███╔╝ █████╗  ██████╔╝
		██║     ██╔══██║   ██║   ██╔══██║██║    ╚██╔╝   ███╔╝  ██╔══╝  ██╔══██╗
		╚██████╗██║  ██║   ██║   ██║  ██║███████╗██║   ███████╗███████╗██║  ██║
		 ╚═════╝╚═╝  ╚═╝   ╚═╝   ╚═╝  ╚═╝╚══════╝╚═╝   ╚══════╝╚══════╝╚═╝  ╚═╝
		                                                               
				By Ahmad Almorabea @almorabea - almorabea.net - v1										''')
    print("Welcome to Catalyzer")
    print("[+] Creating a folder for this project")
    outputTXT.append("Welcome to Catalyzer\n")
    outputTXT.append("[+] Creating a folder for this project\n")
    foldername = input("Please provide a folder name for your project\n")
    samepath = input("You want to save it in the same path of the python file or another directory? (Y/N)\n")
    if samepath.lower() == "y":
        fullpath = os.path.dirname(os.path.realpath(__file__))
    else:
        fullpath = input("Enter the path you want to create the folder in\n")
    if os.path.exists(fullpath+"/"+foldername):
        foldername = foldername+str(random.randint(1, 50))
        os.makedirs(fullpath +"/"+ foldername)
        print("[+] We have created the folder with the same name and we've added a random number to it, because the folder exists in that path")
        print("[+] The new folder name is " + fullpath+"/"+foldername)
        outputTXT.append("[+] We have created the folder with the same name wnd we've added a random number to it, because the folder exists in that path\n")
        outputTXT.append("[+] The new folder name is " + fullpath+"/"+foldername+ "\n")
    else:
        print("folder created at : " + fullpath +"/"+ foldername)
        outputTXT.append("folder created at : " + fullpath +"/"+ foldername+"\n")
        os.makedirs(fullpath + "/" + foldername)
    if args.folder:
        if os.path.exists(args.folder):
            print("[+] Folder Created under the following name: " + fullpath+"/"+foldername)
            outputTXT.append("[+] Folder Created under the following name: " + fullpath+"/"+foldername+"\n")
            choice = input("Analyze all of the files in this folder or specific extensions? Y/N \n")
            res = []
            analyze = input("Do you want a full analysis for all of the files or just a general information? (Y/N)\n")
            if(choice.lower() == "y"):
                res = scanfolder(args.folder, "")
                print(res)
                for value in res:
                    GeneralInfo(args.folder+"/"+ value)
                    if analyze.lower() == "y":
                        Interesting(args.folder+"/"+ value)
                    print("")
                    print("")
                    outputTXT.append("\n")
                    outputTXT.append("\n")
            else:
               ext =  input("Type the file extensions you want to analyze and seperate with comma like (.one,.pptx)")
               res = scanfolder(args.folder, ext)
               for value in res:
                   GeneralInfo(str(args.folder)+"/"+value)
                   if analyze.lower() == "y":
                       Interesting(args.folder+"/"+value)
                   print("")
                   print("")
                   outputTXT.append("\n")
                   outputTXT.append("\n")
        else:
            print("the path provided is not valid")
            outputTXT.append("the path provided is not valid\n")

    elif args.cut:
        if args.file is None:
            file = input("Please select a file to work with\n")
            print("")
            outputTXT.append("\n")
            GeneralInfo(file)
            print("")
            outputTXT.append("\n")
            data = str(args.cut)
            data = data.split(":")
            cut(file,data[0],data[1])
        else:
            GeneralInfo(args.file)
            print("")
            outputTXT.append("\n")
            data = str(args.cut)
            data = data.split(":")
            cut(args.file, data[0], data[1])
    
    elif args.file:
        if zipfile.is_zipfile(args.file):
            print("[+]File is an archive/compressed")
            outputTXT.append("[+]File is an archive/compressed\n")
            zf = zipfile.ZipFile(args.file)
            for zinfo in zf.infolist():
                is_encrypted = zinfo.flag_bits & 0x1
                if is_encrypted:
                    print('[+] %s is encrypted!' % args.file )
                    outputTXT.append('[+] %s is encrypted!' % args.file+ "\n")
                    try:
                        with pyzipper.AESZipFile(args.file) as zf:
                            zf.extractall(pwd=str(args.password).encode("utf-8"), path=fullpath+"/"+foldername)
                            print("[+] We extracted the files , the password:  " + (args.password) + " worked!")
                            outputTXT.append("[+] We extracted the files , the password:  " + args.password + " worked!\n")
                            for file in os.listdir(fullpath+"/"+foldername):
                                filex = file.replace(" ", "")
                                if os.path.isfile(fullpath+"/"+foldername+"/"+file):
                                    GeneralInfo(fullpath+"/"+foldername+"/"+filex)
                                    print("")
                                    outputTXT.append("\n")
                                    Interesting(fullpath+"/"+foldername+"/"+filex)
                                    outputTXT.append("\n")
                                    outputTXT.append("\n")
                                else:
                                    print("missed the if")
               
                    except Exception as e:
                        print("There was a problem in unzippig the archive with the supplied password")
                        outputTXT.append("There was a problem in unzippig the archive with the supplied password, we suggest to nuzip it locally and then supply the file alone\n")
                        print(__file__, ": ", type(e).__name__, " - ", e, sep="", file=sys.stderr)
                else:
                    GeneralInfo(args.file)
                    print("")
                    outputTXT.append("")
                    Interesting(args.file)
                    print("")
                    print("")
                    outputTXT.append("")
                    outputTXT.append("")
        else:
            GeneralInfo(args.file)
            print("")
            outputTXT.append("")
            Interesting(args.file)
            print("")
            print("")
            outputTXT.append("")
            outputTXT.append("")

            if args.dump:
                print("dump")
                if (args.file and args.dump):
                    data = str(args.dump)
                    data = data.split(":")
                    dump(args.file, data[0], data[1], args.format)

    




    outputTXT.append("\n")
    outputTXT.append("Caveat:\n")
    outputTXT.append(
        "Please examine the results carefully as this is an automated script and it could be fooled by malware authors\n")
    outputTXT.append("\n")
    outputTXT.append("This script created by Ahmad Almorabea @almorabea")

    with open(fullpath+"/"+foldername+"/"+foldername+".txt", 'w') as f:
        for value in outputTXT:
            f.write(value)

        f.close()






if __name__ == '__main__':
    Main()
