#!/usr/bin/env python
import os
import pwd
import hashlib
import json
import sys
import textwrap
from datetime import datetime
import grp
import pprint
import argparse
from grp import getgrgid



if os.path.exists('siv/report1.txt'):
    print "File exists"

else:
   open("siv/report1.txt", 'w')

if os.path.exists('siv/report2.txt'):
    print "File exists"

else:
   open("siv/report2.txt", 'w')


if os.path.exists('siv/verify.txt'):
    print "File exists"

else:
   open("siv/verify.txt", 'w')

# python siv/siv.py -i -D TOOLS -V siv/verify.txt -R siv/report1.txt -H MD5
#python siv/siv.py -v -D TOOLS -V siv/verify.txt -R siv/report2.txt 

parser = argparse.ArgumentParser(
    description=textwrap.dedent('''Initialization --> siv.py -i -D 'dir' -V 'ver_file' -R 'rep_file' -H 'hash'
                                ----------------------------------------------------------------------------
                                Verification  --> siv.py -v -D 'dir' -V 'ver_file' -R 'rep_file' '''))
args_group = parser.add_mutually_exclusive_group()
args_group.add_argument("-i", "--initialize", action="store_true")
args_group.add_argument("-v", "--verification", action="store_true")
parser.add_argument("-D", "--monitored_directory", type=str)
parser.add_argument("-V", "--verification_file", type=str)
parser.add_argument("-R", "--report_file", type=str)
parser.add_argument("-H", "--hash_function", type=str, default="SHA1")

args = parser.parse_args()

monitor = args.monitored_directory
verify = args.verification_file
report = args.report_file
algo = args.hash_function

if args.initialize:

    print("Initialization mood has been activated\n")
    start = datetime.utcnow()
	
    #if monitored directory exists  or not
    if os.path.isdir(monitor) == 1 or os.path.exists(monitor) == 1:
        print ("directory or file  already exists\n")
        
    
        if algo=='MD5' or algo=='SHA1': #hashing algo
            print ("hash supported")
    
            x=0  #parsed dir number
            y=0  #parsed file number
    
    
            detected=[]		
            detected_dirs={}
            detected_file={}
            detected_hash={}
                
            #if verification file already exists or not
            if os.path.isfile(verify)==1 and os.path.isfile(report)==1:
                print ("verification file already exists\n")
    
                if (os.path.commonprefix([monitor, verify]) == monitor) or (os.path.commonprefix([monitor, report]) == monitor):
                    print("Both Ver and Rep files are inside\n")
                    sys.exit()
                else:
                    print("Both Ver and Rep files are outside\n")
                        
            else:
                os.open(verify, os.O_CREAT,mode=0o777)
                os.open(report, os.O_CREAT, mode=0o777)  
                    
                print("verificationfile and report  file just  created\n")
                        
                if (os.path.commonprefix([monitor, verify]) == monitor) or (os.path.commonprefix([monitor, report]) == monitor):
                    print("Both Ver and Rep files are inside\n")
                    sys.exit()
                else:
                    print("Both Ver and Rep files are outside\n")
    
            #ask for overwrite  the  previous 
            #over_write_option = input("Do you want to overwrite? please enter y/n: ")\
            over_write_option = input("Do you want to overwrite?: ['y' for yes  or no for 'n']")
	    if not over_write_option or over_write_option[0].lower() == 'n':
		sys.exit()
   
            elif over_write_option== 'y':
                for subdirs, dirs, files in os.walk(monitor):
                    for folders in dirs:
                        x+=1
                        path = os.path.join(subdirs,folders)
                        size = os.path.getsize(path)
                        users = pwd.getpwuid(os.stat(path).st_uid).pw_name
                        group = getgrgid(os.stat(path).st_gid).gr_name
                        time = datetime.fromtimestamp(os.stat(path).st_mtime).strftime('%c')
                        last_access = oct(os.stat(path).st_mode & 0o777)
    
                        detected_dirs[path]={"size":size, "users":users, "group": group, "time": time, "access": last_access}
    
                        
                    for file in files:
                        y+=1
                        fpath = os.path.join(subdirs, file)
                        fsize = os.path.getsize(fpath)
                        fusers = pwd.getpwuid(os.stat(fpath).st_uid).pw_name
                        fgroup = getgrgid(os.stat(fpath).st_gid).gr_name
                        ftime = datetime.fromtimestamp(os.stat(fpath).st_mtime).strftime('%c')
                        flast_access = oct(os.stat(fpath).st_mode & 0o777)
                
                        #message compatibility  with SHA1
                        
                        if  algo=="SHA1":
                            htype="sha1"
                            hash_type=hashlib.sha1()
                            with open(fpath, 'rb') as sfile:
                                buff=sfile.read()
                                hash_type.update(buff)
                                fed_message=hash_type.hexdigest()
                                        
                        #message compatibility  with MD5
                        else:
                            htype="MD5"
                            hash_type=hashlib.md5()
                            with open(fpath, 'rb') as mdfile:
                                buff=mdfile.read()
                                hash_type.update(buff)
                                fed_message=hash_type.hexdigest()
                            
                        detected_file[fpath]={"size":fsize, "users":fusers, "group": fgroup, "time": ftime, 										"access":flast_access, "hash": fed_message}
    
    
                detected.append(detected_dirs)
                detected_hash={"hash_type":htype}
                detected.append(detected_file)
                detected.append(detected_hash)
                json_str=json.dumps(detected,indent=2, sort_keys=True)
                print('\n Verification file has been generated')
        
                #write to the ver file
                with open (verify, 'wb') as report_file:
                    report_file.write(json_str)
                
                print("\nreport file has been generated")
                #write  to report_file
                with open(report, 'wb') as report_file:
                    end= datetime.utcnow()			
                    report_file.write("Initialization has been complete \n\nMonitored dirs = " + monitor + "\nVerification file =" + verify + "\nNumber of total directories parsed =" + 									str(x) + "\nNumber of total files parsed = " + str(y) + "\n Total Time = " + str(end - start) + "\n")
            else:
                print("Invalid option\n")
                sys.exit()
        else:
            print("invalid hash\n")
            sys.exit()
        
    else:
        print("no monitored directory")
        sys.exit()

elif args.verification:
    start = datetime.utcnow()
    print("Verifiation mood has started\n")
    
    if os.path.isfile(verify) == 1:
        print("Verification File is already exists\n")

        if (os.path.commonprefix([monitor, verify]) == monitor) or (os.path.commonprefix([monitor, report]) == monitor):
            print("Both Ver and Rep files are inside\n")
            sys.exit()
        else:
			print("Both Ver and Rep files are outside\n")
    else:
        print("no verification file here")
        sys.exit()
		
    x=0 #dirs no
    y=0 #file no	
    w=0 #warning num	

    with open (verify) as inp_file:
        json_dec=json.load(inp_file)
    
    with open (report,"a") as rep_file:
        rep_file.write("\n verification mood has been started\n")

    for every_file in json_dec[2]:
        htype = every_file[2]
        
    with open (report,"a") as rep_file:

        for subdirs, dirs, files in os.walk(monitor): 

            for folders in dirs:
                x+=1
                path = os.path.join(subdirs,folders)
                size = os.path.getsize(path)
                users = pwd.getpwuid(os.stat(path).st_uid).pw_name
                group = getgrgid(os.stat(path).st_gid).gr_name
                recent = datetime.fromtimestamp(os.stat(path).st_mtime).strftime('%c')
                last_access = oct(os.stat(path).st_mode & 0o777)

                print("Dirs" + path + '\n')
        
                if path in json_dec[0]:
                    if size != json_dec[0][path]['size']:
                        rep_file.write("\nWarning  at directory  " + path + " has not same size\n")
                        w += 1
                    if users != json_dec[0][path]['users']:
                        rep_file.write("\nWarning  at directory  " + path + " has not same user\n")
                        w += 1
                    if group != json_dec[0][path]['group']:
                        rep_file.write("\nWarning  at directory  " + path + " has not same group\n")
                        w += 1
                    if recent != json_dec[0][path]['time']:
                        rep_file.write("\nWarning  at directory  " + path + " has not same modification date\n")
                        w += 1
                    if last_access != json_dec[0][path]['access']:
                        rep_file.write("\nWarning at directory"+ path +" has modified last access priviliges\n")
                        w += 1
                else:
                    rep_file.write("\nWarning at directory " + path + " has been added\n")
                    w += 1

        for all_dirs in json_dec[0]:
            
            if os.path.isdir(all_dirs)==0:
                rep_file.write("\n Warning at direcroty" + all_dirs + " has deleted\n")
                w+=1			

        for subdirs, dirs, files in os.walk(monitor): 

            for folders in files:
                x+=1
                path = os.path.join(subdirs,folders)
                size = os.path.getsize(path)
                users = pwd.getpwuid(os.stat(path).st_uid).pw_name
                group = getgrgid(os.stat(path).st_gid).gr_name
                recent = datetime.fromtimestamp(os.stat(path).st_mtime).strftime('%c')
                last_access = oct(os.stat(path).st_mode & 0o777)
                print("Files" + path +"\n")

                #sha1
                if  htype == "SHA1":
                    hash_type=hashlib.sha1()
                    with open(path, "rb") as sfile:
                        buff=sfile.read()
                        hash_type.update(buff)
                        fed_message=hash_type.hexdigest()
                                    
                #md5
                else:
                    hash_type=hashlib.md5()
                    with open(path, "rb") as mdfile:
                        buff=mdfile.read()
                        hash_type.update(buff)
                        fed_message=hash_type.hexdigest()
            
                if path in json_dec[1]:
                    if size != json_dec[1][path]['size']:
                        rep_file.write("\nWarning  at directory  " + path + " has not same size\n")
                        w += 1
                    if users != json_dec[1][path]['users']:
                        rep_file.write("\nWarning  at directory  " + path + " has not same user\n")
                        w += 1
                    if group != json_dec[1][path]['group']:
                        rep_file.write("\nWarning  at directory  " + path + " has not same group\n")
                        w += 1
                    if recent != json_dec[1][path]['time']:
                        rep_file.write("\nWarning  at directory  " + path + " has not same modification date\n")
                        w += 1
                    if last_access != json_dec[1][path]['access']:
                        rep_file.write("\nWarning at directory"+ path + " has modified last access priviliges\n")
                        w += 1

                else:
                    rep_file.write("\nWarning at directory " + path + " has  added\n")
                    w += 1

        for all_files in json_dec[1]:
            if os.path.isdir(all_files)==0:
                rep_file.write("\n Warning at direcroty" + all_files + " has deleted\n")

		##Finally writing to the rep file

		with open(report , "a") as report_file:
			end = datetime.utcnow()
			report_file.write("\nVerification mode complete \n\nMonitored directory = " + monitor + "\nVerification file =" 						+ verify + "\nNumber of directories parsed =" + str(x) + "\nNumber of files parsed = " + 							str(y) + "\nTotal Warnings = " + str(w) + "\nTime taken = " + str(end - start) + "\n")

		print("Report File has been generated")
        
        
        
        
        
        
        
        
        ##I took help from github for doing this. Link is below
        #https://github.com/rohitp93/System-Integrity-Verifier/blob/master/siv.py#L156
        
        
        
