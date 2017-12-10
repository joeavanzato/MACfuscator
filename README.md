# MACfuscator

# Timeline Obfuscation Utility

Joe Avanzato, joeavanzato@gmail.com
Requires PyWin32, Administrative Access

This script was designed as a means to obfuscate the timing of actions on a Windows environment without any real exploits, nominally as a module of some larger malicious package which may contain some form of privilege escalation necessary to perform certain modifications.  It was intended to be executed concurrently with a primary binary which, upon completion, would send some signal to this script initiating a break within the main loop and executing concluding statements.

Currently, this script alters the current system time, file MAC attributes in the folder from which it is executed, event viewer logs, the time-zone value stored in registry and the 'LastBootUpTime' property of CIM_OperatingClass.  This could be easily altered to instead wipe MAC attributes for the entire file-system via logical drive detection.    

In order to achieve this, it first reads the earliest record in the 'System' event log as well as the current datetime and uses these values as boundaries on legitimate date generation for setting the system time.  It is envisioned that file MAC attributes will be altered concurrently with a dynamically changing system time, although currently they are performed after the timing loop is completed (set to 500 changes in current upload, 'count' variable).  Since MAC attributes are adjusted while the system time is illegitimate, the $Entry_Modified value stored in the $Master_File_Table should also be effected but this is not currently verified and I may be completely wrong and dumb.

Event Viewer logs are cleared through standard MSDN functions interfaced with Python such as ClearEventLog and as such errors may be encountered due to certain permission requirements. 

I plan to have this do more things, such as achieve persistence via a PyInstaller packaged .exe added to the 'AutoRun' value and copied into some hidden folder.  With this implementation the binary will also remove its original location and dropped files, 'cleaning house' after itself.  These features are not currently implemented, although perhaps easy to do so, due to the nature of this project, which was to DEMONSTRATE an obfuscation utility for graduate classwork.
