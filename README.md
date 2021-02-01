# zeekscripts

- scriptlog.zeek 

  This script adds a new log that captures part (or all) of script-type files. Scripts may sometimes be moved around an environment post-compromise and used for things like: executing other tools and binaries, archiving files and directories for exfil, enumerating users/accounts/privileges, etc.

- mismatch.zeek

  This script will highlight mismatches between mimetype and expected file extension, which can indicate obfuscation of tool transfer or data exfil. The included list of mimetypes/file exts is not comprehensive but should capture a lot of the file types most likely to be obfuscated or used for obfuscation: archives, scripts and other executables, images, documents.
