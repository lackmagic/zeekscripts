# dlack 2021-01-01
# https://github.com/lackmagic/zeekscripts
# This script will highlight mismatches between mimetype and expected file extension, 
# which can indicate obfuscation of tool transfer or data exfil. 
# The included list of mimetypes/file exts is not comprehensive but should capture a lot 
# of the file types most likely to be obfuscated or used for obfuscation: 
# archives, scripts and other executables, images, documents.
# 
# This script may be noisy depending on your environment and may require tuning or additions to mimes/exts.
#
# This script adds: 
# - a notice to indicate file extension and mimetype mismatch.
# - a file extension field in the Files log (which could be used for batch analysis, sorting on outliers, etc.)
# - a bool in the Files log to indicate file extension and mimetype mismatch 
#  (note: the bool may be a little misleading as not all possible mimetypes and file exts are captured here.)
#
#
# https://attack.mitre.org/techniques/T1036/
# 

@load base/frameworks/files
@load base/frameworks/notice

module Mismatch;

export {
        redef record Files::Info += {
                file_ext: string &optional &log;
                mismatch: bool &optional &log &default=F;
        };

        redef enum Notice::Type += {
                Mimetype_Mismatch
        };

# list to limit the mimetypes to check for. As an example, text/plain frequently shows up
# with non .txt files, so including it here would be very noisy, but it could easily be added.
        const mimes = /application\/ecmascript|application\/epub+zip|application\/gzip|application\/java-archive|application\/javascript|application\/msword|application\/octet-stream|application\/pdf|application\/rtf|application\/vnd.apple.installer+xml|application\/vnd.ms-cab-compressed|application\/vnd.ms-excel|application\/vnd.ms-powerpoint|application\/vnd.oasis.opendocument.presentation|application\/vnd.oasis.opendocument.spreadsheet|application\/vnd.oasis.opendocument.text|application\/vnd.openxmlformats-officedocument.presentationml.presentation|application\/vnd.openxmlformats-officedocument.spreadsheetml.sheet|application\/vnd.openxmlformats-officedocument.wordprocessingml.document|application\/vnd.rar|application\/vnd.visio|application\/x-7z-compressed|application\/x-aspx|application\/x-bat|application\/x-bzip|application\/x-bzip2|application\/x-csh|application\/x-dosexec|application\/x-freearc|application\/x-gzip|application\/x-httpd-php|application\/x-javascript|application\/x-jsp|application\/x-powershell|application\/x-rar|application\/x-sh|application\/x-shockwave-flash|application\/x-tar|application\/xhtml+xml|application\/xml|application\/zip|image\/bmp|image\/gif|image\/jpeg|image\/png|image\/svg+xml|image\/tiff|image\/vnd.microsoft.icon|text\/ecmascript|text\/javascript|text\/vbscript|text\/x-go|text\/x-java|text\/x-lua|text\/x-perl|text\/x-python|text\/x-ruby|text\/x-sh|text\/x-shellscript|text\/x-vb/ &redef;

# This list is not comprehensive but should capture a lot of file types most likely to be obfuscated
# themselves or used for obfuscation: archives, scripts and other executables, images, documents.
        global s1: set[string, string]= { 
        ["application/ecmascript",".js"],
        ["application/epub+zip",".epub"],
        ["application/gzip",".gz"],
        ["application/java-archive",".jar"],
        ["application/javascript",".js"],
        ["application/msword",".doc"],
        ["application/octet-stream",".bin"],
        ["application/pdf",".pdf"],
        ["application/rtf",".rtf"],
        ["application/vnd.apple.installer+xml",".mpkg"],
        ["application/vnd.ms-cab-compressed",".cab"],
        ["application/vnd.ms-excel",".xls"],
        ["application/vnd.ms-powerpoint",".ppt"],
        ["application/vnd.oasis.opendocument.presentation",".odp"],
        ["application/vnd.oasis.opendocument.spreadsheet",".ods"],
        ["application/vnd.oasis.opendocument.text",".odt"],
        ["application/vnd.openxmlformats-officedocument.presentationml.presentation",".pptx"],
        ["application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",".xlsx"],
        ["application/vnd.openxmlformats-officedocument.wordprocessingml.document",".docx"],
        ["application/vnd.rar",".rar"],
        ["application/vnd.visio",".vsd"],
        ["application/x-7z-compressed",".7z"],
        ["application/x-aspx",".aspx"],
        ["application/x-bat",".bat"],
        ["application/x-bzip",".bz"],
        ["application/x-bzip2",".bz2"],
        ["application/x-csh",".csh"],
        ["application/x-dosexec",".com"],
        ["application/x-dosexec",".dll"],
        ["application/x-dosexec",".exe"],
        ["application/x-freearc",".arc"],
        ["application/x-gzip",".gz"],
        ["application/x-httpd-php",".php"],
        ["application/x-javascript",".js"],
        ["application/x-jsp",".jsp"],
        ["application/x-powershell",".ps1"],
        ["application/x-powershell",".psd1"],
        ["application/x-powershell",".psm1"],
        ["application/x-rar",".rar"],
        ["application/x-sh",".sh"],
        ["application/x-shockwave-flash",".swf"],
        ["application/x-tar",".tar"],
        ["application/xhtml+xml",".xhtml"],
        ["application/xml",".xml"],
        ["application/zip",".zip"],
        ["image/bmp",".bmp"],
        ["image/gif",".gif"],
        ["image/jpeg",".jpeg"],
        ["image/jpeg",".jpg"],
        ["image/png",".png"],
        ["image/svg+xml",".svg"],
        ["image/tiff",".tif"],
        ["image/tiff",".tiff"],
        ["image/vnd.microsoft.icon",".ico"],
        ["text/ecmascript",".js"],
        ["text/javascript",".js"],
        ["text/javascript",".mjs"],
        ["text/vbscript",".vbs"],
        ["text/x-go",".go"],
        ["text/x-java",".java"],
        ["text/x-lua",".lua"],
        ["text/x-perl",".pl"],
        ["text/x-python",".py"],
        ["text/x-python",".pyw"],
        ["text/x-ruby",".rb"],
        ["text/x-sh",".bash"],
        ["text/x-sh",".ksh"],
        ["text/x-sh",".sh"],
        ["text/x-shellscript",".sh"],
        ["text/x-vb",".vb"]
        };
}

event file_state_remove (f: fa_file)
{
        local c: connection;
        for ( cid in f$conns )
                {
                c = f$conns[cid];
                break;
                }

	if ( f?$info && f$info?$filename ){ 
        	local this_fn = f$info$filename;
                # arbitrary 5 char file ext check, but most ext will be under this length.
        	local file_ext = find_last(this_fn,/\..{1,5}$/);
        	f$info$file_ext = file_ext;     
        	}

        if (! f$info?$mime_type && ! f$info?$file_ext) {return;} 

	if ( f$info?$mime_type && f$info?$file_ext && mimes in f$info$mime_type && [f$info$mime_type,f$info$file_ext] !in s1 ) {
                
                f$info$mismatch = T; 

                NOTICE([$note=Mismatch::Mimetype_Mismatch,
                        $msg=fmt("Mimetype and file extension mismatch seen. %s, %s", f$info$mime_type, f$info$file_ext),
                        $sub=f$info$filename,
                        $conn = c,
                        $fuid = f$id
                        ]);
        }
}
