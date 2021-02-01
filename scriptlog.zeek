# dlack 2021-01-01
#
# This script adds a new log that captures part (or all) of script-type files.
# Scripts may sometimes be moved around an environment post-compromise and used for things like:
# executing other native tools and binaries, archiving files and directories for exfil, 
# enumerating users/accounts/privileges, etc.
#
# The list of script file types was intentionally kept small but could easily be expanded.
# One option for tuning by filename is provided but other tuning options could be added
# (for ex. a check for an org-specific script header might be helpful.)
#
# https://attack.mitre.org/techniques/T1059/
#

@load base/frameworks/files

module Scriptlog;

export {
		redef enum Log::ID += { LOG };

		type Info: record { 
					ts: time	&log;
					uid: string &log;
					fuid: string &log;
					id: conn_id &log;
					mime_type: string &log &optional;
					filename: string &log &optional;
					buffer: string &log;
					};

# Have to check for both file extensions and mimetypes as sometimes script files will have a text/plain mimetype which would be too noisy to capture on its own.
# .bat, .csh, .ps1, .psd1, .psm1, .sh, .vbs, .go, .java, .lua, .pl, .py, .pyw, .rb, .bash, .ksh, .sh, .vb
		const script_exts = /\.([bB][aA][tT]|[cC][sS][hH]|[pP][sS][1]|[pP][sS][dD][1]|[pP][sS][mM][1]|[sS][hH]|[vV][bB][sS]|[gG][oO]|[jJ][aA][vV][aA]|[lL][uU][aA]|[pP][lL]|[pP][yY]|[pP][yY][wW]|[rR][bB]|[bB][aA][sS][hH]|[kK][sS][hH]|[sS][hH]|[vV][bB])$/ &redef;

		const script_mimetypes = /application\/x-bat|application\/x-csh|application\/x-powershell|application\/x-sh|text\/vbscript|text\/x-go|text\/x-java|text\/x-lua|text\/x-perl|text\/x-python|text\/x-ruby|text\/x-sh|text\/x-shellscript|text\/x-vb/&redef;	

		# Add filenames here to tune out specific admin scripts etc.
		const ignore_filenames = /ignore\.bat|ignore\.py|ignore\.ps1/ &redef;
}

redef record connection += {
	scriptlog: Info &optional;
};

event zeek_init() &priority=5
	{
	Log::create_stream(Scriptlog::LOG, [$columns=Info, $path="scriptlog"]);
	}

event file_sniff(f: fa_file, meta: fa_metadata)
	{
		local c: connection;
		for ( cid in f$conns )
			{
			c = f$conns[cid];
			break;
			}
		
		# return if no mimetype or filename
		if (! meta?$mime_type || ! f?$info && ! f$info?$filename) {return;}

		# return if we've tuned out the specific filename
		if (f?$info && f$info?$filename && ignore_filenames in f$info$filename) {return;}


		if ((meta?$mime_type && script_mimetypes in meta$mime_type) || (f?$info && f$info?$filename && script_exts in f$info$filename)) {

			if (f?$info && f$info?$filename){
				local fn = f$info$filename;
				}
			else {
				fn = "";
				}

			if (! meta?$mime_type){
		     	meta$mime_type = "";
				}
			# dumb way to ignore files with no mimetype or filename
			if (meta$mime_type == fn) return;

			local rec: Scriptlog::Info = [$ts=network_time(), $uid=c$uid, $fuid=f$id, $id=c$id, $mime_type=meta$mime_type, $filename=fn, $buffer=f$bof_buffer];
			Log::write(Scriptlog::LOG, rec);
		}
	}