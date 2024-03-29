use ExtUtils::MakeMaker qw(prompt WriteMakefile);

# See lib/ExtUtils/MakeMaker.pm for details of how to influence
# the contents of the Makefile that is written.

# mpopd Makefile.PL v0.01 17 March 2001
# (c) Mark Tiramani 1998-2001 markjt@fredo.co.uk
#
# This is an attempt to make configuration and installation
# of mpopd and Mail::POP3Server a bit easier. Opinions may vary
# as to whether Makefile.PL should attempt this. If you have an
# opinion either way please let me know.
#

#--- Reminders to edit configs
$configured = prompt("\nHave you edited the mpopd.conf file?: "
             ,"y|n");

die "\nPlease edit mpopd.conf to match your system first\n\n" unless $configured =~ /^y$/i;

$conf_dir = prompt("\nWhere should I install the mpopd.conf configuration file.\n"
				. "(Any existing mpopd.conf will be backed up to mpopd.conf-old.)\n\n"
				. "Enter the full path or press return for the default: "
				,"/usr/local/mpopd");

#--- Edit mpopd and mpopdctl and set-up new paths as necessary
unless ($conf_dir eq "/usr/local/mpopd") {
	undef $/;
	open MPOPD, "mpopd" || die "\nERROR Could not edit mpopd script, $!\n\n";
	$mpopd = <MPOPD>;
	close MPOPD;
	$mpopd =~ s/\nmy\s+\$config_file\s*=\s*.*?\n/\nmy \$config_file = \"$conf_dir\/mpopd\.conf\"\;\n/;
	open MPOPD, ">mpopd" || die "\nERROR Could not edit mpopd script, $!\n\n";
	print MPOPD $mpopd;
	close MPOPD;
	open MPOPDCTL, "mpopdctl" || die "\nERROR Could not edit mpopdctl script, $!\n\n";
	$mpopdctl = <MPOPDCTL>;
	close MPOPDCTL;
	$mpopdctl =~ s/\n\s*\$config_file\s*=\s*.*?\n/\n\$config_file = \"$conf_dir\/mpopd\.conf\"\;\n/;
	open MPOPDCTL, ">mpopdctl" || die "\nERROR Could not edit mpopdctl script, $!\n\n";
	print MPOPDCTL $mpopdctl;
	close MPOPDCTL;
	$/ = "\n";
}

#--- Make the config dir if needed and copy mpopd.conf to it.
unless (-d $conf_dir) {
	print "\nCreating directory: $conf_dir\n";
	system "mkdir -p $conf_dir" || die "\nERROR Could not create configuration directory: $conf_dir, $!\n\n";
}

print "\nCopying mpopd.conf to: $conf_dir\n";
system "cp -a $conf_dir/mpopd.conf $conf_dir/mpopd.conf-old" if -f "$conf_dir/mpopd.conf";
system "cp -a mpopd.conf $conf_dir/" || die "\nERROR Could not copy mpopd.conf to: $conf_dir, $!\n\n";

#--- Check if access rule files should be installed.
$configured = prompt("\nIf you are going to run mpopd in daemon mode you should have edited\n"
					. "the mpopd_trusted and mpopd_allow_deny files. These will be copied\n"
					. "into the same location as the mpopd.conf main configuration file\n"
					. "(ANY EXISTING ACCESS FILES WILL BE LEFT UNTOUCHED EVEN IF YOU SAY 'y' BELOW!).\n"
					. "These files are also used when mpopd is run from inetd if mpopd\n"
					. "finds them in the config directory\n\n"
					. "Should I install these access-rule files now?","y|n");

#--- If user answered y to above then back-up old access files and copy over new ones.
if ($configured =~ /^y$/i && !-f "$conf_dir/mpopd_trusted") {
	print "\nCopying mpopd_trusted to: $conf_dir\n";
	system "cp -a mpopd_trusted $conf_dir/" || die "\nERROR Could not copy mpopd_trusted to: $conf_dir, $!\n\n";
}
else {
	print "\nSkipping installation of mpopd_trusted\n"
}
if ($configured =~ /^y$/i && !-f "$conf_dir/mpopd_allow_deny") {
	print "\nCopying mpopd_allow_deny to: $conf_dir\n";
	system "cp -a mpopd_allow_deny $conf_dir/" || die "\nERROR Could not copy mpopd_allow_deny to: $conf_dir, $!\n\n";
}
else {
	print "\nSkipping installation of mpopd_allow_deny\n"
}

#--- Check which editor should be used for on-the-fly mpopd.conf editing.
$editor = prompt("\nWhich editor would you like to use to edit the mpopd.conf configuration file\n"
				. "for a running mpopd daemon when using the: mpopdctl -e config command\n\n"
				. "Enter the full path or press return for the default: "
				,"/usr/bin/vi");

#--- Edit mpopdctl to point to the selected editor if not 'vi'
unless ($editor eq "/usr/bin/vi") {
	undef $/;
	open MPOPDCTL, "mpopdctl" || die "\nERROR Could not edit mpopdctl script, $!\n\n";
	$mpopdctl = <MPOPDCTL>;
	close MPOPDCTL;
	$mpopdctl =~ s/\n\s*\$config_editor\s*=\s*.*?\n/\n\$config_editor = \"$editor\"\;\n/;
	open MPOPDCTL, ">mpopdctl" || die "\nERROR Could not edit mpopdctl script, $!\n\n";
	print MPOPDCTL $mpopdctl;
	close MPOPDCTL;
	$/ = "\n";
}

#--- Get the install dir for mpopd and mpopdctl
$installscript = prompt("\nWhere should I install the wrapper/helper scripts?\n\n"
				. "Enter the full path or press return for the default: "
				,"/usr/local/bin");

#--- Make the script dir if needed.
unless (-d $installscript) {
	system "mkdir -p $installscript" || die "\nERROR Could not create script directory: $installscript, $!\n\n";
}

unless ($installscript eq "/usr/local/bin") {
	undef $/;
	open MPOPDCTL, "mpopdctl" || die "\nERROR Could not edit mpopdctl script, $!\n\n";
	$mpopdctl = <MPOPDCTL>;
	close MPOPDCTL;
	$mpopdctl =~ s/\n\s*\$mpopd\s*=\s*.*?\n/\n\$mpopd = \"$installscript\/mpopd\"\;\n/;
	open MPOPDCTL, ">mpopdctl" || die "\nERROR Could not edit mpopdctl script, $!\n\n";
	print MPOPDCTL $mpopdctl;
	close MPOPDCTL;
	$/ = "\n";
}

#--- Copy the scripts into $installscript
print "\nCopying mpopd to: $conf_dir\n";
system "cp -a mpopd $installscript/" || die "\nERROR Could not copy mpopd to: $installscript, $!\n\n";
print "Copying mpopdctl to: $conf_dir\n";
system "cp -a mpopdctl $installscript/" || die "\nERROR Could not copy mpopdctl to: $installscript, $!\n\n";
print "Copying mpopd_test to: $conf_dir\n";
system "cp -a mpopd_test $installscript/" || die "\nERROR Could not copy mpopd_test to: $installscript, $!\n\n";
print "Setting script permissions to: 0750\n\n";
system "chmod 0750 $installscript/mpopd $installscript/mpopdctl $installscript/mpopd_test" || die "\nERROR Could not set script permissions, $!\n\n";

#--- Can't get WriteMakefile() to do this properly? so we'll do the long way
system "pod2man POP3Server.pm > mpopd.1";
system "pod2man mpopdctl > mpopdctl.1";
system "pod2man mpopd_test > mpopd_test.1";
system "cp mpopd.1 mpopdctl.1 mpopd_test.1 /usr/man/man1" || print "\nCouldn't copy mpopd, mpopdctl and mpopd_test manpages to /usr/man/man1\n\n";

#--- Make the Makefile.
WriteMakefile(
	'NAME' => 'Mail::POP3Server',
	'DISTNAME' => "Mail-POP3Server",
	'VERSION_FROM' => 'POP3Server.pm',
	'dist' => {
		COMPRESS => "gzip -9f",
		SUFFIX => "gz",
	}
);

print "\nNow type:\n\nmake\nmake install\n\nThere is no 'make test' as yet\n\n";

###################  BOTTOM LINE  ###########################