package Mail::POP3Server;

#### This is the heart of the mpopd POP3 server
# POP3Server.pm v2.22 25 July 2001
# (c) Mark Tiramani 1998-2001 markjt@fredo.co.uk

require Exporter;
@ISA = qw(Exporter);
@EXPORT = qw(ReadConfig StartPOP3Server StartDaemon);
use strict;
no strict qw(refs);

#### Standard socket lib is fine since we roll our own CLIENT, SERVER
use Socket;

#### sys_wait_h so mpopd can use WNOHANG in the child reaper
use POSIX qw(sys_wait_h);

#### Most of these are configuration variables.
use vars qw(@ISA @EXPORT $VERSION $allow_non_fqdn $auth_type $reject_bogus_user $debug %debug
$debug_log $debuglog_dir $end_message %forwardto $greeting $host_mail_path $hosts_allow_deny
%user_log $mail_spool_dir $mailgroup $max_servers $md5_no_pam $message_end $message_start
$mpopd_conf_version $mpopd_failed_mail $mpopd_pam_service $mpopd_pid_file $mpopd_spool
$parse_to_disk $passsecret $password_plugin $path_to_homedir $path_to_maildir $receivedfrom
$retry_on_lock $shadow $switch $timeout $timezone $trusted_networks $uidok $use_maildir
$use_pam $user_log_dir $userlist $username_plugin %user_auth $status);

$VERSION = "2.22";

my ($config_file,$port);
sub ReadConfig {

	$config_file = shift;

	require "$config_file";

	#### mpopd config files have a version number of their own which must
	#### be the same as the POP3Server.pm version. As mpopd develops, new features
	#### may require new config items or syntax so the version number of
	#### the config file must be checked first.
	return("\nSorry, you must use an mpopd config file conforming
	to config version $VERSION with POP3Server.pm v$VERSION
	Your config file is version $mpopd_conf_version\n\n")
	if $mpopd_conf_version ne $VERSION;
	&MakeSane;
	return 1;

}

#### A little hack so that the config can be re-read on the fly.
#### The a-y scalars/arrays are all reset in READCONFIG and MPOPDRESTART
my $zconfig_file = $config_file;
my $zmpopd_version = $VERSION;

sub MakeSane {

	#### Create a sane environment if not configured in mpop.conf
	$port = "110" if $port !~ /^\d+$/;
	$message_start = "From " if $message_start !~ /^\w+$/;
	$message_end = "^\\s+\$" if $message_end !~ /^\S+$/;
	$timeout = 10 if $timeout !~ /^\d+$/;
	#### Make disk-based parsing the default
	$parse_to_disk = 1 unless defined($parse_to_disk);
	#### Try and make the sanest guess at the mailbox location
	if ($use_maildir == 1 && $path_to_maildir !~ /\S+/) {
		$path_to_homedir = "/home";
	}
	elsif (!-d "$mail_spool_dir") {
		$mail_spool_dir = "/var/spool/mail";
	}

}

#### Set the expected \r\n line ending
my $CRLF = "\015\012";

#### These are the only commands accepted
my @COMMANDS = ("USER",
				"PASS",
				"LIST",
				"STAT",
				"RETR",
				"DELE",
				"RSET",
				"LAST",
				"QUIT",
				"NOOP",
				"UIDL",
				"TOP"
				);

my ( $paddr,$command,$arg,$arg1,$crypt_password,$debug_open,%delete,$delmessagecnt,
	$deltotaloctets,%from_line,$initial,$lastaccess,$line,$maildir,@maildir,$messagecnt,
	$mpopd,%octets,$opened,$openmod,$pass,$totaloctets,$uid,$uidl,%uidl,$user_id,
	$ip,$fqdn,$zkids,%zkids,$input_fh,$output_fh,%status);

############################################################
#### The main POP3 routines are all enclosed within StartPOP3Server
sub StartDaemon {

	my $custom_port = shift;
	$port = $custom_port if $custom_port  =~ /^\d{3,4}$/;

	#### Try and rescue a broken pipe or interrupt attempt by rebuilding
	#### the server-socket etc.
	$SIG{PIPE} = \&MPOPDRESTART;
	$SIG{INT} = \&MPOPDRESTART;
	#### Ignore alarm signals from kernel
	$SIG{ALRM} = "IGNORE";

	#### Build the server socket and bind to $port
	&BuildServer;

	#### Create parent socket and bind to POP3 port (or custom port)
	sub BuildServer {

		#### Set up the server socket
		socket(SERVER, PF_INET, SOCK_STREAM, getprotobyname('tcp'));

		#### Set up for quick restart
		setsockopt(SERVER, SOL_SOCKET, SO_REUSEADDR, 1);

		### Set up socket address
		my $my_addr = sockaddr_in($port, INADDR_ANY);
		bind(SERVER, $my_addr) || &TimeIsUp("Couldn't bind to port $port : $!\n");

		### Establish a queue for incoming connections.
		listen(SERVER, SOMAXCONN) || &TimeIsUp("Couldn't listen on port $port : $!\n");

		#### Write a pid file with the port used on line 2
		open MPOPDPID, ">$mpopd_pid_file";
		print MPOPDPID "$$\n$port\n";
		close MPOPDPID;

	}

	#### If we get a plain kill then try and close down all child
	#### servers, remove pid file and exit.
	$SIG{TERM} = \&MPOPDQUIT;

	sub MPOPDQUIT {
		my $key;
		foreach $key (keys %zkids) {
			kill "USR1", $key;
			&REAPER;
		}
		close SERVER;
		unlink "$mpopd_pid_file";
		exit;
	}

	#### Just re-read the config file on a SIGUSR1, don't restart.
	$SIG{USR1} = \&READCONFIG;

	sub READCONFIG {
		reset 'a-y';
		do "$config_file";
		&MakeSane;
		$SIG{USR1} = \&READCONFIG;
	}

	#### If we receive a SIGHUP kill off the forked servers gracefully(?)
	#### with a SIGUSR1, close and re-open the server socket, reset as much
	#### as possible and then re-read the config file.
	$SIG{HUP} = \&MPOPDRESTART;

	sub MPOPDRESTART {
		my $key;
		foreach $key (keys %zkids) {
			kill "USR1", $key;
			&REAPER;
		}
		close SERVER;
		reset 'a-y';
		do "$zconfig_file";
		&MakeSane;
		&BuildServer;
		reset 'z';
		$SIG{HUP} = \&MPOPDRESTART;
		$SIG{PIPE} = \&MPOPDRESTART;
		$SIG{INT} = \&MPOPDRESTART;
	}

	#### Catch SIGCHLD
	$SIG{CHLD} = \&REAPER;

	#### Counter used to track number of children
	$zkids = 0;

	sub REAPER {
		my $kidpid;
		while (($kidpid = waitpid(-1, WNOHANG)) > 0) {
			--$zkids;
			delete $zkids{$kidpid};
		}
		$SIG{CHLD} = \&REAPER;
	}

	#### Listen for a client and fork off a child server process
	while (1) {

		my $paddr;

		#### Trap errors caused by peer-resets etc.
		unless ( eval { $paddr = accept(CLIENT, SERVER) } ) {
			close CLIENT;
			next;
		}

		#### Close the connection if this one would exceed the maximum
		#### concurrent servers allowed, $max_servers.
		unless ($zkids < $max_servers) {
			close CLIENT;
			sleep 2;
			next;
		}

		#### Try and fork
		my $kidpid;
		if ($kidpid = fork) {
			++$zkids;
			$zkids{$kidpid} = 1;
			next;
		}

		#### If fork fails log the event to a file
		unless (defined $kidpid) {
			open NOFORK, ">/usr/local/mpopd/fork_alert";
			print NOFORK "Fork failed at: ", localtime(time), ": $!\n";
			close NOFORK;
			close CLIENT;
			next;
		}

		#### Everything below here (almost) belongs to the child server.

		#### Close clone of SERVER handle.
		close SERVER;

		&StartPOP3Server(0,$paddr);

	}

}

############################################################
#### Do the security checks and then get get the first command
sub StartPOP3Server {

	(my $inetd,$paddr,my $custom_port) = @_;
	$port = $custom_port if $custom_port  =~ /^\d{3,4}$/;

	#### If mpopd is called from inetd the file-handles
	#### need setting up appropriately
	if ($inetd == 1) {
		$input_fh = \*STDIN;
		$output_fh = \*STDOUT;
	}
	else {
		$input_fh = \*CLIENT;
		$output_fh = \*CLIENT;
	}

	#### Set the default output file handle
	select $output_fh;

	$| = 1;

	#### Try and catch anything nasty and restore mailbox. This can lead to emails
	#### being downloaded more than once but at least they shouldn't be lost.
	local $SIG{HUP} = \&TimeIsUp;
	local $SIG{TERM} = \&TimeIsUp;
	local $SIG{PIPE} = \&TimeIsUp;
	local $SIG{USR1} = \&TimeIsUp;
	local $SIG{SEGV} = \&TimeIsUp;
	#### Catch kernel alarms and close gracefully if the client stalls
	local $SIG{ALRM} = \&TimeIsUp;

	#### SECURITY CHECKS
	#### Get the client's IP and FQDN. We don't have tcpwrapper protection in daemon
	#### mode and therefore need to do a reverse lookup. $allow_non_fqdn can be set to 1
	#### to effectively disable reverse lookups.
	$ip = "";
	$fqdn = "";
	my $reject = &PeerLookup("YES");
	#### Make an exception for trusted networks
	my $secure = 0;
	if (-f "$trusted_networks") {
		open SECURENETS, "$trusted_networks";
		while (<SECURENETS>) {
			next if /^\#/;
			next if /^\s+$/;
			chomp;
			s/\s+|\*//g;
			if ($ip =~ /^$_/ || $fqdn =~ /^$_$/) {
				$secure = 1;
				last;
			}
		}
		close SECURENETS;
	}
	if ($reject == 2 && $allow_non_fqdn == 0 && $secure != 1) {
		&mpopLog("$ip\tFAILED reverse lookup at") if $debug == 1;
		&mpopdExit;
	}
	#### Check a seperate blocking list for particular client's/networks
	if (-s "$hosts_allow_deny") {
		my $deny_all = 0;
		my $allowed = 0;
		open ALLOWDENY, "$hosts_allow_deny";
		while (<ALLOWDENY>) {
			next if /^\#/;
			next if /^\s+$/;
			chomp;
			#### Each line can be one action, DENY, ALLOW or WARN, followed by
			#### an IP, subnet or hostname, whereby 'ALL' is a special case.
			#### If the special rule 'DENY ALL' appears anywhere then
			#### a client will be refused unless they match an 'ALLOW' line.
			#### Lines starting with '#' or whitespace are skipped.
			my ($action,$peer) = split /\s+/, $_;
			$action =~ s/\s+//g;
			$peer =~ s/\s+|\*//g;
			if ($action =~ /deny/i && $peer =~ /all/i) {
				$deny_all = 1;
			}
			elsif ($ip =~ /^$peer/ || $fqdn =~ /^$peer$/i) {
				if ($action =~ /allow/i) {
					&mpopLog("$ip\tALLOWED connection at") if $debug == 1;
					$allowed = 1;
					last;
				}
				elsif ($action =~ /warn/i) {
					&mpopLog("$ip\tWARN connected at") if $debug == 1;
				}
				elsif ($action =~ /deny/i && $peer !~ /all/i) {
					&mpopLog("$ip\tDENIED connection at") if $debug == 1;
					&mpopdExit;
				}
			}
		}
		close ALLOWDENY;
		if ($deny_all == 1 && $allowed == 0) {
			&mpopLog("$ip\tDENIED connection at") if $debug == 1;
			&mpopdExit;
		}
	}

	#### Log the connection IP and time if global debugging is on
	if ($debug && $debug == 1) {
		&mpopLog("$ip\tconnected at");
	}

	# Send the mpopd greeting.
	$greeting =~ s/([\w\.-_:\)\(]{50}).*/$1/;
	print "+OK $greeting$CRLF";

	$command = "";
	$arg = "";
	$arg1 = "";
	$crypt_password = "";
	$debug_open = 0;
	$delmessagecnt = 0;
	$deltotaloctets = 0;
	$initial = "";
	$lastaccess = 0;
	$line = 0;
	$maildir = "";
	$messagecnt = 0;
	$mpopd = "";
	$opened = 0;
	$openmod = 0;
	$pass = 0;
	$totaloctets = 0;
	$uid = "";
	$uidl ="";
	$user_id = "";

	&GetCommand;

}

############################################################
#### mpop returns here after all POP3 commands, except QUIT
sub GetCommand {

	$arg = "";
	$line = 0;
	my $request = "";
	my $char;

	while (1) {
		#### Set the kernel alarm for $timeout seconds and then only
		#### wait that long for the next command from the client.
		#### The whole read process is eval'ed. See man perlfunc -> portability
		eval {
			local $SIG{ALRM} = sub { die "alarm\n" }; # NB: \n required
			alarm $timeout;
			$char = getc($input_fh);
			alarm 0;
		};
		if ($@) {
			&TimeIsUp if $@ eq "alarm\n";
		}
		else {
		    last unless (defined($char));
		    last if ($char eq "\012");
		    $request .= $char;
		    &TimeIsUp if (length($command) > 50);
		}
	}
	&TimeIsUp unless (defined($char));

	# remove all but alphanumeric chars and whitespace from the
	# request, and only accept 3-50 chars total (UIDL could be long'ish)
	$request =~ s/^([\s\w]{3,50})/$1/g;
	$request =~ s/\r|\n//g;

	($command,$arg,$arg1) = split /\s+/,$request;
	$command = uc $command;
	my $commandok = 0;

	&DebugUser("$command  $arg  $arg1");

	# check for a valid command, close if not
	foreach (@COMMANDS) {
		$commandok = 1 if $command eq $_;
	}

	#### Close and warn if an invalid command is received
	if ($commandok != 1) {
		&PeerLookup("NO");
		&mpopLog("$ip\tWARN no command sent, port scan? at") if $debug == 1;
		&TimeIsUp("So, that's the way you want it... :\($CRLF");
	}

	&{'command'.$command};

}

############################################################
#### Check the user name supplied against whatever authentication
#### method is set (e.g. /etc/passwd) and extract the password
sub commandUSER {

	$uid = $arg;

	#### Allow for per-user authentication switch
	if ($user_auth{"$uid"} > 0) {
		$auth_type = $user_auth{"$uid"};
	}

	if ($auth_type == 1) {
		$uidok = &EtcPwdShadow($uid);
		&AuthFailed if $uidok == 2;
	}
	elsif ($auth_type == 2) {
		$uidok = &EtcPwdShadow($uid);
		if ($uidok == 2) {
			&PeerLookup;
			&ReadUserList;
		}
		&AuthFailed if $uidok == 2;
	}
	elsif ($auth_type == 3) {
		$uidok = &EtcPwdShadow($uid);
		if ($uidok == 2) {
			if ($uid =~ /\@/) {
				&SplitEmail;
			}
			else {
				&PeerLookup;
			}
			$uidok = &ReadUserList($uid,$initial);
		}
		&AuthFailed if $uidok == 2;
	}
	elsif ($auth_type == 4) {
		&PeerLookup;
		$uidok = &ReadUserList($uid,$initial);
		&AuthFailed if $uidok == 2;
	}
	elsif ($auth_type == 5) {
		if ($uid =~ /\@/) {
			&SplitEmail;
		}
		else {
			&PeerLookup;
		}
		$uidok = &ReadUserList($uid,$initial);
		&AuthFailed if $uidok == 2;
	}
	elsif ($auth_type == 6) {
		$uidok = &ReadUserList($uid);
		&AuthFailed if $uidok == 2;
	}
	elsif ($auth_type == 7) {
		$uidok = (do "$username_plugin");
		&AuthFailed if $uidok == 2;
	}
	else {
		&AuthFailed;
	}

	&GetCommand;

}

############################################################
####
sub commandPASS {

	if ($uidok == 0) {
		#### Check the password supplied
		if (&CheckPassword == 0 && $opened != 1) {
			my $addedbytes;
			$pass = 1;
			#### Check to see if the qmail 'maildir' mailbox format should be used
			#### or default to Berkeley mbox type mailbox
			if (!$use_maildir || $use_maildir != 1) {
				my $lockcnt = 0;
GETLOCK:
				if (-s "$mail_spool_dir/$uid" && !-f "$mail_spool_dir/$uid.lock") {
					#### Slightly paranoid mailbox locking...
					open LOCKFILE, ">$mail_spool_dir/$uid.lock";
					unless (flock LOCKFILE, 2|4) {
						unlink "$mail_spool_dir/$uid.lock";
						&TimeIsUp("Could not flock $mail_spool_dir/$uid.lock... :|($CRLF");
					}
					chmod 0600, "$mail_spool_dir/$uid.lock";
					chown $user_id, $mailgroup, "$mail_spool_dir/$uid.lock";
					&PrintLock;
					#### set effective UID to user for the rest of the session;
					$> = $user_id;
					#### stat the file to get its size, this is checked before closing the mailbox.
					#### If the size has changed the lock may have been compromised, so a backup is then made.
					my @filestat = stat "$mail_spool_dir/$uid";
					$openmod = $filestat[9];
					if (!$forwardto{$uid} || $forwardto{$uid} != 1) {
						$mpopd = "Received: from $receivedfrom$CRLF\tby mpopd V$zmpopd_version$CRLF\tfor $uid; ".localtime(time)." $timezone".$CRLF;
						$addedbytes = length($mpopd);
					}
					#### start reading the mailbox
					open MDROP,"$mail_spool_dir/$uid";
					$_ = <MDROP>;
					$opened = 1;
					#### check for a valid first line, if not report no message status to client and close
					if (/^$message_start/) {
						$messagecnt = 1;
						#### Hold the "From ..." line to put back if message is not retrieved
						s/\n|\r//g;
						$from_line{$messagecnt} = $_;
						#### now get the second line, which may hold the mpopd UIDL ID
						$_ = <MDROP>;
						#### check/create the unique ID code
						&UIDL;
						&PushMessage;
						$octets{$messagecnt} += $addedbytes;
						while (<MDROP>) {
							&PrintLockCount;
							if ($end_message == 1 && /^$message_start/) {
								$totaloctets += $octets{$messagecnt};
								++$messagecnt;
								s/\n|\r//g;
								#### Hold the "From ..." line to put back if message is not retrieved
								$from_line{$messagecnt} = $_;
								#### now get the second line, which may hold the UIDL ID
								$_ = <MDROP>;
								#### check/create the unique ID code, and create a new temp
								#### message if $parse_to_disk == 1
								&UIDL;
								&PushMessage;
								$octets{$messagecnt} += $addedbytes;
							}
							else {
								$end_message = 0;
								if (/$message_end/) {
									$end_message = 1;
								}
								&PushMessage;
							}
						}
						$> = 0;
						if (seek MESSAGE, -2, 2) {
							print MESSAGE "\0";
							close MESSAGE;
						}
						$> = $user_id;
						$totaloctets += $octets{$messagecnt};
						print "+OK thanks $uid. Got a lock on your mailbox..$CRLF";
						&DebugUser("+OK thanks $uid. Got a lock on your mailbox..");
					}
					else {
						$> = 0;
						$opened = 0;
						close LOCKFILE;
						unlink "$mail_spool_dir/$uid.lock";
						print "+OK no messages for you $uid TTFN$CRLF";
						&DebugUser("+OK no messages for you $uid TTFN");
					}
				}
				elsif (-s "$mail_spool_dir/$uid") {
					if ($retry_on_lock > 0) {
						++$lockcnt;
						if ($lockcnt == $retry_on_lock) {
							print "+OK Could not get a lock on mailbox!$CRLF";
							my $logtime = localtime(time);
							&DebugUser("$logtime +OK Could not get a lock on mailbox!");
						}
						else {
							sleep 1;
							&PrintLock;
							goto GETLOCK;
						}
					}
					else {
						$messagecnt = 0;
						$totaloctets = 0;
						print "+OK Could not get a lock on mailbox!$CRLF";
						my $logtime = localtime(time);
						&DebugUser("$logtime +OK Could not get a lock on mailbox!");
					}
				}
				else {
					print "+OK thanks $uid, no messages yet though...$CRLF";
					&DebugUser("+OK thanks $uid, no messages yet though...$CRLF");
				}
			}
			else {
				#### Use qmail-style 'maildir' mailboxes.
				#### Try and find the user's Maildir or equivalent
				my @user_info = getpwnam $uid;
				my $home = $user_info[7];
				if (open QMAIL, "$home/.qmail") {
					$maildir = <QMAIL>;
					close QMAIL;
					chomp $maildir;
					$maildir =~ s/\/$//;
					$maildir =~ s/^\.//;
					$maildir =~ s/^\///;
					$maildir = "$home/$maildir";
				}
				else {
					$maildir = "$path_to_homedir/$uid/Maildir";
				}
				opendir MAILDIR, "$maildir/new";
				@maildir = grep !/^\./, readdir MAILDIR;
				closedir MAILDIR;
				@maildir = sort @maildir;
				&StatMailDir(\@maildir,$addedbytes);
				print "+OK thanks $uid...$CRLF";
				&DebugUser("+OK thanks $uid...");
				#### Slightly paranoid mailbox locking...
				if (!-f "$maildir/new/.mpopd.lock") {
					open MAILDIRLOCK, ">>$maildir/new/.mpopd.lock";
					unless (flock MAILDIRLOCK, 2|4) {
						unlink "$maildir/new/.mpopd.lock";
						&TimeIsUp("Could not flock $maildir/new/.mpopd.lock... :|($CRLF");
					}
					$opened = 1;
				}
				else {
					&TimeIsUp("Maildir/new lockfile already exists... :|($CRLF");
				}
			}
		}
		else {
			print "-ERR access denied $uid $arg $CRLF";
			if (defined($user_log{"$uid"})) {#
				my $logtime = localtime(time);
				print USERLOG "$logtime -ERR access denied $uid $arg\n\n";
				close USERLOG;
			}
			&mpopdExit;
		}
	}
	else {
		print "-ERR I need your USER name first!$CRLF";
		&DebugUser("-ERR I need your USER name first!");
	}

	&GetCommand;

}

############################################################
####
sub commandSTAT {

	if ($pass == 1) {
		my $resp = "+OK ".($messagecnt - $delmessagecnt)." ".($totaloctets - $deltotaloctets);
		print "$resp$CRLF";
		&DebugUser($resp);
	}
	else {
		print "-ERR not logged in yet! ($command)$CRLF";
		&DebugUser("-ERR not logged in yet! ($command)");
	}

	&GetCommand;

}

############################################################
####
sub commandLIST {

	if ($delete{$arg} != 1) {
		if ($pass == 1) {
			if (! $arg || $arg <= $messagecnt) {
				if ($arg > 0) {
					print "+OK $arg $octets{$arg}$CRLF";
				}
				else {
					print "+OK ",($messagecnt - $delmessagecnt)," messages$CRLF";
					for (1..$messagecnt) {
						if ($delete{$_} != 1) {
							print "$_ $octets{$_} octets$CRLF";
						}
					}
					print ".$CRLF";
				}
				&DebugUser("+OK (list stats)");
			}
			else {
				print "-ERR whoa! no such message$CRLF";
				&DebugUser("-ERR whoa! no such message");
			}
		}
		else {
			print "-ERR not logged in yet!$CRLF";
			&DebugUser("-ERR not logged in yet!");
		}
	}
	else {
		print "-ERR message $arg is marked for deletion!$CRLF";
		&DebugUser("-ERR message $arg is marked for deletion!");
	}

	&GetCommand;

}

############################################################
#### Send the email requested by $arg to the client
sub commandRETR {

	if ($delete{$arg} != 1) {
		if ($pass == 1) {
			#### Send the email to the client if it exists
			if ($arg > 0 && $arg <= $messagecnt) {
				print "+OK $octets{$arg} octets$CRLF";
				print $mpopd;
				if ($use_maildir && $use_maildir == 1) {
					#### $maildir is the full /path/file and starts at 0 !
					open MDIRMAIL, "$maildir/new/$maildir[$arg - 1]";
					while (<MDIRMAIL>) {
						chomp;
						#### remove the LDA's >From  escaping
						s/^>From /From /o;
						#### byte-stuff lines starting with .
						s/^\./\.\./o;
						&PrintLockCount;
						print "$_$CRLF";
					}
					close MDIRMAIL;
				}
				elsif ($parse_to_disk == 1) {
					$> = 0;
					open SPOOL, "$mpopd_spool/$uid/$arg";
					while (<SPOOL>) {
						chomp;
						s/^>From /From /o;
						s/^\./\.\./o;
						&PrintLockCount;
						print "$_$CRLF";
					}
					close SPOOL;
					$> = $user_id;
					# set the message status for the Status: header
					$status{$arg} = "RO";
				}
				else {
					foreach (@{"message".$arg}) {
						s/^>From /From /o;
						s/^\./\.\./o;
						&PrintLockCount;
						print $_;
						#### the escaping / byte-stuffing is put back
						#### in case the message is not deleted
						s/^From />From /o;
						s/^\.\./\./o;
					}
				}
				print ".$CRLF";
				if (defined($user_log{"$uid"})) {
					my $logtime = localtime(time);
					print USERLOG "RETRieved\t$octets{$arg}\t$logtime\n";
				}
				if ($arg > $lastaccess) {$lastaccess = $arg;}
			}
			else {
				print "-ERR retrieve which message?$CRLF";
				&PrintLock;
				&DebugUser("-ERR retrieve which message?");
			}
		}
		else {
			print "-ERR not logged in yet!$CRLF";
			&DebugUser("-ERR not logged in yet!");
		}
	}
	else {
		print "-ERR message $arg is marked for deletion!$CRLF";
		&PrintLock;
		&DebugUser("-ERR message $arg is marked for deletion!");
	}

	&GetCommand;

}

############################################################
####
sub commandDELE {

	if ($delete{$arg} != 1) {
		if ($pass == 1) {
			if ($arg > 0 && $arg <= $messagecnt) {
				print "+OK message $arg flagged for deletion$CRLF";
				&PrintLock;
				&DebugUser("+OK message $arg flagged for deletion");
				$delete{$arg} = 1;
				$delmessagecnt += 1;
				$deltotaloctets += $octets{$arg};
				if ($arg > $lastaccess) {$lastaccess = $arg;}
			}
			else {
				print "-ERR delete which message?$CRLF";
				&DebugUser("-ERR delete which message?");
			}
		}
		else {
			print "-ERR not logged in yet!$CRLF";
			&DebugUser("-ERR not logged in yet!");
		}
	}
	else {
		print "-ERR message $arg already marked for deletion!$CRLF";
		&PrintLock;
		&DebugUser("-ERR message $arg already marked for deletion!");
	}

	&GetCommand;

}

############################################################
####
sub commandNOOP {

	print "+OK$CRLF";
	&PrintLock;
	&DebugUser("+OK");

	&GetCommand;

}

############################################################
####
sub commandLAST {

	print "+OK $lastaccess$CRLF";
	&PrintLock;
	&DebugUser("+OK $lastaccess");

	&GetCommand;

}

############################################################
####
sub commandRSET {

	undef %delete;
	undef $delmessagecnt;
	undef $deltotaloctets;
	print "+OK all message flags reset$CRLF";
	&PrintLock;
	&DebugUser("+OK all message flags reset");

	&GetCommand;

}

############################################################
####
sub commandUIDL {

	if ($pass == 1) {
		if ($arg > 0 && $arg <= $messagecnt && $delete{$arg} != 1) {
			print "+OK $arg $uidl{'message'.$arg}$CRLF";
			&PrintLock;
			&DebugUser("+OK $arg $uidl{'message'.$arg}");
		}
		elsif ($arg) {
			print "-ERR unique-id for which message?$CRLF";
			&PrintLock;
			&DebugUser("-ERR unique-id for which message?");
		}
		else {
			print "+OK unique-id listing follows$CRLF";
			for (1..$messagecnt) {
				&PrintLock;
				if ($delete{$_} != 1) {
					print "$_ $uidl{'message'.$_}$CRLF";
				}
			}
			print ".$CRLF";
			&DebugUser("+OK unique-id listing follows");
		}
	}
	else {
		print "-ERR not logged in yet!$CRLF";
		&DebugUser("-ERR not logged in yet!");
	}

	&GetCommand;

}

############################################################
####
sub commandTOP {

	my $cnt;

	if ($pass == 1) {
		if ($arg1 >= 0 && $arg > 0 && $arg <= $messagecnt && $delete{$arg} != 1) {
			my $top_bytes = 0;
			print "+OK top of message $arg follows$CRLF";
			if ($use_maildir && $use_maildir == 1) {
				open MDIRMAIL, "$maildir/new/$maildir[$arg - 1]";
				#### print the headers
				while (<MDIRMAIL>) {
					last if /^\s+$/;
					chomp;
					&PrintLockCount;
					print "$_$CRLF";
					$top_bytes += length("$_$CRLF");
				}
				print "$CRLF";
				$cnt = 0;
				#### print the TOP arg number of body lines
				while (<MDIRMAIL>) {
					++$cnt;
					last if $cnt > $arg1;
					#### remove the LDA's >From  escaping
					s/^>From /From /o;
					#### byte-stuff lines starting with .
					s/^\./\.\./o;
					&PrintLockCount;
					chomp;
					print "$_$CRLF";
					$top_bytes += length("$_$CRLF");
				}
				close MDIRMAIL;
			}
			elsif ($parse_to_disk == 1) {
				$> = 0;
				open SPOOL, "$mpopd_spool/$uid/$arg";
				while (<SPOOL>) {
					last if /^\s+$/;
					chomp;
					&PrintLockCount;
					print "$_$CRLF";
					$top_bytes += length("$_$CRLF");
				}
				print "$CRLF";
				$cnt = 0;
				while (<SPOOL>) {
					++$cnt;
					last if $cnt > $arg1;
					s/^>From /From /o;
					s/^\./\.\./o;
					&PrintLockCount;
					chomp;
					print "$_$CRLF";
					$top_bytes += length("$_$CRLF");
				}
				close SPOOL;
				$> = $user_id;
			}
			else {
				my $rows = (scalar @{"message".$arg}) -1;
				$arg1 = $rows if $arg1 > $rows;
				$cnt = 0;
				foreach (@{"message".$arg}) {
					++$cnt;
					s/^>From /From /o;
					&PrintLockCount;
					print $_;
					$top_bytes += length($_);
					last if /^\s+$/;
				}
				for ($cnt..(($cnt + $arg1) -1)) {
					&PrintLockCount;
					${"message".$arg}[$_] =~ s/^>From /From /o;
					${"message".$arg}[$_] =~ s/^\./\.\./o;
					print ${"message".$arg}[$_];
					${"message".$arg}[$_] =~ s/^From />From /o;
					${"message".$arg}[$_] =~ s/^\.\./\./o;
					$top_bytes += length($_);
				}
			}
			print ".$CRLF";
			&DebugUser("+OK top of message $arg follows");
			if (defined($user_log{"$uid"})) {
				my $logtime = localtime(time);
				print USERLOG "RETRieved\t$top_bytes\t$logtime\n";
			}
		}
		else {
			print "-ERR TOP what?$CRLF";
			&PrintLock;
			&DebugUser("-ERR TOP what?");
		}
	}
	else {
		print "-ERR not logged in yet!$CRLF";
		&DebugUser("-ERR not logged in yet!");
	}

	&GetCommand;

}

############################################################
####
sub commandQUIT {

	&TimeIsUp("+OK TTFN $uid...$CRLF");

}

############################################################
#### Reject bogus login name and exit or fake a password auth
sub AuthFailed {

	&mpopLog("$ip\tBOGUS user name given at") if $debug == 1;

	if ($reject_bogus_user == 1) {
		print "-ERR no record here of $uid,...$CRLF";
		&mpopdExit;
	}
	else {
		my $request;
		print "+OK $uid send me your password....$CRLF";
		alarm 10;
		sysread $input_fh, $request, 1;
		alarm 0;
		print "-ERR access denied$CRLF";
		&mpopdExit;
	}

}

############################################################
#### Get the remote IP, and hostname and do a reverse lookup,
#### unless $lookup eq "NO".
sub PeerLookup {

	my $lookup = shift;

	my ($uport,$uaddr) = unpack_sockaddr_in($paddr);
	$ip = inet_ntoa($uaddr);
	unless ($lookup eq "NO") {
		$fqdn = gethostbyaddr(inet_aton($ip), AF_INET);
		my @addr = gethostbyname($fqdn);
		#### See if any of the domain names returned matches the IP
		#### and return an error if none does.
		if (grep { $ip eq inet_ntoa($_) } @addr[4..$#addr]) {
			return 0;
		}
		else {
			return 2;
		}
		$fqdn =~ tr/A-Z/a-z/;
		$fqdn =~ /^(.)/;
		$initial = $1;
	}

}

############################################################
#### Get the user-name and domain from a full someone@somewhere.co.uk
#### USER login. For domain name based mbox hashing
sub SplitEmail {

	($uid,$fqdn) = split /@/,$uid;
	$fqdn =~ /^(.)/;
	$initial = $1;

}

############################################################
#### Read a non-system password file for domain-name hashed
#### mail boxes. Format: username:password:uid
####              e.g. markjt:$1$d56geIhf$agr7nng92bgf32:100
#### The uid should correspond to the system 'mail' user or
#### a special 'mpopd' system user in /etc/passwd
sub ReadUserList {

	my ($uid,$initial) = @_;

	open(USERLIST,"$host_mail_path/$initial/$fqdn/$userlist");
	while (<USERLIST>) {
		if (/^$uid:/) {
			($uid,$crypt_password,$user_id) = split /:/, $_;
			last;
		}
	}
	close USERLIST;
	if (defined($crypt_password)) {
		unless ($switch == 1 || $auth_type == 6) {
			$mail_spool_dir = "$host_mail_path/$initial/$fqdn";
		}
		print "+OK $uid send me your password...$CRLF";
		&LogUser;
		&DebugUser("$command  $arg  $arg1\n+OK $uid send me your password....");
		return 0;
	}
	else {
		return 2;
	}

}

############################################################
#### Get the users' numeric uid and crypt/crypt_MD5 password
sub EtcPwdShadow {

	my $uid = shift;
	my @pwdentry;

	if (defined($shadow)) {
		open SHADOW, $shadow || &TimeIsUp("Could not open $shadow $CRLF");
		unless (flock SHADOW, 2|4) {
			&TimeIsUp("Could not flock $shadow $CRLF");
		}
		while (<SHADOW>) {
			if (/^$uid:(.+?):/) {
				$crypt_password = $1;
				$user_id = getpwnam $uid;
				last;
			}
		}
		close SHADOW;
		if (defined($crypt_password)) {
			print "+OK $uid send me your password....$CRLF";
			&LogUser;
			&DebugUser("$command  $arg  $arg1\n+OK $uid send me your password....");
			return 0;
		}
		else {
			return 2;
		}
	}
	elsif (@pwdentry = getpwnam $uid) {
		$user_id =  getpwnam $uid;
		$crypt_password = $pwdentry[1];
		print "+OK $uid send me your password....$CRLF";
		&LogUser;
		&DebugUser("$command  $arg  $arg1\n+OK $uid send me your password....");
		return 0;
	}
	else {
		return 2;
	}

}

############################################################
#### Do the actual password check
sub CheckPassword {

	if ($md5_no_pam && $md5_no_pam =~ /\w+/) {
		$crypt_password =~ /^\$1\$(.{8})\$/;
		my $salt = $1;
		if (unix_md5_crypt($arg, $salt) eq $crypt_password) {
			return 0;
		}
		else {
			return 2;
		}
	}
	elsif ($use_pam && $use_pam =~ /\w+/) {
		my $service = $mpopd_pam_service;
		my $pamh;

		sub my_conv_func {
			my @res;
			while ( @_ ) {
				my $code = shift;
				my $msg = shift;
				my $ans = "";
 				$ans = $uid if ($code == PAM_PROMPT_ECHO_ON() );
				$ans = $arg if ($code == PAM_PROMPT_ECHO_OFF() );
 				push @res, (PAM_SUCCESS(),$ans);
			}
			push @res, PAM_SUCCESS();
			return @res;
		}

		$pamh = new Authen::PAM($service, $uid, \&my_conv_func) ||
		        &TimeIsUp("Error code $pamh during PAM init$CRLF");

		if ($pamh->pam_authenticate == 0) {
			return 0;
		}
		else {
			return 2;
		}

	}
	elsif ($auth_type && $auth_type == 6) {
		do "$password_plugin";
	}
	else {
		if (crypt($arg,$crypt_password) eq $crypt_password) {
			return 0;
		}
		else {
			return 2;
		}
	}

}

############################################################
#### Optional per-user brief logging of connection times
sub LogUser {

	if (defined($user_log{"$uid"})) {
		if (!-d $user_log_dir) {
			`mkdir $user_log_dir`;
			`chmod 1777 $user_log_dir`;
		}
		open USERLOG, ">>$user_log_dir/$uid\_log";
		`chown $uid $user_log_dir/$uid\_log`;
		chmod 0600, "$user_log_dir/$uid\_log";
		my $logtime = localtime(time);
		print USERLOG "$logtime\tCONNECTION OPENED\n";
	}

}

############################################################
#### Close the mailbox in a sane state and close the connection
sub TimeIsUp {

	my $signoff = shift;
	my $logtime = localtime(time);

	if ($signoff) {
		if ($signoff eq "ALRM") {
			$signoff = "Haven't got all day you know... \r\n";
		}
		elsif ($signoff eq "USR1") {
			$signoff = "My parent told me to close... \r\n";
		}
		print $signoff;
		$signoff =~ s/$CRLF$//;
		if (defined($user_log{"$uid"})) {
			print USERLOG "$logtime $signoff\n\n";
			close USERLOG;
		}
	}
	else {
		print "Sorry your time is up :)$CRLF";
		if (defined($user_log{"$uid"})) {
			print USERLOG "$logtime Sorry your time is up :)\n\n";
			close USERLOG;
		}
	}
	if ($opened == 1) {
		if ($use_maildir && $use_maildir == 1) {
			#### A quit command is the only proof that the client
			#### closed the connection normally/intentionally,
			#### so don't delete any emails unless $command eq "QUIT"!
			if ($command eq "QUIT" && $debug{$uid} != 1) {
				for (1..$messagecnt) {
					if ($delete{$_} == 1) {
						unlink "$maildir/new/$maildir[$_ - 1]";
					}
				}
			}
			close MAILDIRLOCK;
			unlink "$maildir/new/.mpopd.lock";
		}
		else {
			my @mpopdspool;
			my @filestat = stat "$mail_spool_dir/$uid";
			my $closemod = $filestat[9];
			if ($closemod == $openmod) {
				open MDROP,">$mail_spool_dir/$uid";
			}
			else {
				$> = 0;
				my $dtime = time;
				#### this is so that disk-based parsing writes here too
				$mail_spool_dir = $mpopd_failed_mail;
				unless (-d "$mpopd_failed_mail") {
					mkdir "$mpopd_failed_mail", 0700;
				}
				open MDROP,">$mpopd_failed_mail/$uid-$dtime";
				chmod 0600, "$mpopd_failed_mail/$uid-$dtime";
				&DebugUser("Maildir/new lock error");
				&mpopLog("$ip\t$uid lock error, backed-up at") if $debug == 1;
			}
			if ($parse_to_disk == 1) {
				close MDROP;
				$> = 0;
				opendir MPOPDSPOOL, "$mpopd_spool/$uid";
				@mpopdspool = grep !/^\./, readdir MPOPDSPOOL;
				closedir MPOPDSPOOL;
			}
			my $cnt;
			foreach $cnt (1..$messagecnt) {
				if ($delete{$cnt} != 1) {
					#### cat the entire message from the temp dir plus "From ..." line
					#### and a blank line at the end, then delete the file
					if ($parse_to_disk == 1) {
						open MAILBOX, ">>$mail_spool_dir/$uid";
						#### Enable per-command buffering (disables block buffering)
						select MAILBOX;
						$| = 1;
						print MAILBOX "$from_line{$cnt}\n";
						open MPOPDMAIL, "$mpopd_spool/$uid/$mpopdspool[$cnt - 1]";
						#### If Status: header is to be used
						if ($status == 1) {
							# first pull off the X-UIDL: header
							$_ = <MPOPDMAIL>;
							print MAILBOX "$_";
							# next one should be the Status:
							$_ = <MPOPDMAIL>;
							if (/(Status: )([RO]){1,2}/ && $status{$cnt}) {
								print MAILBOX "Status: $status{$cnt}\n";
							}
							elsif (/(Status: )([RO]){1,2}/) {
								print MAILBOX "$_";
							}
							else {
								print MAILBOX "Status: O\n";
							}
						}
						while (<MPOPDMAIL>) {
							print MAILBOX "$_";
						}
						unless (/^\s+$/) {
							print MAILBOX "\n";
						}
						close MAILBOX;
						close MPOPDMAIL;
						#### Re-select the right default output FH
						select $output_fh;
					}
					elsif (@{"message".$cnt}[0] !~ /^X-UIDL: mpop/) {
						#### if we're hit by a SIG pipe check the first line of the first message!
						unshift @{"message".$cnt},"X-MPOP: mpop-pipe-correction$CRLF";
					}
					else {
						unshift @{"message".$cnt}, $from_line{$cnt}.$CRLF;
						foreach (@{"message".$cnt}) {
							s/$CRLF$/\n/;
							print MDROP;
						}
					}
				}
				if ($parse_to_disk == 1) {
					unlink "$mpopd_spool/$uid/$mpopdspool[$cnt - 1]" unless $debug{$uid} == 1;
				}
			}
			close MDROP;
			$> = 0;
			close LOCKFILE;
			unlink "$mail_spool_dir/$uid.lock";
			if ($parse_to_disk == 1) {
				close MPOPDSPOOLLOCK;
				unlink "$mpopd_spool/$uid/.mpopd.lock";
			}
			$> = $user_id;
		}
	}

	&mpopdExit;

}

############################################################
#### Check or create the unique message ID for UIDL commands
sub UIDL {

	if ($use_maildir && $use_maildir == 1 && $uidl{"message".$messagecnt} !~ /\S+/) {
		$uidl = $maildir[$messagecnt - 1];
		$uidl{"message".$messagecnt} = $uidl;
		$octets{$messagecnt} += length ("X-UIDL: mpop$uidl".$CRLF);
	}
	elsif (/^X-UIDL: mpop(.+)/) {
		$uidl = $1;
		$uidl =~ s/\r|\n//g;
		if ($parse_to_disk == 1) {
			#### Create a new temp message, but don't add X-UIDL header
			&ParseToDisk("NO");
		}
		$uidl{"message".$messagecnt} = $uidl;
	}
	else {
		$uidl = $uid.time.$messagecnt.$$;
		if ($parse_to_disk == 1) {
			#### Create a new temp message and add X-UIDL header
			&ParseToDisk;
		}
		else {
			push @{"message".$messagecnt},"X-UIDL: mpop$uidl$CRLF";
		}
		$octets{$messagecnt} += length ("X-UIDL: mpop$uidl".$CRLF);
		$uidl{"message".$messagecnt} = $uidl;
	}

}

############################################################
#### If disk-based parsing is set then create dirs / message
sub ParseToDisk {

	my $no_uidl = shift;

	#### were parsing to disk so switch EID to root,
	#### close the last email and open the next for writing
	$> = 0;
	if (seek MESSAGE, -2, 2) {
		print MESSAGE "\0";
	}
	close MESSAGE;
	unless (-d "$mpopd_spool") {
		mkdir "$mpopd_spool", 0700 || &TimeIsUp("Couldn't create mpopd spool dir...$CRLF");
	}
	unless (-d "$mpopd_spool/$uid") {
		mkdir "$mpopd_spool/$uid", 0700 || &TimeIsUp("Couldn't create user's spool dir...$CRLF");
	}
	#### Create or flock the user's mpopd spool dir
	open MPOPDSPOOLLOCK, ">>$mpopd_spool/$uid/.mpopd.lock";
	unless (flock MPOPDSPOOLLOCK, 2|4) {
		&TimeIsUp("Could not flock $mpopd_spool/$uid/.mpopd.lock $CRLF");
	}
	open MESSAGE, ">$mpopd_spool/$uid/$messagecnt" || &TimeIsUp("Couldn't create user's spool file...$CRLF");
	chmod 0600, "$mpopd_spool/$uid/$messagecnt";
	unless ($no_uidl && $no_uidl eq "NO") {
		print MESSAGE "X-UIDL: mpop$uidl\n" ;
		if ($status == 1) {
			print MESSAGE "Status: O\n" ;
		}
	}

	$> = $user_id;

}

############################################################
#### Record mpopd conversations in the individual mailbox log
sub DebugUser {

	if ($user_log{"$uid"} && $user_log{"$uid"} == 2) {
		my $response = shift;
		if ($response =~ /^PASS\s+(.*)/ && $passsecret != 0) {
			$response =~ s/$1/\*\*\*\*\*\*/;
		}
		print USERLOG "$response\n";
	}

}

############################################################
#### Build message arrays or write the next line to disk
sub PushMessage {

	s/\r|\n//g;

	#### if $parse_to_disk is == 1 then the mailbox will be
	#### parsed into individual messages and stored in a temp dir
	if ($parse_to_disk == 1) {
		$> = 0;
		print MESSAGE "$_\n" || &TimeIsUp("Couldn't write to user's spool file...$CRLF");
		$> = $user_id;
	}
	else {
		push @{"message".$messagecnt},"$_$CRLF";
	}
	$octets{$messagecnt} += length ($_.$CRLF);

}

############################################################
#### Refresh the mailbox lock-file
sub PrintLock {

	#### This is to update the m time on the <user>.lock mbox lock file.
	#### It may seem paranoid but I have seen lock files removed by impatient
	#### MDA's, so the file is written-to, unbuffered, as often as is
	#### practicable. When run under inetd CLIENT is actually a copy of STDIN
	#### so STDOUT, not CLIENT, must be selected before leaving this sub.
	$> = 0;
	select LOCKFILE;
	$| = 1;
	seek LOCKFILE, 0, 0;
	print LOCKFILE "\0";
	select $output_fh;
	$| = 1;
	$> = $user_id;

}

############################################################
####
sub PrintLockCount {

	if (++$line == 1000) {
		&PrintLock;
		$line = 0;
	}

}

############################################################
#### Get the number and size of messages in a Maildir mailbox

sub StatMailDir {

	my ($maildir_files,$addedbytes) = @_;

	foreach (@$maildir_files) {
		++$messagecnt;
		#### check/create the unique ID code
		$octets{$messagecnt} = -s "$maildir/new/$_";
		&UIDL;
		$octets{$messagecnt} += $addedbytes;
		$totaloctets += $octets{$messagecnt};
	}

}

############################################################
#### Write something in the main mpopd log
sub mpopLog {

	my $error = shift;

	if (defined($debug_log)) {
		$> = 0;
		unless ($debug_open == 1) {
			($debuglog_dir) = $debug_log =~ /^(.+)\//;
			if (!-d $debuglog_dir) {
				mkdir $debuglog_dir, 0700;
			}
			open DEBUGLOG, ">>$debug_log";
			chown 0, "root", "$debug_log";
			chmod 0600, "$debug_log";
			$debug_open = 1;
		}
		my $logtime = localtime(time);
		print DEBUGLOG "$error\t$logtime\n";
		$> = $user_id if $user_id;
	}

}

############################################################
#### Clean up and exit
sub mpopdExit {

	close $input_fh;
	exit(0);

}

1;

__END__


=head1 NAME

mpopd -- A POP3 stand-alone forking daemon or inetd server

mpopd complies with: RFC 1939 but one or two recommendations
can be overridden in the configuration file: mpopd allows
rejection of bogus UIDs as a configurable option. mpopd allows
a timeout of n seconds as a configuration item. mpopd supports
UIDL and TOP but not APOP. The documentation is minimal at present.
There are pod docs in the mpopd, mpodctl and mpopd_test scripts.

=head1 PREREQUISITES

Either, a local MDA that understands <username>.lock
file locking (e.g. procmail), or a local MDA that uses
the Qmail-style maildir message store.

mpopd has been tested on Linux 2.0.35 with Perl 5.005_3
and on several later versions up to 2.2.18 / 5.6.0

=head1 COREQUISITES

The following module may be required for some systems
when using crypt-MD5-hashed passwords:

	Crypt::PasswdMD5

You will need the following module if you wish to use
PAM authentication:

	Authen::PAM

The PAM authentication has only been tested on Linux 2.2.18,
Perl 5.6.0, Linux-PAM-0.74 and Authen-PAM-0.11

You will need the following module if you wish to use
the mpopd_test script:

	Time::HiRes

=head1 SYNOPSIS

mpopdctl [B<-f>] [B<-p> port] start | stop | restart | refresh | [B<-e>] config | B<-h>

or

mpopd [port] &

=head1 DESCRIPTION

=head2 To run mpopd under inetd:

Place a line like the following in inetd.conf:

pop3 stream tcp nowait root /usr/sbin/tcpd /usr/bin/mpop

The /etc/services file must have an entry similar to this:

pop3		110/tcp

=head2 To run as a standalone daemon:

Either:

Use the mpopdctl script (recommended) or if the mpopd wrapper
script is in your path path just type:
B<mpopd &>
and mpopd should detach itself.

You can also override the config value for the port mpopd
should use by giving it as a single command line argument:

B<mpopd 8110 &>

or:

B<mpopdctl start>

=head1 mpopdctl

mpopdctl is a script to make starting, stopping and sending
signals to mpopd a bit more convenient:

B<mpopdctl> [B<-f>] [B<-p> port] start | stop | restart | refresh | [B<-e>] config | B<-h>

[B<-f>] [B<-p> port] start

Start the mpopd server daemon.

The optional B<-f> flag removes any pid file left over after an
mpopd or system crash.

The optional B<-p> flag allows a port number to be specified,
which overrides the config file setting. This allows other
instances to be run in parrallel to the standard port 110
for testing.

Example:

mpopdctl B<-p> 8110 B<-f> start

Would remove a stale pid file and start mpopd in daemon mode
on port 8110

=head2 stop

Stop the mpopd server daemon.

=head2 restart

Stops the mpopd server daemon and imediately restarts it.

=head2 refresh

mpopd will send a signal to all currently executing
child servers to close. They will interrupt what they
were doing and restore the user's mailbox, ignoring any
commands to delete messages. mpopd will close its server
socket, reopen it and bind to the port set in \$port in
the mpopd config file.

[B<-e>] B<config>

Call a running mpopd server and ask it to re-read the mpopd
configuration file. All subsequent child servers inherit the
new config values, with the exception of the port number
which can only be changed using the 'refresh' flag.

The optional B<-e> flag will open the mpopd config file in an
editor of your choice first. After the editor is closed mpopd
will ask you if it should re-read the modified config file.

B<-h>

Display a help screen.

=head1 Signalling a running mpopd server with 'kill'

As a daemon mpopd understands three signals:

=head2 SIGTERM

Signals mpopd to close all child servers before removing
its own pid file and exiting.

=head2 SIGHUP

Signals all child servers to close, hopefully without
losing any mail. The server socket is closed and some
cleanup is done. The config file is re-read and then the
socket is rebuilt and the port is bound to. This also
facilitates changing the port number.

=head2 SIGUSR1

Just re-read the config file. Any changes will only take
effect for subsequent child server processes.

=head1 README

You will need the full Mail-POP3Server-2.22.tar.gz kit if
this is the first time you have downloaded mpopd. The archive
includes a sample config, access control file samples and a
couple of tool/helper scripts.

You can find it on CPAN or at:

http://mpopd.fredo.co.uk/

First read and then edit mpopd.conf to suit your system.
mpopd.conf is also the best documentation there is for now.
Next, edit the 'CONFIG' values near the top of the mpopd script
itself to reflect the location of mpopd.conf

Requires either qmail-style 'maildir' or single-file
Berkeley-style mbox mailboxes.

For mbox mail files mpopd can use an arbitrary start-of-message
and end-of-message identifier for each message.
These default to 'From ' and a blank line.

=head2 Current test environment:

	Slackware Linux 7.1, 2.2.18 kernel
	Perl 5.6.0
	Crypt::PasswdMD5 1.1
	Linux-PAM-0.74
	Authen-PAM-0.11

=head2 mpopd can be used in one of three modes:

1. Disk-based mailbox handling, the entire mailbox is parsed
   and each message is written to a root-owned mpopd spool
2. Fully RAM-based mailbox handling, the entire mailbox is parsed
   and each message is read into an array
3. Qmail-style maildir mailboxes. No parsing required.

mpopd accommodates virtual-users and hostname-based authentication.

Uses <username>.lock semaphore file checking for Berkeley mbox style
mailbox locking and a lock file for the per-user dirs where the temp
message files are created.

Configurable via the mpopd.conf text/perl config file.

Variable logging levels, including on/off activation
of logging on a per user basis.

=head2 mpopd can use 7 main kinds of authentication:

 1. Standard /etc/passwd or shadow file and system mailboxes.
 2. as 1. plus a fallback to hostname lookup.
 3. as 2. plus remote access via full email address as UID.
 4. hostname lookup and custom user-list authentication only.
 5. as 4. plus remote access via full email address as UID.
 6. Only the user-list and a cental mailspool are used.
 7. A basic form of user-defined plugin.

 Plus:
 Per-user configurable authentication based on 1-7.

 See the 'User authentication' section in mpopd.conf if you want
 to set-up hostname-based mailspool dirs and/or virtual users.

=head2 COPYRIGHT

Copyright (c) Mark Tiramani 1998-2001 <markjt@fredo.co.uk>.
All rights reserved. This program is free software; you can
redistribute it and/or modify it under the same terms as Perl itself.

=head2 DISCLAIMER:

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
See the Artistic License for more details.


=cut

###################  BOTTOM LINE  ###########################
