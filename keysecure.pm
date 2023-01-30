package keysecure;
##
## rancid 3.13
## Copyright (c) 1997-2019 by Henry Kilmer and John Heasley
## All rights reserved.
##
## This code is derived from software contributed to and maintained by
## Henry Kilmer, John Heasley, Andrew Partan,
## Pete Whiting, Austin Schutz, and Andrew Fort.
##
## Redistribution and use in source and binary forms, with or without
## modification, are permitted provided that the following conditions
## are met:
## 1. Redistributions of source code must retain the above copyright
##    notice, this list of conditions and the following disclaimer.
## 2. Redistributions in binary form must reproduce the above copyright
##    notice, this list of conditions and the following disclaimer in the
##    documentation and/or other materials provided with the distribution.
## 3. Neither the name of RANCID nor the names of its
##    contributors may be used to endorse or promote products derived from
##    this software without specific prior written permission.
##
## THIS SOFTWARE IS PROVIDED BY Henry Kilmer, John Heasley AND CONTRIBUTORS
## ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
## TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
## PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE COMPANY OR CONTRIBUTORS
## BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
## CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
## SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
## INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
## CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
## ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
## POSSIBILITY OF SUCH DAMAGE.
##
## It is the request of the authors, but not a condition of license, that
## parties packaging or redistributing RANCID NOT distribute altered versions
## of the etc/rancid.types.base file nor alter how this file is processed nor
## when in relation to etc/rancid.types.conf.  The goal of this is to help
## suppress our support costs.  If it becomes a problem, this could become a
## condition of license.
# 
#  The expect login scripts were based on Erik Sherk's gwtn, by permission.
# 
#  The original looking glass software was written by Ed Kern, provided by
#  permission and modified beyond recognition.
#
#  RANCID - Really Awesome New Cisco confIg Differ
#
#  keysecure.pm - Cisco IOS rancid procedures

use 5.010;
use strict 'vars';
use warnings;
no warnings 'uninitialized';
require(Exporter);
our @ISA = qw(Exporter);

use ksrancid 3.13;

our $proc;
our $ios;
our $found_version;
our $found_env;

our $type;				# device model, from ShowVersion


@ISA = qw(Exporter ksrancid main);
#XXX @Exporter::EXPORT = qw($VERSION @commandtable %commands @commands);

# load-time initialization
sub import {
    0;
}

sub ShowLogSettings() {
  my($INPUT, $OUTPUT, $cmd) = @_;

  print STDERR ("Execute ShowLogSettings()\n") if ($debug);
  ProcessHistory("LOGGING", "", "", "!LOGGING SETTINGS:\n!\n");
  while(<$INPUT>) {
  	tr/\015//d;
	last if (/^$prompt/);
	next if (/^(\s*|\s*$cmd\s*)$/);
	return(1) if (/Invalid command\./);
	return(1) if (/Incorrect number of arguments\./);
	return(1) if (/Usage: show hostname/);
    ProcessHistory("LOGGING", "", "", "!$_");
  }

    ProcessHistory("LOGGING", "", "", "!\n");
  1;

}

sub ShowRasSettings() {
  my($INPUT, $OUTPUT, $cmd) = @_;

  print STDERR ("Execute ShowRasSettings()\n") if ($debug);
  ProcessHistory("ACCESS", "", "", "!REMOTE ACCESS SETTINGS:\n!\n");
  while(<$INPUT>) {
  	tr/\015//d;
	last if (/^$prompt/);
	next if (/^(\s*|\s*$cmd\s*)$/);
	return(1) if (/Invalid command\./);
	return(1) if (/Incorrect number of arguments\./);
	return(1) if (/Usage: show hostname/);
    ProcessHistory("ACCESS", "", "", "!$_");
  }

    ProcessHistory("ACCESS", "", "", "!\n");
  1;

}

sub ShowHostname() {
  my($INPUT, $OUTPUT, $cmd) = @_;

  print STDERR ("Execute ShowHostname()\n") if ($debug);
  ProcessHistory("HOSTNAME", "", "", "!HOSTNAME SETTINGS:\n!\n");
  while(<$INPUT>) {
  	tr/\015//d;
	last if (/^$prompt/);
	next if (/^(\s*|\s*$cmd\s*)$/);
	return(1) if (/Invalid command\./);
	return(1) if (/Incorrect number of arguments\./);
	return(1) if (/Usage: show hostname/);
    ProcessHistory("HOSTNAME", "", "", "!$_");
  }

    ProcessHistory("HOSTNAME", "", "", "!\n");
  1;

}

sub ShowNTP() {
  my($INPUT, $OUTPUT, $cmd) = @_;

  print STDERR ("Execute ShowNTP()\n") if ($debug);

  ProcessHistory("NTP", "", "", "!NTP SETTINGS:\n!\n");

  while(<$INPUT>) {
  	tr/\015//d;
	last if (/^$prompt/);
	next if (/^(\s*|\s*$cmd\s*)$/);
	return(1) if (/Invalid command\./);
	return(1) if (/Incorrect number of arguments\./);
    ProcessHistory("NTP", "", "", "!$_");
  }
	
	ProcessHistory("NTP", "", "", "!\n");
  1;

}
sub ShowInterfaces() {
  my($INPUT, $OUTPUT, $cmd) = @_;

  print STDERR ("Execute ShowInterfaces()\n") if ($debug);
 
  ProcessHistory("INTERFACES", "", "", "!INTERFACE SETTINGS:\n!\n");

  while(<$INPUT>) {
  	tr/\015//d;
	last if (/^$prompt/);
	next if (/^(\s*|\s*$cmd\s*)$/);
	return(1) if (/Invalid command\./);
	return(1) if (/Incorrect number of arguments\./);
    ProcessHistory("INTERFACES", "", "", "!$_");
  }
	
	ProcessHistory("INTERFACES", "", "", "!\n");
  1;

}

sub ShowMAC() {
  my($INPUT, $OUTPUT, $cmd) = @_;

  print STDERR ("Execute ShowMAC()\n") if ($debug);
 
  ProcessHistory("INTERFACES", "", "", "!MAC SETTINGS:\n!\n");

  while(<$INPUT>) {
  	tr/\015//d;
	last if (/^$prompt/);
	next if (/^(\s*|\s*$cmd\s*)$/);
	return(1) if (/Invalid command\./);
	return(1) if (/Incorrect number of arguments\./);
    ProcessHistory("INTERFACES", "", "", "!$_");
  }
	
	ProcessHistory("INTERFACES", "", "", "!\n");
  1;

}

# post-open(collection file) initialization
sub init {

    # add content lines and separators
    ProcessHistory("","","","!RANCID-CONTENT-TYPE: $devtype\n!\n");
    ProcessHistory("COMMENTS","","","!\n");

    0;
}

# main loop of input of device output
sub inloop {
    my($INPUT, $OUTPUT) = @_;
    my($cmd, $rval);


TOP: while(<$INPUT>) {


	tr/\015//d;
	if (/Exiting command line interface\./) {
		$clean_run = 1;
	    last;
	}
	if (/^Error:/) {
	    print STDOUT ("$host kslogin error: $_");
	    print STDERR ("$host kslogin error: $_") if ($debug);
	    $clean_run = 0;
	    last;
	}
	while (/#\s*($cmds_regexp)\s*$/) {

	    $cmd = $1;

	    if (!defined($prompt)) {
		$prompt = ($_ =~ /^([^#>]+[#>])/)[0];
		$prompt =~ s/([][}{)(+\\])/\\$1/g;
		print STDERR ("PROMPT MATCH: $prompt\n") if ($debug);
	    }

	    print STDERR ("HIT COMMAND:$_") if ($debug);
	    if (! defined($commands{$cmd})) {
		print STDERR "$host: found unexpected command - \"$cmd\"\n";
		$clean_run = 0;
		last TOP;
	    }
	    if (! defined(&{$commands{$cmd}})) {
		printf(STDERR "$host: undefined function - \"%s\"\n",
		       $commands{$cmd});
		$clean_run = 0;
		last TOP;
	    }
	    $rval = &{$commands{$cmd}}($INPUT, $OUTPUT, $cmd);
	    delete($commands{$cmd});
	    if ($rval == -1) {
		$clean_run = 0;
		last TOP;
	    }
	}
    }
}

1;
