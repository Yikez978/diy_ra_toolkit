#!/usr/bin/perl

$os = $^O;
print "AuditAD ($os)\n";

use XML::Simple;
use Data::Dumper;
use Mail::Sendmail;
use Net::LDAP;
use Sys::Syslog;

my $error_msg;

$ref = XMLin("AuditAD.xml");
print "\n\n";

# validate email attributes
if (!$ref->{EMAIL}->{To}) { print "<EMAIL To=> is required \n"; exit 255;}
if (!$ref->{EMAIL}->{From}) { print "<EMAIL From=> is required \n"; exit 255;}
if (!$ref->{EMAIL}->{Subject}) { print "<EMAIL Subject=> is required \n"; exit 255;}

# validate LDAP attributes
if (!$ref->{LDAP}->{host}) { print "<LDAP host=> is required. \n"; exit 255;}
if (!$ref->{LDAP}->{dn}) { print "<LDAP dn=> is required. \n"; exit 255;}
if (!$ref->{LDAP}->{pw}) { print "<LDAP pw=> is required. \n"; exit 255;}

$ref->{EMAIL}->{Message} = "test";

my $ldap = Net::LDAP->new($ref->{LDAP}->{host}) or die "Can't bind to ldap: $!\n";
$ldap->bind($ref->{LDAP}->{dn}, password => $ref->{LDAP}->{pw});

# check all the groups
foreach my $name (keys %{$ref->{'SEC-GROUP'}})
{
	my %hash = %{$ref->{'SEC-GROUP'}->{$name}};
	my $cnRef = $ref->{'SEC-GROUP'}->{$name}->{CN};

	# check to make sure that dn exists
	if (!$hash{dn}) { print "<SEC-GROUP> $name is missing dm= \n"; exit 255}
	
	my $result = $ldap->search(base => $hash{dn}, filter => '(objectclass=*)' );
	
	my @arry;
	if ($cnRef =~ /ARRAY/)
	{
	}
	else
	{
		$arry[0] = $cnRef;
		$cnRef = \@arry;
		
	}
	
	my $status = compareSecGroup($name, $result, $cnRef);
}

if ($error_msg)
{
	syslog('notice', "AuditAD - directory security errors found %s", $error_msg);
	$ref->{EMAIL}->{Message} = $error_msg;
	sendmail(%{$ref->{EMAIL}});
	print "$error_msg\n";
}
else
{
	syslog('notice', "AuditAD - no directory security errors found")
}

sub compareSecGroup
{
	my $group = shift;
	my $result = shift;
	my $cnRef = shift;
	my @cn = @$cnRef;
	
	#print "$group " . $result . " " . $cnRef . "\n";
	
	my $ref  = $result->{entries}[0]->{asn}->{attributes};
	my @asn = @$ref;
	
	my @adusers;
	my @xmlusers = @cn;

	foreach my $key (@asn)
	{
		if ($key->{type} eq "member")
		{
			my $arrayRef = $key->{vals};
			my @arr = @$arrayRef;
			foreach my $usr (@arr)
			{
				$usr =~ m/CN=(.+?)\,/sgm;
				push @adusers, $1;
			}
		}
	}
	
	#compare aduesrs with XML users
	foreach my $adu (@adusers)
	{
		my $found = 0;
		foreach my $xmlu (@xmlusers)
		{
			if ($adu eq $xmlu) 
			{
				$found = 1;
				last;
			}
		}
		if ($found eq 1)
		{
			next;
		}
		else
		{
			$error_msg .= "user $adu in group $group was not authorized \n";
		}
	}
	
	#compare xmluesrs with AD users
	if ($#xmlusers > 0)
	{
		foreach my $xmlu (@xmlusers)
		{
			my $found = 0;
			foreach my $adu (@adusers)
			{
				if ($adu eq $xmlu) 
				{
					$found = 1;
					last;
				}
			}
			if ($found eq 1)
			{
				next;
			}
			else
			{
				$error_msg .= "user $xmlu in group $group was missing from AD \n";
			}
		}
	}
}
