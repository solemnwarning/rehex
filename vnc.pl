#!/usr/bin/env perl

use strict;
use warnings;

use Net::VNC;

my $xvnc = XvncServer->new();

my $rehex = do
{
	local $ENV{DISPLAY} = ":" . $xvnc->display();
	REHex::LinuxInstance->new("./rehex");
};

my $doc_ctrl = $rehex->find_window("//*[\@class=\"REHex::DocumentCtrl\"]");

my $vnc = Net::VNC->new({hostname => "localhost", port => $xvnc->port(), password => $xvnc->password()});
$vnc->depth(24);
$vnc->login;

print $vnc->name . ": " . $vnc->width . ' x ' . $vnc->height . "\n";

$vnc->send_key_event(0xff09); # tab
foreach my $char(split("", "Hello world3"))
{
    $vnc->send_key_event(ord($char));
}

sleep(1);

my $image = $vnc->capture;

sub find_rect_cols2
{
    my ($image, $xbase, $ybase, $xstep, $ystep, $r, $g, $b, $mw) = @_;

    my $x1 = undef;
    my $x2 = undef;

    my $check_pixel = sub
    {
        my ($x, $y) = @_;

        my ($pr, $pg, $pb) = $image->query_pixel($x, $y);
        return $pr == $r && $pg == $g && $pb == $b;
    };

    my $x = $xbase;
    my $y = $ybase;

    while($x <= $image->width() && $y <= $image->height())
    {
        my $w = 0;

        while(($x + ($w * $xstep)) <= $image->width() && ($y + ($w * $ystep)) <= $image->height() && $check_pixel->(($x + ($w * $xstep)), ($y + ($w * $ystep))))
        {
            ++$w;
        }

        if($w >= $mw)
        {
            if(!defined($x1))
            {
                if(($x + ($w * $xstep)) < $image->width() && ($y + ($w * $ystep)) < $image->height())
                {
                    $x1 = (($x + $w) * $xstep) + (($y + $w) * $ystep);
                }
            }
            elsif(!defined($x2))
            {
                $x2 = (($x - 1) * $xstep) + (($y - 1) * $ystep);
            }
            else{
                warn "Too many matches on y = $y";
                return undef, undef;
            }
        }

        $x += ($w + 1) * $xstep;
        $y += ($w + 1) * $ystep;
    }

    if(defined($x1) && defined($x2))
    {
        return $x1, $x2;
    }
    else{
        return undef, undef;
    }
}

sub find_rect
{
    my ($image, $r, $g, $b, $mw) = @_;

    my ($x1, $x2);

    for(my $y = 0; $y < $image->height(); ++$y)
    {
        my ($x1b, $x2b) = find_rect_cols2($image, 0, $y, 1, 0, $r, $g, $b, $mw);

        if(defined($x1) && defined($x1b))
        {
            if($x1b != $x1 || $x2b != $x2)
            {
                warn "wat $x1 $x1b $x2 $x2b";
            }
        }
        elsif(defined $x1b)
        {
            $x1 = $x1b;
            $x2 = $x2b;
        }
    }

    if(defined $x1)
    {
        my ($y1, $y2);

        for(my $x = $x1; $x <= $x2; ++$x)
        {
            my ($y1b, $y2b) = find_rect_cols2($image, $x, 0, 0, 1, $r, $g, $b, $mw);

            if(defined($y1) && defined($y1b))
            {
                if($y1b != $y1 || $y2b != $y2)
                {
                    warn "wat $y1 $y1b $y2 $y2b";
                }
            }
            elsif(defined $y1b)
            {
                $y1 = $y1b;
                $y2 = $y2b;
            }
        }

        if(defined $y1)
        {
            return $x1, $y1, ($x2 - $x1 + 1), ($y2 - $y1 + 1);
        } 
    }

    return;
}

# my ($x, $y, $w, $h) = find_rect($image, 0, 255, 255, 1);

my ($x, $y, $w, $h) = ($doc_ctrl->{screen_x1}, $doc_ctrl->{screen_y1}, ($doc_ctrl->{screen_x2} - $doc_ctrl->{screen_x1}), ($doc_ctrl->{screen_y2} - $doc_ctrl->{screen_y1}));

if(defined $x)
{
    print "Found control at $x,$y ${w} x {$h}\n";

    my $cropped = $image->crop($x, $y, $w, $h);
    $cropped->save("out2.png");
}

$image->save("out.png");

package REHex::LinuxInstance;

use IO::Socket::INET;
use XML::XPath;

sub new
{
    my ($class, $binary) = @_;

	my $pid = open(my $stdout, "-|", $binary)
		or die "$binary: $!";

	my $window_enum_port = undef;

	while(defined(my $line = <$stdout>))
	{
		if($line =~ m/Window enumerator bound to port (\d+)/)
		{
			$window_enum_port = $1;
			last;
		}
	}

	die "Window enumerator didn't initialise" unless(defined $window_enum_port);

	return bless({
		pid => $pid,
		stdout => $stdout,
		window_enum_port => $window_enum_port,
	}, $class);
}

sub DESTROY
{
	my ($self) = @_;

	kill(9, $self->{pid});
	waitpid($self->{pid}, 0);
}

sub get_windows
{
	my ($self) = @_;

	my $sock = IO::Socket::INET->new(
		Proto    => "tcp",
		PeerAddr => "localhost",
		PeerPort => $self->{window_enum_port},
	) or die "Cannot connect to window enumerator: $!";

	my $xml = "";

	my $buf;
	while(defined $sock->recv($buf, 1024) && length($buf) > 0)
	{
		$xml .= $buf;
	}

	$xml = XML::XPath->new(xml => $xml);

	return REHex::Windows->new($xml);
}

sub find_window
{
	my ($self, $xpath) = @_;

	my ($window) = $self->get_windows()->find($xpath);
	return $window;
}

package REHex::Windows;

sub new
{
	my ($class, $xml) = @_;

	return bless({ xml => $xml }, $class);
}

sub find
{
	my ($self, $xpath) = @_;

	my @windows = map { REHex::Window->new($_) } $self->{xml}->findnodes($xpath);
	return @windows;
}

package REHex::Window;

sub new
{
	my ($class, $xml_node) = @_;

	my $self = bless({}, $class);

	foreach my $key(qw(class id name label local_x1 local_y1 local_x2 local_y2 screen_x1 screen_y1 screen_x2 screen_y2))
	{
		$self->{$key} = $xml_node->getAttribute($key);
	}

	return $self;
}

sub class { return shift->{class}; }
sub id    { return shift->{id};    }
sub name  { return shift->{name};  }
sub label { return shift->{label}; }

sub local_x1 { return shift->{local_x1}; }
sub local_y1 { return shift->{local_y1}; }
sub local_x2 { return shift->{local_x2}; }
sub local_y2 { return shift->{local_y2}; }

sub screen_x1 { return shift->{screen_x1}; }
sub screen_y1 { return shift->{screen_y1}; }
sub screen_x2 { return shift->{screen_x2}; }
sub screen_y2 { return shift->{screen_y2}; }

package XvncServer;

use File::Temp;
use IPC::Run qw(run);
use POSIX;

sub new
{
	my ($class) = @_;

	# TODO: Find a free display/port
	my $display = 1;

	# Generate a random password for the VNC connection.
	my $password = join("", map { [ "A".."Z" ]->[int rand 26] } (1..8));

	my $pwfile = File::Temp->new();
	run(
		[ "vncpasswd", "-f" ],
		"<" => \$password,
		">" => $pwfile) or die "Unable to create Xvnc password file";

	my $pid = fork() // die "fork: $!";

	if($pid == 0)
	{
		exec("Xvnc", ":${display}", "-PasswordFile" => "$pwfile", "-geometry" => "1024x768");
		print STDERR "Xvnc: $!\n";

		POSIX::exit(1); # Skip destructors
	}

	return bless({
		pid      => $pid,
		display  => $display,
		password => $password,
		pwfile   => $pwfile,
	}, $class);
}

sub DESTROY
{
	my ($self) = @_;

	kill(15, $self->{pid});
	waitpid($self->{pid}, 0);
}

sub display
{
	my ($self) = @_;
	return $self->{display};
}

sub port
{
	my ($self) = @_;
	return 5900 + $self->{display};
}

sub password
{
	my ($self) = @_;
	return $self->{password};
}
