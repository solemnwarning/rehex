# Reverse Engineer's Hex Editor
# Copyright (C) 2022 Daniel Collins <solemnwarning@solemnwarning.net>
#
# This program is free software; you can redistribute it and/or modify it
# under the terms of the GNU General Public License version 2 as published by
# the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful, but WITHOUT
# ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
# FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
# more details.
#
# You should have received a copy of the GNU General Public License along with
# this program; if not, write to the Free Software Foundation, Inc., 51
# Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.

use strict;
use warnings;

use Template;
use Template::Provider;
use FindBin;
use Getopt::Long;

my @include_paths = ();
my $dep_file;
my $dep_target;

GetOptions(
	"include=s"    => \@include_paths,
	"dep-file=s"   => \$dep_file,
	"dep-target=s" => \$dep_target,
);

my ($template_name) = @ARGV;

my @contents = load_contents();

my $tt = Template->new({
	RECURSION => 1,
	LOAD_TEMPLATES => [
		TemplateLoadLogger->new(\@include_paths),
		Template::Provider->new({ INCLUDE_PATH => \@include_paths }),
	]},
) or die $Template::ERROR;

$tt->process("$template_name.tt", {
	contents      => \@contents,
	template_name => $template_name }
) or die $tt->error();

open(my $dep_out, ">", $dep_file) or die "$dep_file: $!\n";
print {$dep_out} "$dep_target: ", join(" ", keys(%TemplateLoadLogger::LOADED_TEMPLATES)), "\n";

sub load_contents
{
	my $contents_file = "$FindBin::Bin/contents.txt";
	open(my $contents, "<", $contents_file) or die "$contents_file: $!\n";
	
	my @pages = ();
	my @stack = (
		[ -1, \@pages ],
	);
	
	foreach(<$contents>)
	{
		chomp;
		
		my ($leading_ws, $page, $title) = m/^(\s*)(\S+)\s+(.+)/;
		next unless defined $title;
		
		$leading_ws =~ s/\t/        /;
		my $depth = length($leading_ws);
		
		while($stack[-1]->[0] >= $depth)
		{
			pop(@stack);
		}
		
		my $p = {
			page => $page,
			title => $title,
			
			children => [],
		};
		
		push(@{ $stack[-1]->[1] }, $p);
		
		push(@stack, [ $depth, $p->{children} ]);
	}
	
	return @pages;
}

package TemplateLoadLogger;

use Template::Constants;

our %LOADED_TEMPLATES = ();

sub new
{
	my ($class, $include_paths) = @_;
	return bless([ @$include_paths ], $class);
}

sub fetch
{
	my ($self, $name) = @_;
	
	foreach my $path(@$self)
	{
		if(-e "$path/$name")
		{
			$LOADED_TEMPLATES{"$path/$name"} = 1;
			last;
		}
	}
	
	return (undef, Template::Constants::STATUS_DECLINED);
}

sub load
{
	my ($self, $name) = @_;
	return $self->fetch($name);
}
