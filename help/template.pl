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
use FindBin;

my ($template_name, $include_path) = @ARGV;

my @contents = load_contents();

my $tt = Template->new({
	INCLUDE_PATH => $include_path,
	RECURSION    => 1 }
) or die $Template::ERROR;

$tt->process("$template_name.tt", {
	contents      => \@contents,
	template_name => $template_name }
) or die $tt->error();

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
