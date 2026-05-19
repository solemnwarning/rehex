# Reverse Engineer's Hex Editor
# Copyright (C) 2026 Daniel Collins <solemnwarning@solemnwarning.net>
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

if((scalar @ARGV) != 1)
{
    die "Usage: $0 <rehex executable>\n";
}

my ($rehex) = @ARGV;

open(my $pipe, "-|", $rehex, "--data-types")
    or die "$rehex: $!\n";

print "[%- REHEX_DATA_TYPES = [\n";

my $current_depth = 0;

while(defined(my $line = <$pipe>))
{
    $line =~ s/\r?\n$//s;

    if($line =~ m/^( *)\* (\S+) {4,}(.+)$/s)
    {
        my $type_pad = $1;
        my $type_name = $2;
        my $type_label = $3;

        my $type_depth = length($type_pad) / 4;

        while($type_depth < $current_depth)
        {
            print "  ] },\n";
            $current_depth -= 1;
        }

        $type_name =~ s/([\\'])/\\$1/g;
        $type_label =~ s/([\\'])/\\$1/g;

        print "  ${type_pad}{ name = '$type_name', label = '$type_label' },\n";
    }
    elsif($line =~ m/^( *)\* (.*)$/s)
    {
        my $group_pad = $1;
        my $group_label = $2;

        my $group_depth = length($group_pad) / 4;

        while($group_depth < $current_depth)
        {
            print "  ] },\n";
            $current_depth -= 1;
        }

        $group_label =~ s/([\\'])/\\$1/g;

        print "  ${group_pad}{ group = '$group_label', types => [\n";
        $current_depth += 1;
    }
    else{
        warn "Unexpected line read from $rehex --data-types: '$line'\n";
    }
}

while($current_depth > 0)
{
    print "  ] },\n";
    $current_depth -= 1;
}

print "] -%]\n";

close($pipe) or die($! || "$rehex exited with status $?");
