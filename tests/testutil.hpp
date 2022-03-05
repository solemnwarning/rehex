/* Reverse Engineer's Hex Editor
 * Copyright (C) 2022 Daniel Collins <solemnwarning@solemnwarning.net>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 as published by
 * the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc., 51
 * Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
*/

#ifndef REHEX_TESTUTIL_HPP
#define REHEX_TESTUTIL_HPP

#include <functional>

void run_wx_for(unsigned int ms);
bool run_wx_until(const std::function<bool()> &predicate, unsigned int timeout_ms = 10000, unsigned int check_interval_ms = 100);

#endif /* !REHEX_TESTUTIL_HPP */
