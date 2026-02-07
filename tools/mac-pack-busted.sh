#!/bin/sh
# Pack up busted script and supporting Lua interpreter/modules built by
# mac-build-dependencies.sh for use on another machine.

set -e

if [ "$#" -ne "1" ]
then
	echo "Usage: $0 <busted-bundle-name>" >&2
	exit 1
fi

if [ -z "$LUA" ] || [ -z "$BUSTED" ]
then
	echo "LUA and/or BUSTED not set in environment - have you sourced mac-build-dependencies.sh?" >&2
	exit 1
fi

lua_root="$(dirname "$(dirname "$LUA")")"

old_pwd="$(pwd)"
cd "$lua_root"

busted_main="$(echo lib/luarocks/rocks-*/busted/*/bin/busted)"

if [ ! -f "$busted_main" ]
then
	echo "Cannot find busted entry point" >&2
	exit 1
fi

lib_lua_path="$(echo lib/lua/*)"
share_lua_path="$(echo share/lua/*)"

if [ ! -d "$lib_lua_path" ] || [ ! -d "$share_lua_path" ]
then
	echo "Cannot find Lua module directory" >&2
	exit 1
fi

cd "$old_pwd"

tmpdir="$(mktemp -d)"
trap 'rm -rf "$tmpdir"' EXIT

busted_out="${tmpdir}/$(basename "$1")"
mkdir -p "${busted_out}"

mkdir -p \
	"${busted_out}/bin" \
	"${busted_out}/lib/lua" \
	"${busted_out}/share/lua"

cp -a "${lua_root}/bin/lua" "${busted_out}/bin/"
cp -a "${lua_root}/${lib_lua_path}/"* "${busted_out}/lib/lua/"
cp -a "${lua_root}/${share_lua_path}/"* "${busted_out}/share/lua/"
cp -a "${lua_root}/${busted_main}" "${busted_out}/bin/_busted"

# Write out a wrapper for busted which detects where it has been unpacked and
# sets up the Lua module paths as required.
cat > "${busted_out}/bin/busted" << 'EOF'
#!/bin/sh

lua_root="$(dirname "$(dirname "$0")")"

export LUA_PATH="${lua_root}/share/lua/?.lua;${lua_root}/share/lua/?/init.lua"
export LUA_CPATH="${lua_root}/lib/lua/?.so"

exec "${lua_root}/bin/lua" -- "${lua_root}/bin/_busted" "$@"
EOF

chmod +x "${busted_out}/bin/busted"

tar -czf "$1.tar.gz" -C "${tmpdir}" "$(basename "$1")/"
echo "Wrote busted bundle to $1.tar.gz"
