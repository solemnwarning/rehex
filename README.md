# Redhat Packaging Notes

## Building snapshot versions

I use `rpmbuild` to produce an initial SRPM and `mock` to produce the final packages, as a rough guide:

    $ GIT_COMMIT=$(git log -1 --format="%H")

    $ make dist
    $ mkdir -p ~/rpmbuild/SOURCES/
    $ cp rehex-${GIT_COMMIT}.tar.gz ~/rpmbuild/SOURCES/

    $ rpmbuild --define "git_commit_sha ${GIT_COMMIT}" -bs rehex-git.spec

    $ mock -r fedora-31-x86_64 rebuild ~/rpmbuild/SRPMS/rehex-${GIT_COMMIT}-0~fc31.src.rpm

## Building release versions

TODO.

## Version Numbers

See the `README.md` under the `debian/` directory of any of the Debian/Ubuntu packaging branches. rpm follows the same rules as dpkg and the same logic is applied.
