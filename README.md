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

Releases are built and distributed on [Copr](https://copr.fedorainfracloud.org/).

  # First, prepare a dist tarball from the release sources.
  
  $ make dist
  $ cp rehex-${VERSION}.dist ~/rpmbuild/SOURCES/
  
  # Then build an SRPM using a .spec file from this branch.
  
  $ rpmbuild -bs rehex-${VERSION}.spec
  
  # Now just upload the SRPM to Copr and let it do its thing.

## Version Numbers

See the `README.md` in the [rehex-debian](https://github.com/solemnwarning/rehex-debian) repository. rpm follows the same rules as dpkg and the same logic is applied.
