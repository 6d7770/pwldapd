#!/bin/sh
# Build (or update) the APT and dnf repositories served from GitHub Pages.
#
# Usage: publish.sh SITE_DIR PKG_DIR
#   SITE_DIR  checkout of the gh-pages branch (created if empty)
#   PKG_DIR   directory containing the release .deb and .rpm files
#
# Requires reprepro, createrepo_c, rpmsign and gpg, with exactly one
# secret key in the default keyring; it signs the APT Release file, every
# RPM, and the rpm repodata. Run from the repository root.
set -eu

site="$1"
pkgs="$2"
here="$(cd "$(dirname "$0")" && pwd)"

keyid="$(gpg --list-secret-keys --with-colons | awk -F: '/^fpr:/ { print $10; exit }')"
if [ -z "$keyid" ]; then
    echo "publish.sh: no secret key in the gpg keyring" >&2
    exit 1
fi

# APT: reprepro manages the pool and dists trees and signs Release.
mkdir -p "$site/deb"
reprepro --basedir "$site/deb" --confdir "$here/conf" \
    includedeb stable "$pkgs"/*.deb
# The reprepro database is not part of the published site.
rm -rf "$site/deb/db"

# dnf: one repository per architecture. Each package carries its own
# signature (dnf's gpgcheck=1 requires it) and the metadata is signed
# detached (repo_gpgcheck=1).
for rpm in "$pkgs"/*.rpm; do
    arch="$(rpm -qp --queryformat '%{ARCH}' "$rpm" 2>/dev/null \
        || basename "$rpm" | sed 's/.*\.\([^.]*\)\.rpm$/\1/')"
    mkdir -p "$site/rpm/$arch"
    dest="$site/rpm/$arch/$(basename "$rpm")"
    cp "$rpm" "$dest"
    rpmsign --define "_gpg_name $keyid" --addsign "$dest"
done
for dir in "$site"/rpm/*/; do
    createrepo_c --update "$dir"
    rm -f "$dir/repodata/repomd.xml.asc"
    gpg --batch --yes --detach-sign --armor --local-user "$keyid" \
        "$dir/repodata/repomd.xml"
done
cp "$here/pwldapd.repo" "$site/rpm/pwldapd.repo"

# Public key in both forms, and the landing page.
gpg --batch --yes --export "$keyid" > "$site/pwldapd-archive-keyring.gpg"
gpg --batch --yes --export --armor "$keyid" > "$site/pwldapd-archive-keyring.asc"
cp "$here/index.html" "$site/index.html"
# Pages must not run Jekyll over the repository trees.
: > "$site/.nojekyll"

echo "repository updated in $site (key $keyid)"
