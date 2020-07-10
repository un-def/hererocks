#!/usr/bin/env bash

# When using a hererocks-scoped API Token,
# ~/.pypirc should look like this:

# [distutils]
#   index-servers =
#     hererocks
#      
# [hererocks]
#    repository = https://upload.pypi.org/legacy/
#    username = __token__
#    password = pypi-**********API-TOKEN**********
            
[ "$1" ] || {
   echo "usage: $0 <version>"
   echo "example: $0 0.22.0"
   exit 1
}

function die() {
   echo "$@"
   exit 1
}

python3 --version || die "no python3, please install"
twine --version || die "no twine, please 'pip install twine'"
[ "$EDITOR" ] || die "please set your EDITOR variable"
[ -e hererocks.py -a -d .git ] || die "please run this script from the hererocks git clone"
[ -e ~/.pypirc ] || die "you need a ~/.pypirc config file to upload hererocks to pypi"

version=$1

set -e

echo ""
echo "First you need to edit CHANGELOG.md. Press Enter to open the editor, or Ctrl-C to cancel."
echo ""
read

$EDITOR CHANGELOG.md

echo ""
echo "Now, adjust the supported versions on README.rst. Press Enter to open the editor, or Ctrl-C to cancel."
echo ""
read

$EDITOR README.rst
sed -i 's/hererocks_version = ".*"/hererocks_version = "Hererocks '$version'"/' hererocks.py
sed -i 's/version=".*",/version="'$version'",/' setup.py

echo ""
echo "Now, let's check the resulting diff. Press Enter to commit or Ctrl-C to cancel."
echo ""
read

git diff

echo ""
echo "If the changes look all right, press Enter to commit or Ctrl-C to cancel."
echo ""
echo "***** PRESS ENTER TO RELEASE VERSION $version *****"
echo ""
read

git add CHANGELOG.md README.rst setup.py hererocks.py
git commit -m "$version release"
git tag $version
python3 -m pip install --user --upgrade setuptools wheel
python3 setup.py sdist bdist_wheel

[ -d dist ] || die "no dist!?"

twine upload --repository hererocks dist/hererocks-$version*
git push origin $version
git checkout latest
git reset --hard $version
git push --force
git checkout master
git push

