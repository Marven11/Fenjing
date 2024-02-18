# This is an example PKGBUILD file. Use this as a start to creating your own,
# and remove these comments. For more information, see 'man PKGBUILD'.
# NOTE: Please fill out the license field for your package! If it is unknown,
# then please put 'unknown'.

# See http://wiki.archlinux.org/index.php/Python_Package_Guidelines for more
# information on Python packaging.

# Maintainer: Marven11 <110723864+Marven11@users.noreply.github.com>
pkgname=python-fenjing
pkgver=$(cat VERSION)
pkgrel=1
pkgdesc=""
arch=('any')
url=""
license=('MPL-2.0')
groups=()
depends=(
  'python'
  'python-requests'
  'python-beautifulsoup4'
  'python-click'
  'python-flask'
  'python-jinja'
  'python-prompt_toolkit'
  'python-pygments'
  'python-pysocks'
)
makedepends=('python-build')
provides=()
conflicts=()
replaces=()
backup=()
options=(!emptydirs)
install=
source=()
md5sums=()

package() {
  cd "$srcdir/.."
  python -m build
  PIP_CONFIG_FILE=/dev/null pip install --isolated --root="$pkgdir" --ignore-installed --no-deps dist/*.whl
}

# vim:set ts=2 sw=2 et:
