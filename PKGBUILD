# Maintainer: Jefferson Cesar Antunes <jefferson.antunes@gmail.com>
pkgname=kscanner
pkgver=20260831
pkgrel=1
pkgdesc="Lightweight Linux memory auditing tool focused on RWX detection and automated forensic triage"
arch=('x86_64')
url="https://github.com/jeffersoncesarantunes/K-Scanner"
license=('MIT')
depends=('ncurses' 'binutils')
makedepends=('gcc' 'make' 'clang' 'pkg-config' 'libbpf')
optdepends=('libbpf: eBPF real-time RWX telemetry (--bpf flag)')
source=("$pkgname-$pkgver.tar.gz::https://github.com/jeffersoncesarantunes/K-Scanner/archive/main.tar.gz")
# Packaged straight from the default branch (no version tag required).
# Generate the sha256sum with:
#   curl -sL https://github.com/jeffersoncesarantunes/K-Scanner/archive/main.tar.gz | sha256sum
sha256sums=('SKIP')

build() {
    cd "$srcdir/K-Scanner-main"
    make bpf
    make
}

check() {
    cd "$srcdir/K-Scanner-main"
    make test
}

package() {
    cd "$srcdir/K-Scanner-main"
    make PREFIX="$pkgdir/usr" install
}
