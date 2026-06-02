# Maintainer: Jefferson Cesar Antunes <jefferson.antunes@gmail.com>
pkgname=kscanner
pkgver=0.1.0
pkgrel=1
pkgdesc="Lightweight Linux memory auditing tool focused on RWX detection and automated forensic triage"
arch=('x86_64')
url="https://github.com/jeffersoncesarantunes/K-Scanner"
license=('MIT')
depends=('ncurses' 'binutils')
makedepends=('gcc' 'make' 'clang' 'pkg-config')
optdepends=('libbpf: eBPF real-time RWX telemetry (--bpf flag)')
source=("$pkgname-$pkgver.tar.gz::https://github.com/jeffersoncesarantunes/K-Scanner/archive/v$pkgver.tar.gz")
sha256sums=('SKIP')

build() {
    cd "$srcdir/K-Scanner-$pkgver"
    make bpf
    make
}

check() {
    cd "$srcdir/K-Scanner-$pkgver"
    make test
}

package() {
    cd "$srcdir/K-Scanner-$pkgver"
    make PREFIX="$pkgdir/usr" install
}
