# Maintainer: Jefferson Cesar Antunes <jefferson.antunes@gmail.com>
pkgname=kscanner
pkgver() {
    cd "$srcdir/$pkgname"
    printf "r%s.%s" "$(git rev-list --count HEAD)" "$(git rev-parse --short HEAD)"
}
pkgrel=1
pkgdesc="Lightweight Linux memory auditing tool focused on RWX detection and automated forensic triage"
arch=('x86_64')
url="https://github.com/jeffersoncesarantunes/K-Scanner"
license=('MIT')
depends=('ncurses' 'binutils' 'coreutils')
makedepends=('git' 'gcc' 'make' 'clang' 'pkg-config' 'libbpf')
optdepends=('libbpf: eBPF real-time RWX telemetry (--bpf flag)'
            'yara: YARA rule-based scanning (--yara flag)')
source=("git+${url}.git")
sha256sums=('SKIP')

build() {
    cd "$srcdir/$pkgname"
    make bpf
    make
}

check() {
    cd "$srcdir/$pkgname"
    make test-unit
}

package() {
    cd "$srcdir/$pkgname"
    make PREFIX="$pkgdir/usr" install
}
