# Maintainer: Gavin Lloyd <gavinhungry@gmail.com>

pkgname=combust-git
pkgver=20130331
pkgrel=1
pkgdesc='Firewall/iptables script with profiles'
arch=('any')
license=('MIT')
url='https://github.com/gavinhungry/combust'
depends=('iptables')

_gitroot='https://github.com/gavinhungry/combust.git'
_gitname='combust'
_gitbranch='master'

build() {
  cd "${srcdir}"
  msg 'Connecting to Git server ...'
  if [ -d ${_gitname} ] ; then
    cd ${_gitname} && git pull origin
    msg 'Local Git tree is up to date'
  else
    msg "Cloning Git repository: ${_gitbranch} branch"
    git clone --depth=1 ${_gitroot} ${_gitname} --branch ${_gitbranch}
  fi
}

package() {
  cd "${srcdir}/${_gitname}"

  install -d $pkgdir/etc/iptables/
  install -d $pkgdir/usr/lib/systemd/system/
  install -m755 combust.sh "${pkgdir}"/etc/iptables/
  install -m600 combust.conf "${pkgdir}"/etc/iptables/
  install -m644 combust.service "${pkgdir}"/usr/lib/systemd/system/
}

