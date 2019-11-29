export LDFLAGS="-L/usr/local/lib -liconv"
export CPPFLAGS=-I/usr/local/opt/openssl/include
autoreconf -i
./configure --with-openssl=/usr/local/opt/openssl --without-wbclient  --disable-nls --with-xml-catalog-path=/usr/local/etc/xml/catalog
make
sudo make install

