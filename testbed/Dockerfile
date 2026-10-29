# Stage 1: build liboqs + oqs-provider (FN-DSA/Falcon, HQC) for OpenSSL 3.5.
# OQS_USE_OPENSSL=ON: liboqs draws randomness from OpenSSL RAND, so `-rand <qrng file>` reaches FN-DSA keygen.
FROM alpine:3.22 AS oqs
RUN apk add --no-cache build-base cmake ninja git openssl-dev linux-headers
ARG LIBOQS_TAG=0.16.0
ARG OQSPROV_TAG=0.12.0
RUN git clone --depth 1 -b ${LIBOQS_TAG} https://github.com/open-quantum-safe/liboqs /src/liboqs \
 && cmake -S /src/liboqs -B /src/liboqs/build -GNinja -DCMAKE_INSTALL_PREFIX=/opt/oqs \
      -DBUILD_SHARED_LIBS=OFF -DCMAKE_POSITION_INDEPENDENT_CODE=ON -DOQS_BUILD_ONLY_LIB=ON \
      -DOQS_ENABLE_KEM_HQC=ON -DOQS_USE_OPENSSL=ON \
      "-DOQS_MINIMAL_BUILD=KEM_hqc_1;KEM_hqc_3;KEM_hqc_5;SIG_falcon_512;SIG_falcon_1024;SIG_falcon_padded_512;SIG_falcon_padded_1024" \
 && cmake --build /src/liboqs/build && cmake --install /src/liboqs/build
RUN git clone --depth 1 -b ${OQSPROV_TAG} https://github.com/open-quantum-safe/oqs-provider /src/oqsprov \
 && cmake -S /src/oqsprov -B /src/oqsprov/build -GNinja -Dliboqs_DIR=/opt/oqs/lib/cmake/liboqs -DOQS_KEM_ENCODERS=ON \
 && cmake --build /src/oqsprov/build \
 && cp "$(find /src/oqsprov/build -name 'oqsprovider.so' | head -1)" /oqsprovider.so

# Stage 2: one runtime image for every testbed node. OpenSSL 3.5 natively provides SLH-DSA (FIPS 205);
# oqs-provider adds FN-DSA (Falcon) signatures and HQC key exchange to TLS for nginx, python and the CLI.
FROM alpine:3.22
RUN apk add --no-cache openssl nginx nginx-mod-stream python3 py3-psycopg postgresql17 postgresql17-client \
 && mkdir -p /run/nginx /run/postgresql /data /usr/lib/ossl-modules \
 && chown postgres:postgres /run/postgresql
COPY --from=oqs /oqsprovider.so /usr/lib/ossl-modules/oqsprovider.so
COPY openssl-oqs.cnf /etc/ssl/openssl-oqs.cnf
ENV OPENSSL_CONF=/etc/ssl/openssl-oqs.cnf
COPY apps/ /apps/
COPY start.sh /start.sh
RUN chmod +x /start.sh
ENTRYPOINT ["/start.sh"]
