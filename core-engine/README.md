# core-engine (SecureFile backend)

## Prereqs

- Java 17
- Maven
- A PKCS12 keystore at `../keystore/securefile.p12` (or adjust `application.properties`)

## Create keystore (example)

keytool -genkeypair -alias securefilekey -keyalg RSA -keysize 2048 \
 -dname "CN=SecureFileApp, OU=Dev, O=YourOrg, L=City, ST=State, C=IN" \
 -validity 3650 -keystore securefile.p12 -storetype PKCS12 \
 -storepass ChangeMe123! -keypass ChangeMe123!

Put `securefile.p12` into `SecureFileApp/keystore/` and update `application.properties` path.

## Run

mvn clean package
mvn spring-boot:run

Endpoints:
POST /api/security/encrypt (form-data: files[], policy)
POST /api/security/decrypt (form-data: file)
