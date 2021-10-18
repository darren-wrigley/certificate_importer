# certificate_util
utility library to download site certificates (chain of certs) to import into a truststore

# usage
java -jar certificate_importer-1.0.jar --url=https://<server_with_optional_port> --keystore <truststore_file_to_import certs> --storepass=<truststore password>

Notes:  
- you can pass multiple --url arguments
- if you do use --storepass, you will be prompted for a password
- if your keystore has no password, use --storepass=      (with no value)


# example urls
- for google (bigquery & storage)

   `--url=https://console.cloud.google.com/`

- for snowflake: example account

    `--url=https://<snowflake account>.snowflakecomputing.com/`

e.g. `--url=https://informaticapartner.snowflakecomputing.com/`

you can add as many url's as you want in a single run

# sample output
```
java -jar certificate_importer-1.0.jar --url=https://console.cloud.google.com/ --keystore=$INFA_HOME/services/shared/security/infa_truststore.jks
web app certificate export & trustore import
no password passed for truststore: prompt for input
Password for keystore:
running cert export & import for truststore
extracting certicates...
website... Certificates for url = https://console.cloud.google.com/
        writing certificate: ./certs/*.googlecode.com.pem with 31 lines
        writing certificate: ./certs/GTS CA 1C3.pem with 32 lines
        writing certificate: ./certs/GTS Root R1.pem with 31 lines
        writing certificate: ./certs/GlobalSign Root CA.pem with 21 lines
4 certificates extracted
loading keystore: /opt/informatica/1051/services/shared/security/infa_truststore.jks
        adding new alias 'GlobalSign Root CA' to keystore
        adding new alias 'GTS Root R1' to keystore
        adding new alias 'GTS CA 1C3' to keystore
        adding new alias '*.googlecode.com' to keystore
updating keystore, with 4 new entries
```
