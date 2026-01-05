# Security Features

## JWKS Endpoint URL Validation

### Overview

Per prevenire attacchi SSRF (Server-Side Request Forgery), il bundle implementa una validazione rigorosa dell'URL del JWKS endpoint.

### Validazione dell'URL Base

L'URL base di Keycloak (`base_url`) viene validato nel costruttore di `JWKSTokenDecoder` per garantire:

1. **Formato URL valido**: L'URL deve avere uno schema (scheme) e un host validi
2. **Solo HTTPS**: Viene forzato l'uso di HTTPS per ambienti non-localhost
3. **Blocco IP privati**: Gli indirizzi IP privati (RFC 1918) sono bloccati automaticamente
4. **Blocco endpoint metadata**: Gli endpoint di metadata cloud (es. 169.254.169.254) sono bloccati
5. **Localhost consentito**: HTTP è consentito solo per localhost (127.0.0.1, ::1, localhost)

### Whitelist Domini JWKS

È possibile configurare una whitelist di domini autorizzati per le richieste JWKS:

```yaml
# config/packages/mainick_keycloak_client.yaml

mainick_keycloak_client:
  keycloak:
    base_url: '%env(IAM_BASE_URL)%'
    realm: '%env(IAM_REALM)%'
    # ... altre configurazioni ...

    # Whitelist di domini consentiti per l'endpoint JWKS
    allowed_jwks_domains:
      - 'keycloak.example.com'
      - '*.auth.example.com'  # Supporta wildcard per sottodomini
```

### Comportamento Predefinito

Se non viene specificata alcuna whitelist (`allowed_jwks_domains`), il bundle consente **solo** il dominio presente in `base_url`.

Esempio:
- Se `base_url` è `https://keycloak.example.com`, solo questo dominio sarà consentito per le richieste JWKS
- Qualsiasi tentativo di reindirizzamento o richiesta a un dominio diverso verrà bloccato

### Wildcard per Sottodomini

È possibile utilizzare wildcard per consentire tutti i sottodomini di un dominio specifico:

```yaml
allowed_jwks_domains:
  - '*.example.com'  # Consente auth.example.com, keycloak.example.com, ecc.
```

**Nota**: Il wildcard `*.example.com` consente sia `auth.example.com` che `example.com` stesso.

### Validazione HTTPS

Per gli ambienti non-localhost, l'endpoint JWKS **deve** utilizzare HTTPS. Qualsiasi tentativo di utilizzare HTTP per domini pubblici verrà rifiutato con un'eccezione.

### Eccezioni di Sicurezza

Quando viene rilevata una violazione di sicurezza, viene lanciata un'eccezione `TokenDecoderException` con un messaggio dettagliato che indica:

- Il dominio non autorizzato
- Il motivo del rifiuto (non nella whitelist, IP privato, ecc.)

Esempio di messaggio di errore:
```
Invalid token: JWKS URL host "malicious.com" is not in the allowed domains whitelist
```

### Hosts Bloccati

I seguenti pattern di host sono automaticamente bloccati:

- Indirizzi IP privati (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16)
- Indirizzi IP riservati (169.254.0.0/16, 224.0.0.0/4, 240.0.0.0/4)
- Endpoint metadata cloud:
  - `metadata.google.internal`
  - `169.254.169.254` (AWS metadata)
  - Qualsiasi host contenente `metadata` o `internal`

### Best Practices

1. **Ambiente di produzione**: Specificare sempre una whitelist esplicita di domini autorizzati
2. **HTTPS obbligatorio**: Non utilizzare HTTP per domini pubblici
3. **Minimizzare la whitelist**: Includere solo i domini strettamente necessari
4. **Evitare wildcard ampi**: Preferire domini specifici quando possibile
5. **Monitoraggio**: Registrare e monitorare le eccezioni `TokenDecoderException` per rilevare potenziali tentativi di attacco

### Esempio di Configurazione Sicura

```yaml
mainick_keycloak_client:
  keycloak:
    verify_ssl: true
    base_url: 'https://keycloak.example.com'
    realm: 'production'
    client_id: '%env(IAM_CLIENT_ID)%'
    client_secret: '%env(IAM_CLIENT_SECRET)%'
    # ... altre configurazioni ...

    # Whitelist rigorosa per l'ambiente di produzione
    allowed_jwks_domains:
      - 'keycloak.example.com'
      - 'auth.example.com'
```

### Test di Sicurezza

Il bundle include test completi per verificare:

- Validazione del formato URL
- Rifiuto di HTTP per domini non-localhost
- Blocco di IP privati
- Blocco di endpoint metadata
- Funzionamento della whitelist domini
- Supporto wildcard per sottodomini
- Validazione HTTPS per endpoint JWKS

Per eseguire i test di sicurezza:

```bash
./vendor/bin/phpunit tests/Token/JWKSTokenDecoderTest.php
```

## Segnalazione Vulnerabilità

Se scopri una vulnerabilità di sicurezza, ti preghiamo di **NON** aprire un issue pubblico. Invia invece una segnalazione privata seguendo le linee guida nel file `SECURITY.md` nella root del progetto.

