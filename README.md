# EVoting System

Konzolna Java aplikacija koja simulira sistem za sigurno online glasanje (e-voting). Razvijena kao projektni zadatak iz predmeta **Kriptografija i računarska zaštita** na Elektrotehničkom fakultetu Banja Luka.

**Autor:** Dajana Popović

---

## Sadržaj

- [Opis projekta](#opis-projekta)
- [Tehnologije](#tehnologije)
- [Arhitektura](#arhitektura)
- [Kriptografski mehanizmi](#kriptografski-mehanizmi)
- [Pokretanje](#pokretanje)
- [Korišćenje](#korišćenje)
- [Struktura projekta](#struktura-projekta)

---

## Opis projekta

Sistem omogućava dva tipa korisnika — **organizatore** i **glasače** — da bezbijedno učestvuju u procesu elektronskog glasanja. Svaki korisnik dobija digitalni sertifikat pri registraciji, a autentifikacija se vrši u dva koraka: validacijom sertifikata, a zatim provjerom korisničkog imena i lozinke.

Glasovi se enkriptuju simetričnim algoritmom (AES/GCM) sa jedinstvenim ključem po glasu, koji se zatim enkriptuje RSA javnim ključem organizatora. Na taj način samo organizator može dešifrovati glasove i pokrenuti brojanje rezultata.

---

## Tehnologije

- **Java 11**
- **Maven** (upravljanje zavisnostima)
- **Bouncy Castle 1.78** (`bcprov-jdk18on`, `bcpkix-jdk18on`) — kriptografske operacije
- Podaci se čuvaju lokalno putem Java serijalizacije (`.ser` fajlovi) i PKCS12 keystoreova

---

## Arhitektura

### CA hijerarhija (dva nivoa)

```
RootCA
├── OrganizationalCA  →  izdaje sertifikate organizatorima
└── VoterCA           →  izdaje sertifikate glasačima
```

Root CA samo potpisuje podređena CA tijela i ne izdaje korisničke sertifikate. Svako CA tijelo vodi svoju CRL listu.

### Klase sistema

| Klasa | Uloga |
|---|---|
| `Main` | Ulazna tačka, konzolni meni |
| `AuthenticationService` | Dvofazna prijava, praćenje neuspjelih pokušaja, automatsko povlačenje sertifikata |
| `StorageService` | Persistencija korisnika, glasanja, CA podataka |
| `CertificateManager` | Izdavanje i validacija sertifikata |
| `CryptoUtils` | Sve kriptografske operacije (RSA, AES/GCM, HMAC, potpis) |
| `VotingService` | Kreiranje glasanja, glasanje, brojanje, verifikacija |
| `CRLManager` | Upravljanje listama povučenih sertifikata |
| `CA`, `RootCA`, `OrganizationalCA`, `VoterCA` | CA hijerarhija |
| `User`, `Organizer`, `Voter` | Model korisnika |
| `Poll`, `Vote` | Model glasanja i glasa |

---

## Kriptografski mehanizmi

### Sertifikati i ključevi
- RSA ključni par (2048 bita) generiše se za svakog korisnika pri registraciji
- Sertifikati (X.509 v3) sadrže odgovarajuće ekstenzije (`basicConstraints`, `keyUsage`, `extendedKeyUsage`)
- Sertifikat i privatni ključ se čuvaju u passwordom zaštićenom **PKCS12** fajlu (`evoting_data/user_certs/<username>.p12`)

### Enkripcija glasova
- Svaki glas se enkriptuje algoritmom **AES-256/GCM** (sa nasumičnim IV)
- Simetrični ključ se enkriptuje **RSA/PKCS1** javnim ključem organizatora
- Glasovi se dešifruju tek pri brojanju, privatnim ključem organizatora

### Integritet metapodataka
- Metapodaci glasanja se štite **HMAC-SHA256** algoritmom

### Digitalni potpisi
- Glasovi se potpisuju privatnim ključem glasača (**SHA256withRSA**)
- Izvještaji rezultata su digitalno potpisani
- Glasač može u svakom trenutku verifikovati svoj glas bez otkrivanja sadržaja

### Zaštita od napada
- Nakon **3 neuspješne prijave**, sertifikat korisnika se automatski povlači (dodaje na CRL)
- Validacija sertifikata uključuje: provjeru potpisa izdavača, vremensku validnost, provjeru CRL liste i poklapanje CN-a sa korisničkim imenom

---

## Pokretanje

### Preduslovi
- Java 11 ili novija
- Maven 3.6+

### Build i pokretanje

```bash
# Klonirati repozitorijum
git clone <repo-url>
cd EVotingSystem_Dajana_Popovic_1158-21

# Build
mvn compile

# Pokretanje
mvn exec:java -Dexec.mainClass="evoting.Main"
```

> **Napomena:** Pri prvom pokretanju sistem generiše CA infrastrukturu i traži lozinku za CA keystore. Ovu lozinku je potrebno zapamtiti — koristi se pri svakom narednom pokretanju.

---

## Korišćenje

### Registracija

```
=== E-VOTING SYSTEM ===
1. Register
2. Login
3. Exit
Choice: 1

Account type (organizer/voter): organizer
Username: org1
Organization name: Izborna komisija
Identification number: 12345
Password: ****
```

Nakon registracije, generišu se ključevi i sertifikat koji se čuvaju u `evoting_data/user_certs/<username>.p12`.

### Prijava

```
Path to your certificate file (.p12): evoting_data/user_certs/org1.p12
Username: org1
Password: ****
```

### Organizator — kreiranje glasanja

```
--- ORGANIZER MENU ---
1. Create new poll
2. List my polls
3. Tally votes (after end date)
4. Logout
```

- Navodi se naslov, opis, vremenski period (`yyyy-MM-dd HH:mm`) i 2–5 opcija

### Glasač — glasanje i verifikacija

```
--- VOTER MENU ---
1. List active polls
2. Vote
3. Verify my last vote
4. Logout
```

- Glasač bira aktivno glasanje, odabira opciju — glas se automatski enkriptuje i potpisuje
- Verifikacija glasa ne otkriva sadržaj

### Brojanje glasova

Organizator pokreće brojanje po isteku glasanja. Sistem dešifruje glasove, broji rezultate i generiše digitalno potpisan izvještaj u `evoting_data/reports/`.

---

## Struktura projekta

```
EVotingSystem/
├── src/main/java/evoting/
│   ├── Main.java                  # Ulazna tačka, konzolni meni
│   ├── AuthenticationService.java # Prijava i upravljanje sesijom
│   ├── StorageService.java        # Persistencija podataka
│   ├── CertificateManager.java    # Izdavanje i validacija sertifikata
│   ├── CryptoUtils.java           # Kriptografske operacije
│   ├── VotingService.java         # Logika glasanja
│   ├── CRLManager.java            # CRL liste
│   ├── CA.java / RootCA.java / OrganizationalCA.java / VoterCA.java
│   ├── User.java / Organizer.java / Voter.java
│   ├── Poll.java / Vote.java
├── evoting_data/                  # Generiše se automatski pri pokretanju
│   ├── ca/                        # CA keystore i CRL liste
│   ├── user_certs/                # PKCS12 fajlovi korisnika
│   ├── reports/                   # Potpisani izvještaji rezultata
│   ├── users.ser                  # Serializovani podaci o korisnicima
│   └── polls.ser                  # Serializovana glasanja
└── pom.xml
```
