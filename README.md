# BlackCat Installer

Automatizovaný instalátor, který podle výběru modulů (auth, database, observability, governance…) připraví kompletní prostředí. Je navržen tak, aby fungoval jak manuálně (CLI), tak přes AI scénář: AI si "objedná" stack a installer vyřeší composer/npm dependency, bootstrap databází, docker compose atd.

## Hlavní úlohy
- čte `modules.json` katalog (v repo `blackcat-modules`)
- provádí `composer require` + `npm install` podle modulů
- generuje `.env` / `.blackcatrc`
- spouští bootstrap skripty (např. `php bin/auth-http --init`)
- integruje se s GitHub Actions / AI agentem (OpenAI) – prompt -> modul list -> instalace

Repo nyní obsahuje skeleton (viz docs/ROADMAP). Další vývoj: CLI `blackcat-installer`, API pro AI integraci, pluginy.

## CLI (Stage 1)

```bash
# přehled katalogu modulů
php bin/installer list

# instalace vybraných modulů (zapisuje do logu, generuje .blackcat/env.generated)
php bin/installer install --modules=auth-core,observability

# změna cesty pro generovaný env soubor nebo vypnutí
php bin/installer install --modules=auth-core --env-out=config/.env.blackcat
php bin/installer install --modules=observability --no-env

# vypnutí bootstrap hooků
php bin/installer install --modules=auth-core --no-bootstrap
```

CLI čte `modules.json` a vypisuje, které composer/npm/docker kroky by bylo potřeba spustit. Současně generuje `.env` soubor kombinací všech modulů a spouští bootstrap příkazy definované v katalogu (např. `php bin/auth-http --init`). V dalších fázích se přidá skutečné volání composer/npm a scaffolding docker-compose.
