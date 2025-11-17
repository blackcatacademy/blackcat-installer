# BlackCat Installer – Roadmap

## Stage 1 – Skeleton ✅
- CLI `blackcat-installer list/install` + načtení `modules.json`.
- Zatím dry-run logování (příprava na composer/npm dispatch).

## Stage 2 – Bootstrap workflows (in progress)
- ✅ Generování `.env` kombinací modulových proměnných (`--env-out`, `--no-env`).
- ✅ Bootstrap runner (spouští `bootstrap` příkazy, volitelně `--no-bootstrap`).
- ▢ Templaty pro docker-compose (observability, database).

## Stage 3 – AI Integration
- REST API + OpenAI agent workflow (prompt -> modules). `installer ai-setup "project needs auth + analytics"`.

## Stage 4 – Frontend org support
- Automatické naklonování FE repo, instalace UI modulů, link s backend moduly.

## Stage 5 – Cloud deploy
- Provisioning Terraform/helm templaty, multi-env pipeline.
