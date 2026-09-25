# Harbor Scanner Grype — установка (linux/amd64)

Образ `ant1freeze/harbor-scanner-grype:latest` собирается из этого репозитория (`Dockerfile`):
Grype 0.117.0, Syft 1.51.1, Alpine 3.24.1, база уязвимостей и список Exploit-DB внутри.
Сборка под серверы: `docker buildx build --platform linux/amd64 -t ant1freeze/harbor-scanner-grype:latest --load .`,
перенос: `docker save ant1freeze/harbor-scanner-grype:latest | gzip > harbor-scanner-grype-amd64.tar.gz`.

Файлы:
- `harbor-scanner-grype-amd64.tar.gz` — образ
- `docker-compose.yml`, `.env.example`, `deploy.sh` — для запуска
- `grype-db-2026-09-15.tar.zst` — база уязвимостей для ручного обновления (см. ниже)
- `SHA256SUMS` — контрольные суммы

## Обновление уже работающей установки

```bash
sha256sum -c SHA256SUMS
docker load -i harbor-scanner-grype-amd64.tar.gz
docker compose up -d
```

В `.env` проверьте `SCANNER_JOB_QUEUE_WORKER_CONCURRENCY=5` — не больше, чем воркеров у Harbor.

## Первая установка

```bash
sha256sum -c SHA256SUMS
docker load -i harbor-scanner-grype-amd64.tar.gz
cp .env.example .env        # отредактировать: ключ API, учётка registry, хосты, пороги, воркеры
docker rm -f grype-adapter grype-redis   # только при переходе со старой версии
docker compose up -d
```

После правки `.env` — снова `docker compose up -d`.

Сборка на сервере не нужна: compose использует загруженный образ и не тянет старый с Docker Hub.
Нужен ещё `redis:7-alpine`; если его нет на сервере, compose скачает его (~15 МБ).

Учётка `SCANNER_REGISTRY_USERNAME`/`SCANNER_REGISTRY_PASSWORD` из `.env` отправляется только на
хосты из `SCANNER_REGISTRY_TRUSTED_HOSTS`. Проверка сертификата registry по умолчанию выключена
(`SCANNER_REGISTRY_INSECURE_SKIP_TLS_VERIFY=true`), как в готовом образе; чтобы включить —
смонтировать свой CA в контейнер, указать `SSL_CERT_FILE` (или `SSL_CERT_DIR`) и поставить
`SCANNER_REGISTRY_INSECURE_SKIP_TLS_VERIFY=false`.

## Регистрация в Harbor

1. Сгенерировать ключ: `openssl rand -hex 32` (не короче 16 символов) и записать его в `.env` как `SCANNER_API_KEY`.
2. `docker compose up -d`.
3. Harbor → Interrogation Services → Scanners → New Scanner: адрес `http://grype-adapter:8090`,
   Authorization — `Bearer`, Credentials — тот же ключ. Без ключа коннектор отвечает 401.

## Уровни в Harbor

Режим `SCANNER_RISK_MODE=policy`: уровень выставляется по пяти правилам, причина с датой оценки
пишется в начало описания уязвимости, например
«High: риск grype 69.0, порог High от 30 (EPSS 92%, критичность grype High); эксплойтов не найдено; в KEV нет.».
Правила и пороги — в `RISK_CALCULATION.md`. Harbor хранит первое описание записи (CVE/пакет/версия)
навсегда и не переписывает его при повторных сканах — после смены `SCANNER_POLICY_*` или режима
перерегистрируйте сканер, чтобы получить свежие причины (порядок действий и почему — в
`RISK_CALCULATION.md`, раздел «Harbor keeps the first description»).

## База уязвимостей

Обновляется ночью по cron (`GRYPE_DB_UPDATE_SCHEDULE` в `.env`), результат — в логе контейнера
и в `/var/log/grype-update.log`. База хранится в volume `grype_db`, поэтому загрузка нового
образа её не заменяет.

Если ночное обновление не может скачать базу (например, `dial tcp ...: i/o timeout`), обновите
её вручную из архива. Сканы перестают работать, если база старше 5 дней
(`GRYPE_DB_MAX_ALLOWED_BUILT_AGE`).

```bash
docker cp grype-db-2026-09-15.tar.zst grype-adapter:/tmp/grype-db.tar.zst
docker exec -u scanner grype-adapter grype db import /tmp/grype-db.tar.zst
docker exec grype-adapter rm /tmp/grype-db.tar.zst
docker exec -u scanner grype-adapter grype db status
```

Тем же ночным заданием обновляется список Exploit-DB (`SCANNER_EXPLOITDB_URL`, через `HTTPS_PROXY`, если задан).
Если скачать не удалось, остаётся прежняя копия; в образе есть копия на момент сборки.

## Логи

События сканов (queued / started / finished / failed / skipped с причиной), свободные воркеры,
дата базы при старте, ночное обновление:

```bash
docker compose logs -f grype-adapter
docker compose logs grype-adapter | grep -E 'msg="Scan (failed|skipped)"'
```
