postgres-start:
	@docker-compose --file docker-compose.test.yml up --detach
	@sleep 3
	@go run scripts/migrate.go migrate

postgres-reset:
	@go run scripts/migrate.go rollback
	@go run scripts/migrate.go migrate

postgres-restart: postgres-stop postgres-start

postgres-stop:
	@docker-compose --file docker-compose.test.yml down --remove-orphans --volumes
