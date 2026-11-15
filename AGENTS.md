# Инструкции проекта

## Правила проекта

Правила описаны в профильных документах. Прочитай нужный документ до начала работы и следуй ему:

- [docs/WORKFLOW.md](docs/WORKFLOW.md) — задачи, ветки, коммиты и pull request;
- [REVIEW.md](REVIEW.md) — ревью изменений и приоритеты замечаний;
- [docs/RELEASING.md](docs/RELEASING.md) — подготовка и публикация выпуска;
- [CONTRIBUTING.md](CONTRIBUTING.md) — окружение, проверки и устройство кода.

Любое изменение делай в ветке от `dev` и после завершения открывай PR из этой ветки в `dev`.

## Авторство коммитов Git

При создании коммита самостоятельно подставляй имя и email своего агента для автора и коммитера. Передавай данные только на время вызова `git commit`. В Bash выбери свою команду и подставь сообщение коммита.

```bash
# Codex использует служебный адрес проекта.
GIT_AUTHOR_NAME=Codex GIT_AUTHOR_EMAIL=codex@kpot.invalid \
  GIT_COMMITTER_NAME=Codex GIT_COMMITTER_EMAIL=codex@kpot.invalid \
  git commit -m "<commit message>"

# Claude Code
GIT_AUTHOR_NAME=Claude GIT_AUTHOR_EMAIL=noreply@anthropic.com \
  GIT_COMMITTER_NAME=Claude GIT_COMMITTER_EMAIL=noreply@anthropic.com \
  git commit -m "<commit message>"
```

Авторство задаётся только этими переменными. Не добавляй в сообщение коммита служебные строки вроде `Co-Authored-By:` или `Claude-Session:`.

## GitHub MCP и локальный Git

Всё, что меняет код и историю, делай локальным `git`, а работу с GitHub как с платформой — через GitHub MCP. Если GitHub MCP недоступен, используй `gh`.

Правила ниже описывают действия и одинаково действуют для GitHub MCP, `gh` и прямых вызовов API. Названия инструментов и команд приведены как примеры.

Локально через `git`:

- чтение кода, `diff`, `log`, `blame`, поиск по репозиторию;
- создание веток, коммиты, `rebase`, разрешение конфликтов;
- `push` в свою ветку.

Через GitHub MCP:

- PR: создание, чтение, обновление описания, ревью и комментарии;
- issues и sub-issues, назначение и снятие существующих меток;
- GitHub Actions: статус запусков и логи заданий;
- релизы и теги: только чтение;
- чтение других репозиториев без клонирования: `get_file_contents`, `get_repository_tree`, `search_code`.

Не создавай коммиты и ветки на стороне GitHub в обход локального `git`: `push_files`, `create_or_update_file`, `delete_file`, `create_branch`, запись файлов через `gh api`. Такой коммит записывается от владельца токена и обходит правила авторства выше.

Только с явного согласия пользователя:

- слияние PR и обновление его ветки: `merge_pull_request`, `update_pull_request_branch`, `gh pr merge`;
- запуск, перезапуск и отмена workflow, удаление запусков и их журналов: `actions_run_trigger`, `gh workflow run`, `gh run rerun`, `gh run cancel`;
- создание, форк и удаление репозиториев, изменение их настроек и правил: `create_repository`, `fork_repository`, `delete_repository`, `create_repository_ruleset`;
- создание, изменение и удаление меток репозитория: `label_write`, `gh label`;
- передача работы Copilot: `assign_copilot_to_issue`, `create_pull_request_with_copilot`;
- публикация вне репозитория, например `create_gist`;
- закрытие issue или PR;
- любое другое изменяющее действие на GitHub, которого нет в списках выше.

## Ссылки на сессии агентов

Не публикуй ссылки на сессии и задачи агентов (например, `https://claude.ai/code/session_…`) нигде: в коммитах, описаниях PR, комментариях, issue и файлах репозитория.
