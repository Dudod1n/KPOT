# Инструкции проекта

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

Локально через `git`:

- чтение кода, `diff`, `log`, `blame`, поиск по репозиторию;
- создание веток, коммиты, `rebase`, разрешение конфликтов;
- `push` в свою ветку.

Через GitHub MCP:

- PR: создание, чтение, обновление описания, ревью и комментарии;
- issues, sub-issues и метки;
- GitHub Actions: статус запусков и логи заданий;
- релизы и теги: только чтение;
- чтение других репозиториев без клонирования: `get_file_contents`, `get_repository_tree`, `search_code`.

Не используй инструменты MCP, которые коммитят или создают ветки на GitHub: `push_files`, `create_or_update_file`, `delete_file`, `create_branch`. Они записывают коммит от владельца токена и обходят правила авторства выше.

Только с явного согласия пользователя:

- `merge_pull_request` и `update_pull_request_branch`;
- `actions_run_trigger`: запуск, перезапуск, отмена и удаление запусков;
- `create_repository`, `fork_repository`, `label_write`;
- закрытие issue или PR.

## Ссылки на сессии агентов

Не публикуй ссылки на сессии и задачи агентов (например, `https://claude.ai/code/session_…`) нигде: в коммитах, описаниях PR, комментариях, issue и файлах репозитория.
