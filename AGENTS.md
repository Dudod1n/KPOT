# Инструкции проекта

## Порядок работы

GitHub Flow: ветка от `dev` → коммиты и push → PR в `dev` → ревью и проверки → слияние.
`main` обновляется только PR `dev → main`, см. [docs/RELEASING.md](docs/RELEASING.md).

- Ветка: `<тип>/<кратко-латиницей>`, с задачей — `<тип>/<номер>-<кратко>`, например `fix/42-ipv6-reject`.
- Коммит и заголовок PR: `<тип>(<область>): <описание>`. Типы: `feat`, `fix`, `docs`, `test`, `refactor`, `perf`, `build`, `ci`, `chore`, `release`. Область можно опустить. Описание на русском, со строчной буквы, без точки, о результате.
- Один PR — одна задача. Описание PR заполняй по шаблону; задачу указывай строкой `Closes #N`.
- Задаче, созданной через API или MCP, ставь метку типа явно: `bug`, `enhancement` или `documentation`.
- Перед push изменения кода выполни проверки из [CONTRIBUTING.md](CONTRIBUTING.md#проверки).
- Ревью идёт по [REVIEW.md](REVIEW.md).

## Авторство коммитов Git

При создании коммита самостоятельно подставляй имя и email своего агента для автора и коммитера. Передавай данные только на время вызова `git commit`.

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

Не добавляй в сообщение коммита служебные строки вроде `Co-Authored-By:` или `Claude-Session:`.

## Git и GitHub

Код и историю меняй только локальным `git`: ветки, коммиты, `rebase`, `push` в свою ветку. Не создавай коммиты и ветки на стороне GitHub (`push_files`, `create_or_update_file`, `create_branch`, запись через `gh api`): они записываются от владельца токена в обход правил авторства.

С GitHub как с платформой работай через GitHub MCP, а если он недоступен — через `gh`: PR, комментарии, задачи, существующие метки, чтение Actions.

Только с явного согласия пользователя:

- слияние PR и обновление его ветки;
- закрытие задачи или PR;
- запуск, перезапуск и отмена workflow, удаление запусков;
- создание, изменение и удаление меток репозитория;
- создание, удаление и настройка репозиториев;
- публикация вне репозитория и передача работы Copilot;
- любое другое изменяющее действие на GitHub, не названное в этом разделе.

Не публикуй ссылки на сессии и задачи агентов (например, `https://claude.ai/code/session_…`) нигде: в коммитах, PR, комментариях, задачах и файлах репозитория.
