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

## Ссылки на сессии агентов

Не публикуй ссылки на сессии и задачи агентов (например, `https://claude.ai/code/session_…`) нигде: в коммитах, описаниях PR, комментариях, issue и файлах репозитория.
