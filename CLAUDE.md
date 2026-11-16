@AGENTS.md

## Claude Code

- Перед PR с изменением кода запусти `/simplify`.
- После открытия такого PR запусти `/code-review medium <номер PR> --comment`, для высокого риска по [REVIEW.md](REVIEW.md) — `high`. Уровень `low` и флаг `--fix` не используй: `low` не смотрит дальше diff, `--fix` правит код без ответов в PR.
- PR `dev → main` сам не ревьюй: предложи пользователю запустить в новой сессии `/code-review high <номер PR> --comment` и `/security-review`.
- Уровни `max` и `ultra` — только по явной просьбе пользователя.
