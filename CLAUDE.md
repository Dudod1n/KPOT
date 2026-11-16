@AGENTS.md

## Claude Code

- После открытия PR с высоким риском по [REVIEW.md](REVIEW.md) запусти `/code-review high <номер PR> --comment`. Флаг `--fix` не используй: он правит код без ответов в PR.
- PR `dev → main` сам не ревьюй: предложи пользователю запустить в новой сессии `/code-review high <номер PR> --comment` и `/security-review`.
- Уровни `max` и `ultra` — только по явной просьбе пользователя.
