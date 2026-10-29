# ronovo-portfolio-auth

Portfolio login, security questions and the login lock, shared by the Ronovo portfolio and the Python apps
that log in through it: Ronovo's Casino, Dead But Dreaming, Space Station Explorer, Stand Alone Gun System and
Esoteric Chat. The portfolio uses it to issue login tokens, the apps to check them.

## What is in it

| Module | What it does |
| --- | --- |
| `ronovo_portfolio_auth.portfolio_sso` | Both sides of the login token: `issue` signs one (the portfolio), `verify` checks one (the apps). Also the key helpers, the callback path and query names, and `add_flask_routes`, which adds `/sso/login` and `/sso/callback` to a Flask app. |
| `ronovo_portfolio_auth.security_questions` | The 30 security questions, answer normalizing and checks, and the reset limits (5 wrong answers, then a 15 minute lock). |
| `ronovo_portfolio_auth.login_limiter` | Locks a username for a minute after 5 wrong passwords in a row. It counts in memory, so each server process counts on its own. |

Portfolio login is on only when both `PORTFOLIO_SSO_URL` and `PORTFOLIO_SSO_PUBLIC_KEY` are set.

## Using it

Each app pins one release in its `requirements.txt`, as a GitHub release tarball so no `git` is needed:

```
ronovo-portfolio-auth @ https://github.com/Ronovo/ronovo-portfolio-auth/archive/refs/tags/v1.1.0.tar.gz
```

To release a change: bump `version` in `pyproject.toml`, push, tag it (for example `v1.0.1`), then
update the tag in each app's `requirements.txt`.

To work on it next to an app, install it from the folder instead: `pip install -e ../ronovo-portfolio-auth`.

## License

BSD 2-Clause. See [LICENSE](LICENSE).
