# ronovo-portfolio-auth

Portfolio login and security questions, shared by the Python apps that log in through the Ronovo
portfolio: Ronovo's Casino, Dead But Dreaming, Space Station Explorer, Stand Alone Gun System and
Esoteric Chat. The portfolio itself uses `security_questions`.

## What is in it

| Module | What it does |
| --- | --- |
| `ronovo_portfolio_auth.portfolio_sso` | Sends a player to the portfolio's `/sso/authorize` and checks the RS256 token it posts back. `add_flask_routes` adds `/sso/login` and `/sso/callback` to a Flask app. |
| `ronovo_portfolio_auth.security_questions` | The 30 security questions, answer normalizing and checks, the reset limits (5 wrong answers, then a 15 minute lock), and the stand-in question shown for a username with no account. |

Portfolio login is on only when both `PORTFOLIO_SSO_URL` and `PORTFOLIO_SSO_PUBLIC_KEY` are set.

## Using it

Each app pins one release in its `requirements.txt`, as a GitHub release tarball so no `git` is needed:

```
ronovo-portfolio-auth @ https://github.com/Ronovo/ronovo-portfolio-auth/archive/refs/tags/v1.0.0.tar.gz
```

To release a change: bump `version` in `pyproject.toml`, push, tag it (for example `v1.0.1`), then
update the tag in each app's `requirements.txt`.

To work on it next to an app, install it from the folder instead: `pip install -e ../ronovo-portfolio-auth`.
