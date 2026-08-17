# Attack Surface — Sample Fixture

**Probe date:** 2026-07-29

## Endpoints

| Method | Path | Auth | Handler |
|--------|------|------|---------|
| POST | /auth/login | None | loginHandler |
| POST | /auth/token | None | tokenHandler |
| GET | /debug/pprof/ | None | pprofHandler |
| GET | /debug/vars | None | varsHandler |
| GET | /api/users | Bearer | usersHandler |
