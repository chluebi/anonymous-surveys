# anonymous-surveys
making (vaguely) anonymous online surveys from scratch

### Permission Levels

- ``private``: Not accessible by anyone
- ``guild-only``: Only accessible by people in ``guilds``
- ``log-in``: Only accessible by people who have logged in with a Discord account
- ``public``: (Results only) Accessible by everyone

If the permission level of ``results`` is set to ``guild-only`` or ``log-in``, ``results-only-after`` can
be set to ``true`` to only allow seeing results after filling in the survey.
