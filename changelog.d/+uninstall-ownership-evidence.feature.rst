``pipx uninstall --dry-run`` now reports the ownership evidence for every exposed app, manual page, and completion and
says which entries it would remove and which it would keep. A real uninstall uses the same classification and
re-checks each entry immediately before unlinking it, so it only reclaims files that still belong to the environment:
links that resolve into it, dangling links that name it, and copies proven by their shebang, bytes, or the absence of
symlinks on the filesystem. An entry repointed to another environment, a file replaced by hand, or a copy another
environment claims is left in place.
