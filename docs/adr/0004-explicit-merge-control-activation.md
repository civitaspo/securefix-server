# Make activation separate from scheduled reconciliation

Creating or reactivating controlled-merges can prevent maintainers from landing fixes.
It requires an explicit full-set dispatch and observable readiness checks for every configured repository.
The server repository is activated last.
Partial activation can be retried after all checks pass again.

Scheduled reconciliation updates only controlled-merges rulesets that already exist and are active.
It never creates or reactivates them.
Removing a repository from tag protection policy leaves its existing tag ruleset in place because deleting that protection would weaken an already deployed boundary.
