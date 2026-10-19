# ChatGPT Hub (Rust) — staging / intégration VPS Étude

## État exact

Cette branche adapte **mcp-proxy 0.6.0**, déjà entièrement en Rust (MIT/Apache-2.0). Elle **n'est pas déployée**. Elle contient une garde supplémentaire appliquée automatiquement **uniquement lorsque `proxy.name = "chatgpt-hub"`**, un modèle de configuration et des tests unitaires. La connexion ChatGPT Web n'a pas encore été éprouvée. Aucun MCP existant n'est modifié.

Le but est d'enregistrer **un seul endpoint stable dans ChatGPT**, tandis que les MCP derrière cette façade sont ajoutés au registre, sans enregistrer un nouveau connecteur ChatGPT. Le proxy recherche les outils par BM25 (`proxy__search_tools`), renvoie leurs schémas (`proxy__get_tool`) et route les appels (`proxy__call_tool`). Leur disponibilité et les permissions restent vérifiées à l'exécution par le proxy et les gateways en aval.

## Sécurité (première itération)

- Seulement des outils **explicitement allowlistés**, sans glob ni regex ; `read_only_only=true` et `hide_destructive=true` ajoutent une défense, sans remplacer les listes explicites.
- La garde Rust rejette un listener autre que `127.0.0.1`, les backends hors HTTP, l'auth absente, le `forward_auth`, les configurations `tool_exposure` directes, les composites, les canarys, le mirroring et le failover. Les permissions au niveau de l'upstream restent obligatoires : **une annotation readOnlyHint n'est pas une preuve**.
- JWT/OAuth entrant : vérifier signature, issuer, **audience égale à l'URL publique exacte de la ressource MCP**, expiration, puis `sub` dans une liste d'une seule identité via `auth.role_mapping.default_deny=true`.
- **Jamais de passthrough** du jeton ChatGPT vers les MCP internes. Chaque passerelle interne dispose de son propre compte/token en lecture seule, renouvelé par son mécanisme autorisé, jamais exposé au modèle ou à Git.
- L'API d'administration n'est pas activée dans l'exemple (pas de `security.admin_token`).
- Aucun outil d'exécution système, de navigateur connecté à un profil personnel, d'agent runner, ou d'écriture ne doit entrer dans la première allowlist.
- Par prudence, **`hot_reload=false` en staging** : le rechargement générique de nouveaux backends n'appliquerait pas à lui seul les invariants supplémentaires du profil ChatGPT. Les changements d'upstream nécessitent un redémarrage contrôlé du service, mais pas de nouvel enregistrement du connecteur ChatGPT. Ne pas activer hot reload avant test d'admission de politique sur chaque révision.

## Intégration avec la stack existante

Les services identifiés historiquement sur VPS Étude sont Vault, GitHub, Tasks, Calendar, Astra et l'orchestrateur. Ils ont leurs propres façades OAuth/politiques et sont conservés. Revalider ports, chemins publics et droits *en live* avant intégration. Ne jamais appeler leurs serveurs internes en contournant leur gateway d'autorisation : notamment le GitHub MCP a sa propre allowlist de permissions.

La configuration `examples/chatgpt-hub-staging.toml` utilise **deux backends factices de démonstration**, sur des ports loopback non présumés existants : ils ne sont **pas** des adresses réelles des gateways. Avant de lancer le proxy, un opérateur doit :
1. Mettre en place l'issuer OAuth compatible ChatGPT, avec RFC 8414, PKCE S256 / enregistrement client accepté, JWKS et tokens pour l'audience publique propre au Hub. Les routes de découverte RFC 9728 et `WWW-Authenticate` doivent être vérifiées par un test E2E ; le moteur upstream documente déjà une implémentation mais la compatibilité effective n'est pas prouvée.
2. Remplacer `example.invalid` et `REPLACE_WITH_VERIFIED_USER_SUB` par des données de **configuration**, pas des secrets Git. Garder un seul `sub` autorisé.
3. Définir les URLs d'upstreams autorisés et les `expose_tools` à partir des sorties `tools/list` vérifiées. Les outils sans annotation fiable de lecture doivent être corrigés ou rester exclus. Garder des identifiants dédiés read-only en aval.
4. Charger les tokens depuis un secret store local protégé : `HUB_VAULT_READ_TOKEN`, `HUB_GITHUB_READ_TOKEN` ; des fichiers secrets 0600 non versionnés peuvent être injectés par systemd. Les valeurs ne doivent jamais figurer dans le Vault documentaire, GitHub, ChatGPT ou les logs.
5. Exposer uniquement le transport MCP distant sous HTTPS via un emplacement nginx dédié, sans modifier les vhosts et gateways déjà actifs, ni UFW/SSH/NetBird. Le binaire upstream écoute sur `/` par défaut ; la réécriture de `/hub/mcp` doit être vérifiée (MCP, metadata OAuth, codes 401). Garder le listener applicatif sur loopback.

La reconnexion OAuth à un fournisseur reste parfois imposée par ce fournisseur. Un hub ne peut pas garantir « aucun login à vie ». Dans ChatGPT Web, les plans et modes supportés peuvent restreindre la connexion de serveurs personnalisés ou les actions : voir https://help.openai.com/en/articles/12584461-connecting-custom-mcp-servers-in-chatgpt . Vérifier depuis le compte réel, ne pas assimiler l'API OpenAI à l'UI ChatGPT.

## Validation et critères de promotion

Aucune promotion en production sans :

- `cargo fmt --all -- --check`
- `cargo test --bin mcp-proxy hub_guard::tests`
- `cargo test --test examples`
- `cargo clippy --all-targets -- -D warnings`
- `cargo test` ciblant discovery, invocation, JWT/OAuth/RBAC, reload, outbound headers
- Tests réels `tools/list` (seulement outils méta), `search_tools` → `get_tool` → `call_tool` sur **deux** backends distincts en lecture ; outil refusé par nom/alias/Unicode/glob => refus et zéro appel upstream.
- Rejet vérifié des identités non autorisées, mauvais issuer/audience, JWT expiré, redirection cross-origin, credentials transmis à un upstream, endpoint d'administration public.
- Test depuis ChatGPT Web : parcours découverte OAuth, login utilisateur, choix du connecteur, puis invocation de deux outils read-only. **Ne jamais inférer** réussite d'un simple 200 HTTP.
- Refaire l'évaluation de sécurité avant d'autoriser **la moindre écriture** : outil typé ou procédure de validation hors modèle et journalisation idempotente ; jamais un `call_tool` universel exposé comme lecture seule.

## Reproductibilité et retour arrière

Créer le serveur hub sur un service, listener, répertoire et emplacement HTTPS **distincts**. Conserver tous les connecteurs individuels tant que l'E2E n'est pas passé. Sauvegarder la configuration, enregistrer l'état Git/CI, tester `nginx -t` avant reload. En cas d'échec, désactiver uniquement la nouvelle route et le nouveau service. Les autres gateways, le pare-feu et NetBird restent intacts.

Ce document est un **guide de staging**, pas une certification de sécurité, pas une preuve de compilation, ni une preuve d'OAuth ChatGPT opérationnel.
