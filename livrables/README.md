# TP — DAST avec OWASP ZAP : analyser une application web vulnérable

Entreprise fil rouge : NOVA SERVICES
Application cible : TIWAP (application volontairement vulnérable, utilisée uniquement comme cible de laboratoire)
Outils : Docker Compose, OWASP ZAP (image `ghcr.io/zaproxy/zaproxy:stable`, Baseline Scan), GitHub Actions

---

## 1. SAST et DAST

Dans le TP précédent, SonarQube analysait le **code source** de TIWAP sans l'exécuter (SAST). Ici, ZAP analyse l'application **en fonctionnement** : il explore les pages comme un navigateur, envoie des requêtes HTTP et examine les réponses (DAST).

Le Baseline Scan que j'ai utilisé combine une exploration de l'application (spider) et une **analyse passive** des échanges observés. Il n'envoie pas de requêtes d'attaque.

---

## 2. Déploiement du laboratoire

J'ai cloné TIWAP dans un dossier séparé (`tp-zap-nova`), distinct de celui du TP SonarQube qui contient ma correction de l'injection SQL. L'application analysée ici est donc la version d'origine.

### Modifications du fichier Compose

| Modification | Raison |
|---|---|
| `app` : port `"5000:5000"` remplacé par `"127.0.0.1:5000:5000"` | L'application n'est accessible que depuis ma machine, pas depuis le réseau local |
| `db` : section `ports` supprimée | MongoDB n'est plus exposé sur l'hôte. L'application le joint par le nom de service `db` sur le réseau Docker |
| Ajout du service `zap` | Conteneur ZAP en attente (`sleep infinity`), rapports écrits dans `./reports` |
| Suppression de `version: "2"` | Attribut obsolète, signalé par Docker Compose |

Je n'ai pas modifié les identifiants MongoDB fournis par TIWAP, dont l'application dépend. Le diff complet est dans `compose_modifications.diff`.

J'ai ajouté `reports/` au `.gitignore` : les rapports ne sont pas versionnés dans le dépôt.

### Démarrage et vérification

Les journaux de l'application montrent qu'elle tourne en **HTTPS** avec un certificat auto-signé (`Running on https://...:5000/`). J'ai donc ouvert `https://localhost:5000`, accepté l'avertissement du navigateur et me suis connecté avec `admin` / `admin` (voir capture).

Les mêmes journaux affichent `Debug mode: on`, `Debugger is active!` et `Running on all addresses`.

**Question 1 — Pourquoi démarrer et vérifier l'application avant de lancer ZAP ?**
ZAP analyse ce qu'il reçoit. Si l'application n'est pas démarrée ou renvoie des erreurs, le scan ne trouve rien ou analyse des pages d'erreur, et le rapport n'a pas de valeur. Vérifier avant permet aussi de connaître la bonne URL. Dans mon cas, j'ai découvert que l'application était en HTTPS et non en HTTP comme indiqué dans le sujet.

**Question 2 — Pourquoi ne pas exposer le port MongoDB pendant le TP ?**
La base n'a pas besoin d'être joignable depuis l'hôte : seule l'application l'utilise, par le réseau Docker. Les identifiants de TIWAP sont triviaux (`username` / `password`). Exposer le port 27017 permettrait à toute personne sur le même réseau d'accéder directement aux données. Moins de ports ouverts, c'est moins de surface d'attaque.

---

## 3. Le scan DAST

### Vérification du réseau

Depuis le conteneur ZAP, l'application est joignable par le nom du service :

```bash
docker compose exec zap curl -sk -o /dev/null -w "%{http_code}\n" https://app:5000
```

### Commande de scan

```bash
MSYS_NO_PATHCONV=1 docker compose exec zap zap-baseline.py -t https://app:5000 -m 2 -r zap-report.html -J zap-report.json
```

J'ai adapté la commande du sujet sur trois points :

| Adaptation | Raison |
|---|---|
| Cible `https://app:5000` au lieu de `http://app:5000` | L'application tourne en HTTPS |
| `MSYS_NO_PATHCONV=1` | Sous Git Bash, les chemins commençant par `/` sont convertis en chemins Windows, ce qui casse la commande |
| `-r zap-report.html` au lieu de `/zap/wrk/zap-report.html` | ZAP écrit déjà ses rapports dans `/zap/wrk`, monté sur `./reports` |

### Résultat

```
FAIL-NEW: 0  FAIL-INPROG: 0  WARN-NEW: 15  WARN-INPROG: 0  INFO: 0  IGNORE: 0  PASS: 52
```

15 règles ont produit une alerte, 52 n'ont rien signalé. Le rapport JSON détaille 18 lignes d'alertes : la règle 90004 apparaît pour trois en-têtes différents et la règle 10049 pour deux types de contenu, ce qui fait 15 règles.

`FAIL-NEW: 0` ne signifie pas qu'il n'y a pas de problème grave. Aucune règle n'est configurée pour faire échouer le scan : par défaut, le Baseline Scan classe toutes ses alertes en WARN.

### Liste des alertes (extraite de `zap-report.json`)

| Règle | Risque (confiance) | Alerte | Occurrences |
|---|---|---|---|
| 10202 | Medium (Low) | Absence of Anti-CSRF Tokens | 1 |
| 10038 | Medium (High) | Content Security Policy (CSP) Header Not Set | 5 |
| 10020 | Medium (Medium) | Missing Anti-clickjacking Header | 1 |
| 10099 | Medium (Medium) | Source Code Disclosure - SQL | 1 |
| 90022 | Low (Medium) | Application Error Disclosure | 1 |
| 90004 | Low (Medium) | Cross-Origin-Embedder / Opener / Resource-Policy Header Missing | 1 + 1 + 4 |
| 10063 | Low (Medium) | Permissions Policy Header Not Set | 5 |
| 10036 | Low (High) | Server Leaks Version Information via "Server" Header | 5 |
| 10035 | Low (High) | Strict-Transport-Security Header Not Set | 5 |
| 10021 | Low (Medium) | X-Content-Type-Options Header Missing | 4 |
| 10111 | Informational (High) | Authentication Request Identified | 1 |
| 10027 | Informational (Medium) | Information Disclosure - Suspicious Comments | 2 |
| 10109 | Informational (Medium) | Modern Web Application | 2 |
| 10049 | Informational (Medium) | Non-Storable / Storable and Cacheable Content | 1 + 5 |
| 10015 | Informational (Low) | Re-examine Cache-control Directives | 2 |

---

## 4. Tableau de qualification

| Alerte constatée | Risque indiqué | Vérification réalisée | Résultat | Action envisagée |
|---|---|---|---|---|
| 90022 Application Error Disclosure + 10099 Source Code Disclosure - SQL + 10027 Suspicious Comments (`POST /login`) | Low et Medium | Lecture des preuves du rapport, puis reproduction manuelle avec `curl -sk -X POST https://localhost:5000/login` | **Confirmé.** Code 500, page de traceback du débogueur Werkzeug renvoyée (`__debugger__` présent), code source Python visible, dont la requête `SELECT username, password FROM users WHERE username = ?` | Corriger : désactiver le mode debug, page d'erreur générique |
| 10202 Absence of Anti-CSRF Tokens | Medium (confiance Low) | Croisement avec SonarQube : règle S4502 « disabling CSRF protection » sur `app.py` L28 | **Probable, à confirmer** par lecture de `app.py` L28. Deux outils indépendants pointent le même défaut | Examiner le code puis réactiver la protection CSRF |
| 10038 CSP, 10020 Anti-clickjacking, 10021 X-Content-Type-Options, 10035 HSTS | Medium et Low | `curl -skI https://localhost:5000/login` | **Confirmé.** Aucun de ces en-têtes n'est présent dans la réponse | Corriger : ajouter les en-têtes (application ou reverse proxy) |
| 10036 Server Leaks Version Information | Low | Même requête `curl` | **Confirmé.** `Server: Werkzeug/2.0.3 Python/3.6.15`. Python 3.6 n'est plus maintenu depuis fin 2021 | Corriger : masquer l'en-tête, mettre à jour Python et Werkzeug |
| 10049, 10015, 10109, 10111 | Informational | Lecture des descriptions | Observations sans risque direct dans ce contexte | Documenter |

### Analyse de l'alerte « Source Code Disclosure - SQL »

Le nom de l'alerte peut faire penser à une injection SQL, mais ce n'en est pas une. ZAP a envoyé un formulaire `POST /login` qui a provoqué une erreur serveur. Comme le mode debug est actif, Flask a renvoyé la page de traceback de Werkzeug au lieu d'une page d'erreur générique. Cette page affiche le code source autour de l'erreur, et ZAP a reconnu une requête SQL dans ce code.

La requête exposée est d'ailleurs paramétrée (`= ?`) : elle n'est pas injectable. Le problème est une **divulgation d'informations** : n'importe quel visiteur, sans authentification, peut voir le code de l'application, les noms de la table `users` et de ses colonnes, et accéder à la console interactive du débogueur.

C'est la même cause que l'alerte S4507 (mode debug activé) relevée par SonarQube dans le TP précédent, cette fois observée de l'extérieur.

### Pourquoi une alerte doit être vérifiée

Une alerte ZAP est un constat technique, pas une vulnérabilité confirmée. Mon scan en donne trois exemples :

- **Le nom d'une alerte peut induire en erreur.** « Source Code Disclosure - SQL » n'est pas une injection SQL, mais une fuite de code liée au mode debug. Sans lecture de la preuve, j'aurais pu mal la classer.
- **La confiance est parfois faible.** L'alerte CSRF a une confiance « Low ». ZAP n'a pas trouvé de jeton dans un formulaire, mais ne sait pas si une autre protection existe. Il faut lire le code pour conclure.
- **Le niveau de risque de l'outil n'est pas une priorité métier.** La divulgation d'erreur (90022) est classée « Low » par ZAP, alors qu'elle donne accès au code et à la console du débogueur. Inversement, l'absence d'en-tête CSP est classée « Medium », mais son impact dépend de la présence de failles XSS exploitables.

La vérification consiste à reproduire le constat (comme avec `curl`), à examiner la réponse et le contexte, puis à décider : corriger, accepter, ou classer comme faux positif.

---

## 5. Lien avec l'injection SQL étudiée avec SonarQube

ZAP n'a **pas détecté d'injection SQL**.

Le Baseline Scan est passif : il observe les réponses aux requêtes normales, mais n'envoie jamais de saisie piégée comme `' OR '1'='1`. Il ne peut donc pas constater qu'une requête est injectable. Le scan n'était pas authentifié non plus : la route `/sql-injection` étudiée au TP précédent demande d'être connecté (`@is_logged`), et ZAP ne l'a probablement pas atteinte.

| Outil | Injection SQL de `sqli_low()` | Raison |
|---|---|---|
| SonarQube Community (SAST) | Non détectée | Analyse de flux (taint analysis) absente de l'édition Community |
| ZAP Baseline (DAST) | Non détectée | Scan passif, sans authentification |
| Revue manuelle du code (TP 2) | **Détectée** | Lecture du chemin `request.form` → requête → `execute()` |

Croisement des résultats SAST et DAST sur les autres anomalies :

| Anomalie | SonarQube | ZAP | Conclusion |
|---|---|---|---|
| Mode debug activé | S4507, `app.py` L913 | 90022 + 10099 + 10027 (traceback exposé) | Confirmé par les deux approches, impact réel démontré |
| Écoute sur toutes les interfaces | S8392, `app.py` L913 | Non visible (port limité à 127.0.0.1 par mon Compose) | Confirmé par les journaux, risque réduit par la configuration du labo |
| Protection CSRF désactivée | S4502, `app.py` L28 | 10202 | Deux outils indépendants pointent le même défaut |
| Clé secrète Flask en dur | S6779, `app.py` L29 | Non visible | Seul le SAST peut voir ce qui est dans le code et pas dans les réponses |
| En-têtes de sécurité absents | Non détecté | 10038, 10020, 10021, 10035 | Seul le DAST voit la configuration HTTP réelle |
| Version serveur divulguée | Non détecté | 10036 | Seul le DAST voit les en-têtes renvoyés |

Les deux approches sont complémentaires : le SAST voit le code que le DAST n'atteint pas, et le DAST voit le comportement réel que le code seul ne montre pas.

---

## 6. Fiches de traitement — NOVA SERVICES

Je considère ces résultats comme s'ils concernaient une application interne de NOVA SERVICES de gestion des clients.

### Fiche 1 — Mode debug exposant le code source

| Champ | Contenu |
|---|---|
| Référence | ZAP 90022, 10099, 10027 (SonarQube S4507) |
| Application | TIWAP, utilisée comme cible de laboratoire |
| Actif métier analogue | Application de gestion des clients |
| Impact | Divulgation du code source et de la structure de la base. Accès à la console du débogueur Werkzeug, qui permet d'exécuter du code Python sur le serveur |
| Priorité | **Élevée** (critique si l'application est exposée sur Internet) |
| Justification | Exploitable sans authentification par une simple requête. Impact potentiel sur la confidentialité, l'intégrité et la disponibilité. Aucune mesure compensatoire. Correction simple et rapide |
| Responsable | Équipe de développement, validation par l'exploitation |
| Échéance | 48 heures (18 octobre 2026) |
| Action | Désactiver le mode debug hors développement, ajouter un gestionnaire d'erreurs qui renvoie une page générique, ne plus écouter sur toutes les interfaces |
| Vérification | `curl -sk -X POST .../login` ne doit plus contenir `__debugger__`, nouveau scan ZAP sans les alertes 90022 et 10099 |
| Statut | Ouvert |

### Fiche 2 — Protection CSRF absente

| Champ | Contenu |
|---|---|
| Référence | ZAP 10202 (SonarQube S4502) |
| Application | TIWAP, utilisée comme cible de laboratoire |
| Actif métier analogue | Formulaires de modification de données clients |
| Impact | Un site tiers peut faire exécuter une action à un utilisateur connecté à son insu (modification de données, changement de mot de passe) |
| Priorité | **Moyenne** |
| Justification | Nécessite qu'un utilisateur connecté visite une page piégée. Signalé par deux outils, mais la confiance ZAP est faible et le code n'a pas encore été examiné |
| Responsable | Équipe de développement |
| Échéance | 30 jours (15 novembre 2026) |
| Action | Analyse complémentaire de `app.py` L28, puis réactivation de la protection CSRF sur tous les formulaires |
| Vérification | Revue du code, test d'un envoi de formulaire sans jeton (doit être refusé), nouveau scan ZAP |
| Statut | En cours d'analyse |

### Fiche 3 — En-têtes de sécurité absents et version serveur divulguée

| Champ | Contenu |
|---|---|
| Référence | ZAP 10038, 10020, 10021, 10035, 10036 |
| Application | TIWAP, utilisée comme cible de laboratoire |
| Actif métier analogue | Toutes les applications web de NOVA SERVICES |
| Impact | Pas de défense en profondeur contre le XSS (CSP), le clickjacking et l'interprétation erronée des contenus. La version exacte du serveur (Python 3.6.15, non maintenu) aide un attaquant à cibler des failles connues |
| Priorité | **Moyenne** |
| Justification | Pas exploitable seul, mais aggrave d'autres failles. Correction peu coûteuse, et applicable à toutes les applications d'un coup via un reverse proxy |
| Responsable | Équipe d'exploitation (reverse proxy), équipe de développement (mise à jour de Python) |
| Échéance | 30 jours (15 novembre 2026) |
| Action | Ajouter les en-têtes `Content-Security-Policy`, `X-Frame-Options`, `X-Content-Type-Options` et `Strict-Transport-Security`. Masquer l'en-tête `Server`. Planifier la mise à jour de Python et Werkzeug |
| Vérification | `curl -skI` doit afficher les en-têtes, nouveau scan ZAP sans ces alertes |
| Statut | Ouvert |

---

## 7. Intégration continue

Le sujet propose GitLab CI ou GitHub Actions. J'ai utilisé GitHub Actions, dans un dépôt privé (`izac07/tiwap-zap-lab`) pour ne pas publier l'application vulnérable. Le workflow est dans `dast-zap.yml`.

Le job `dast_zap` :
1. démarre TIWAP (`app`, `db`) et ZAP avec Docker Compose sur le runner GitHub ;
2. attend que l'application réponde, en testant `https://app:5000` depuis le conteneur ZAP ;
3. lance le Baseline Scan ;
4. publie le dossier `reports/` comme artefact `zap-reports`, même en cas d'échec (`if: always()`) ;
5. arrête et supprime les services.

Choix de configuration :
- `-I` : les alertes WARN ne font pas échouer le pipeline. Le scan sert ici à produire et conserver un rapport. Pour bloquer une fusion, il faudrait un fichier de règles qui passe certaines alertes en FAIL.
- `chmod 777 reports` : ZAP s'exécute avec un utilisateur non-root et doit pouvoir écrire ses rapports.

Résultat : pipeline réussi (1 min 54 s), un artefact publié, et **le même résultat qu'en local** (`WARN-NEW: 15`, `PASS: 52`). Le scan est reproductible sur une machine neuve. Voir les captures du pipeline et des artefacts.

GitHub signale deux avertissements sans lien avec la sécurité de TIWAP : les actions `checkout@v4` et `upload-artifact@v4` utilisent Node.js 20, qui est déprécié, et le label `ubuntu-latest` va changer de version. Pour un pipeline plus stable, il faudrait mettre à jour les actions et fixer la version d'Ubuntu.

Limite : le rapport est conservé comme simple artefact. Il n'est pas intégré aux tableaux de vulnérabilités de la plateforme, ce qui demanderait un format de rapport spécifique.

---

## 8. Mini-tableau de bord

Valeurs relevées sur TIWAP au 16 octobre 2026 :

| Indicateur | Valeur |
|---|---|
| Alertes DAST ouvertes | 15 règles : 4 Medium, 6 Low, 5 Informational |
| Vulnérabilités confirmées manuellement | 2 (mode debug exposé, en-têtes absents et version divulguée) |
| Alertes en cours d'analyse | 1 (CSRF) |
| Applications couvertes par un scan DAST automatisé | 1 (TIWAP, via GitHub Actions) |

### Indicateurs proposés

| Indicateur | Définition et calcul | Source | Fréquence | Responsable | Décision |
|---|---|---|---|---|---|
| Vulnérabilités confirmées ouvertes par priorité | Nombre de vulnérabilités qualifiées et non corrigées, par niveau de priorité | Fiches de traitement / outil de ticketing | Hebdomadaire | Responsable sécurité | Répartir l'effort de correction, bloquer une mise en production si une vulnérabilité critique est ouverte |
| Vulnérabilités prioritaires en retard | Nombre de vulnérabilités critiques ou élevées dont l'échéance est dépassée | Fiches de traitement | Hebdomadaire | Tech lead | Escalader au management et réaffecter des ressources |
| Délai médian de correction | Médiane du temps entre la qualification et la correction vérifiée | Dates des fiches de traitement | Mensuelle | Responsable sécurité | Ajuster les échéances ou les moyens si l'objectif n'est pas tenu |
| Pourcentage de corrections vérifiées par un nouveau scan | Corrections confirmées par un scan ZAP ou un test / corrections déclarées | Fiches de traitement + artefacts de CI | Mensuelle | Tech lead | Refuser la clôture d'une fiche sans preuve de vérification |
| Pourcentage d'applications critiques couvertes par le DAST | Applications critiques avec un scan ZAP automatisé / applications critiques du périmètre | Inventaire applicatif + pipelines CI | Mensuelle | Responsable sécurité | Ajouter le scan aux pipelines des applications non couvertes |
| Taux d'échec technique des scans | Scans en erreur (application injoignable, timeout) / scans lancés | Historique des pipelines | Mensuelle | Équipe d'exploitation | Corriger la configuration des pipelines, car un scan en échec ne protège rien |

Le nombre d'alertes ne suffit pas à mesurer le niveau de sécurité. Mon scan n'a trouvé aucune injection SQL alors que l'application en contient. À l'inverse, activer un scan authentifié ou actif augmenterait le nombre d'alertes sans que la sécurité ait changé.

---

## 9. Conclusion sur les limites du DAST et sa complémentarité avec le SAST

Le scan ZAP a apporté ce que l'analyse du code ne pouvait pas donner : la preuve que le mode debug expose réellement le code source à n'importe quel visiteur, l'absence effective des en-têtes de sécurité, et la version exacte du serveur. Ce sont des constats sur le comportement réel de l'application.

Ses limites sont aussi apparues clairement. Le Baseline Scan est passif et non authentifié : il n'a pas détecté l'injection SQL, ni rien de ce qui se trouve derrière la connexion. Il ne voit pas non plus ce qui reste dans le code sans apparaître dans les réponses, comme la clé secrète Flask écrite en dur. Enfin, ses alertes doivent être vérifiées : le nom « Source Code Disclosure - SQL » cachait une fuite de code liée au mode debug, et non une injection.

Sur TIWAP, aucune des trois approches n'a tout trouvé seule. SonarQube a vu le code, ZAP a vu le comportement, et la revue manuelle a trouvé l'injection SQL que les deux outils ont manquée. NOVA SERVICES doit donc utiliser ces outils comme des sources d'information pour son pilotage, et non comme une garantie de sécurité : leurs résultats doivent être qualifiés, transformés en corrections suivies, puis vérifiés par un nouveau scan ou un test.

---

## 10. Questions de compréhension

**1. Quelle est la différence entre SAST et DAST ?**
Le SAST analyse le code source sans l'exécuter. Il couvre tout le code et voit des défauts invisibles de l'extérieur, comme un secret en dur. Le DAST analyse l'application en fonctionnement, par ses requêtes et ses réponses HTTP. Il voit la configuration réelle et le comportement effectif, mais seulement sur les parties qu'il atteint.

**2. Pourquoi ZAP doit-il accéder à une application en fonctionnement ?**
ZAP ne lit pas le code : il envoie des requêtes et analyse les réponses. Sans application démarrée, il n'a rien à observer.

**3. Pourquoi l'adresse cible est-elle `http://app:5000` depuis le conteneur ?**
Dans le conteneur ZAP, `localhost` désigne ZAP lui-même. Le nom du service `app` est résolu par le DNS du réseau Docker vers le conteneur de l'application. Dans mon cas, la cible était `https://app:5000`, car TIWAP tourne en HTTPS.

**4. Quelle est la différence entre un scan passif et un scan actif ?**
Le scan passif observe les échanges normaux sans rien modifier. Le scan actif envoie des requêtes conçues pour tester des vulnérabilités (injections, XSS…). Il peut modifier des données ou perturber l'application, et doit être réservé à un environnement autorisé et préparé.

**5. Pourquoi le Baseline Scan ne garantit-il pas la détection d'une injection SQL ?**
Il est passif : il n'envoie jamais de saisie piégée, donc il ne peut pas constater qu'une requête est injectable. Il n'explore en plus que ce qui est accessible sans authentification. Sur TIWAP, il n'a effectivement détecté aucune injection SQL.

**6. Quelle différence existe-t-il entre une alerte et une vulnérabilité confirmée ?**
Une alerte est un constat de l'outil, qui peut être incomplet ou trompeur. Une vulnérabilité confirmée a été reproduite et son impact a été évalué dans le contexte. Par exemple, l'alerte 10099 n'était pas une injection SQL, mais une fuite de code que j'ai confirmée avec `curl`.

**7. Comment prioriser une alerte concernant une application métier critique ?**
En évaluant la criticité des données, l'exposition réseau, l'impact sur la confidentialité, l'intégrité et la disponibilité, la facilité d'exploitation, les mesures compensatoires existantes, et le coût de la correction. Le niveau de risque de ZAP est un point de départ, pas la priorité finale.

**8. Pourquoi conserver les rapports de scan dans la CI ?**
Chaque rapport est lié à un commit précis : il sert de preuve de ce qui a été analysé, de point de comparaison entre deux versions, et de preuve qu'une correction a bien fait disparaître une alerte. Les conserver comme artefacts évite de les versionner dans le dépôt.

**9. Comment éviter de publier accidentellement une application vulnérable ?**
En limitant les ports à `127.0.0.1`, en n'exposant pas la base de données, en utilisant un environnement isolé et des runners de CI éphémères, en gardant le dépôt privé, et en arrêtant les services après chaque scan (`docker compose down`).

**10. Quels indicateurs permettent de mesurer l'efficacité du processus de correction ?**
Le nombre de vulnérabilités confirmées ouvertes par priorité, le nombre de vulnérabilités prioritaires en retard, le délai médian de correction, le pourcentage de corrections vérifiées par un nouveau scan, et la couverture des applications critiques par le DAST.

---

## 11. Fichiers fournis

| Fichier | Contenu |
|---|---|
| `docker-compose.yml` | Compose modifié pour le laboratoire |
| `compose_modifications.diff` | Différences avec le Compose d'origine |
| `dast-zap.yml` | Workflow GitHub Actions |
| `zap-report.html` / `zap-report.json` | Rapports du Baseline Scan |
| `alertes.txt` | Liste des alertes extraite du rapport JSON |
| Captures | TIWAP fonctionnel, pipeline GitHub Actions, artefacts |

Aucun secret réel ne figure dans ces fichiers. La page de traceback récupérée pendant la vérification n'est pas incluse, car elle contient la valeur secrète du débogueur Werkzeug.
