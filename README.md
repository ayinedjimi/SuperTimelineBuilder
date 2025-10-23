# 🚀 Super Timeline Builder


**Version:** 3.0
**Partie de:** WinToolsSuite
**Objectif:** Agrégation multi-sources forensics pour création timeline unifiée au format Plaso-compatible

---

## 📋 Description

**Super Timeline Builder** est un outil forensics avancé qui agrège des événements provenant de **multiples sources** pour créer une **timeline unifiée chronologique**. Cet outil est essentiel pour l'analyse forensics Windows, permettant de reconstruire la chronologie complète des activités sur un système compromis.

### Inspiré de log2timeline/Plaso

Format de sortie compatible avec l'écosystème **Plaso** (Python Log2Timeline), permettant l'intégration avec d'autres outils forensics professionnels.

- --


## ✨ Fonctionnalités Principales

### 1. Sources Multiples Supportées

#### Sources Actuelles (v3.0)
1. **MFT (Master File Table)** - Simulation
   - Métadonnées fichiers système
   - Timestamps : Created, Modified, Accessed, MFT Entry Modified

2. **Prefetch Files**
   - Parsing `C:\Windows\Prefetch\*.pf`
   - Historique d'exécution applications
   - Timestamps : Dernière exécution

3. **Event Logs**
   - Security, System, Application
   - IDs événements critiques
   - Timestamps : Création événement (UTC)

4. **Registry LastWrite Times**
   - Clés Run (persistence)
   - Modification récentes
   - Timestamps : LastWriteTime

#### Sources Futures (extensions possibles)
- USN Journal complet
- Shimcache (AppCompatCache)
- Amcache
- SRUM (System Resource Usage Monitor)
- Jump Lists
- Recycle Bin ($I files)

### 2. Normalisation et Tri

- **Tous timestamps convertis en UTC**
- **Tri chronologique global** après agrégation
- **Format ISO8601** : `2025-10-20T14:30:45.123Z`

### 3. Format Sortie Plaso-Compatible

#### Structure CSV
```csv
timestamp,source,type,user,host,short,full
```

#### Colonnes
- **timestamp** : ISO8601 UTC
- **source** : MFT, Prefetch, EventLog:Security, Registry
- **type** : FileCreated, Executed, EventID:4624, KeyModified
- **user** : SID ou nom utilisateur
- **host** : Nom machine (localhost par défaut)
- **short** : Description courte (filename, event provider)
- **full** : Détails complets

### 4. Interface Graphique

#### ListView 7 Colonnes
- **Timestamp (UTC)** : ISO8601
- **Source** : Origine événement
- **Type** : Nature événement
- **Description** : Résumé
- **User** : Utilisateur associé
- **Host** : Machine
- **Détails** : Informations complètes

#### Boutons
- **Ajouter Source** : (Réservé future extension)
- **Builder Timeline** : Lance agrégation (threading)
- **Filtrer Dates** : (Future - utiliser Excel pour l'instant)
- **Exporter Plaso CSV** : Sauvegarde timeline complète

- --


## Architecture Technique

### Technologies

- **Langage** : C++ moderne (C++17)
- **APIs Windows** :
  - `wevtapi.lib` : Event Logs (EvtQuery, EvtRender)
  - `advapi32.lib` : Registre (RegQueryInfoKey)
  - FindFirstFile/FindNextFile : Énumération fichiers

### Algorithme de Construction

```
1. Initialiser vecteur événements vide
2. Pour chaque source:
   a. Parser source spécifique
   b. Extraire timestamps (convertir en FILETIME)
   c. Créer TimelineEvent
   d. Ajouter au vecteur global
3. Trier vecteur par timestamp (std::sort)
4. Afficher dans ListView (limiter 5000 UI)
5. Export CSV complet (tous événements)
```

### Threading

- **Parsing parallèle** : Chaque source dans thread séparé (future)
- **UI responsive** : Fenêtre principale non bloquée
- **Progress reporting** : Status temps réel

- --


## Compilation

### Prérequis

- Windows SDK 10.0+
- Visual Studio 2019/2022 (MSVC)
- C++17 minimum

### Build Automatique

```batch
go.bat
```

### Build Manuelle

```batch
cl.exe /W4 /EHsc /O2 /std:c++17 /D_UNICODE /DUNICODE ^
    /Fe:SuperTimelineBuilder.exe SuperTimelineBuilder.cpp ^
    /link comctl32.lib wevtapi.lib advapi32.lib ^
          user32.lib gdi32.lib comdlg32.lib /SUBSYSTEM:WINDOWS
```

- --


## 🚀 Utilisation

### Lancement

```batch
REM Recommandé en administrateur (Event Logs)
SuperTimelineBuilder.exe
```

### Workflow Forensics

#### 1. Construction Timeline
```
Cliquer "Builder Timeline"
→ Parsing sources séquentiellement
→ Affichage temps réel progression
→ Tri chronologique automatique
→ Affichage dans ListView (max 5000)
```

#### 2. Analyse Visuelle
- **Scroll chronologique** : Identifier activités suspectes
- **Filtrer par source** : Focus sur Prefetch (exécutions)
- **Filtrer par user** : Tracer actions utilisateur spécifique

#### 3. Export pour Analyse Avancée
```
Cliquer "Exporter Plaso CSV"
→ Sauvegarder timeline complète
→ Ouvrir dans Excel/LibreOffice
→ Utiliser filtres avancés, graphiques temporels
```

#### 4. Corrélation avec Autres Outils
```
Importer CSV dans:
- Plaso/log2timeline (analyse Python)
- Timesketch (Google timeline analysis)
- Excel avec Power Query
- Tableau/PowerBI pour visualisation
```

- --


## 💡 Exemples de Scénarios Forensics

### Cas 1 : Investigation Malware Execution

**Timeline extrait** :
```
2025-10-20T08:15:23.456Z | Prefetch | Executed | malware.exe | ...
2025-10-20T08:15:24.123Z | EventLog:Security | EventID:4688 | Process Created: malware.exe
2025-10-20T08:15:25.789Z | Registry | KeyModified | HKCU\...\Run | ...
2025-10-20T08:16:01.234Z | EventLog:Security | EventID:3 | Network connection to evil.com
```

**Conclusion** : Malware exécuté, établit persistence registry, puis connexion réseau.

### Cas 2 : Insider Threat - Exfiltration Données

**Timeline extrait** :
```
2025-10-20T14:30:00.000Z | MFT | FileCreated | sensitive_data.zip | User: alice
2025-10-20T14:30:15.456Z | Prefetch | Executed | winrar.exe | ...
2025-10-20T14:31:00.123Z | EventLog:Security | EventID:4663 | Object Access: sensitive_data.zip
2025-10-20T14:32:00.789Z | MFT | FileDeleted | sensitive_data.zip | ...
```

**Conclusion** : Utilisateur alice crée archive, y accède, puis supprime (exfiltration probable).

- --


# 🚀 Si export depuis SuperTimelineBuilder

## Format Plaso CSV Détaillé

### Exemple Complet

```csv
timestamp,source,type,user,host,short,full
2025-10-20T08:15:23.456Z,Prefetch,Executed,(various),localhost,MALWARE.EXE-12345678.pf,Application executed: MALWARE.EXE-12345678.pf
2025-10-20T08:15:24.123Z,EventLog:Security,EventID:4688,S-1-5-21-...,localhost,Microsoft-Windows-Security-Auditing,Process Created: malware.exe
2025-10-20T08:15:25.789Z,Registry,KeyModified,(system),localhost,HKCU\Software\...\Run,Registry key last modified: HKCU\Software\Microsoft\Windows\CurrentVersion\Run
```

### Import dans Plaso

```bash
psort.py -o l2tcsv super_timeline.csv -w timeline_analyzed.csv
```

- --


## Limitations et Améliorations

### Limitations Actuelles

- **MFT Parsing** : Simulation uniquement (pas de lecture $MFT directe)
- **USN Journal** : Non implémenté
- **Event Logs** : Limité à 1000 événements par log (performance)
- **Filtrage** : Pas de filtrage date range intégré (utiliser Excel)

### Améliorations Futures

1. **MFT Parser complet** : Lecture $MFT raw via NTFS
2. **USN Journal** : Parsing complet avec FSCTL_QUERY_USN_JOURNAL
3. **Shimcache/Amcache** : Parsing registry AppCompatCache
4. **SRUM** : System Resource Usage Monitor
5. **Filtrage date range** : UI intégrée
6. **Export formats** : JSON, XML, SQLite

- --


# 🚀 Conversion timeline

# 🚀 Analyse avec psort

# 🚀 Import dans Timesketch (Google)

## Intégration avec Outils Tiers

### Plaso/log2timeline

```bash
log2timeline.py timeline.plaso super_timeline.csv

psort.py -o l2tcsv timeline.plaso -w analyzed.csv
```

### Timesketch

```bash
timesketch importer --timeline_name "Investigation" super_timeline.csv
```

### Excel/LibreOffice

1. Ouvrir CSV
2. Appliquer filtres automatiques
3. Créer graphiques temporels (scatter plot)
4. Pivot tables pour analyse par source/user

- --


## Références Forensics

### Standards Timeline

- **DFIR Timeline** : Format standardisé communauté forensics
- **Plaso Project** : [https://github.com/log2timeline/plaso](https://github.com/log2timeline/plaso)
- **Timesketch** : [https://github.com/google/timesketch](https://github.com/google/timesketch)

### Documentation Microsoft

- [Event Logging (Windows)](https://docs.microsoft.com/en-us/windows/win32/wes/windows-event-log)
- [NTFS MFT](https://docs.microsoft.com/en-us/windows/win32/fileio/master-file-table)
- [Prefetch](https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-vista/cc765944(v=ws.10))

- --


## 🔧 Troubleshooting

### Erreur "Access Denied" Event Logs

**Cause** : Droits insuffisants pour Security log

**Solution** :
```batch
runas /user:Administrator SuperTimelineBuilder.exe
```

### Timeline vide ou incomplète

**Cause** : Sources non accessibles (permissions)

**Solution** : Vérifier accès à :
- `C:\Windows\Prefetch` (peut nécessiter admin)
- Event Logs (Security nécessite admin)
- Registry Run keys (HKLM nécessite lecture)

- --


## 👤 Auteur et Licence

**Développé par** : WinToolsSuite Team
**Version** : 3.0
**Licence** : Usage libre pour analyse forensics et sécurité

- --


## Support

Pour bugs ou questions :
- Consulter documentation Plaso/log2timeline
- Vérifier accès sources forensics (permissions)

**Note** : Outil destiné à professionnels forensics et incident response. Connaissances timeline analysis requises.


---

<div align="center">

**⭐ Si ce projet vous plaît, n'oubliez pas de lui donner une étoile ! ⭐**

</div>