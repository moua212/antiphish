# 🛡️ AntiPhish — Détecteur de Sites de Phishing par IA

[![Docker](https://img.shields.io/badge/Docker-Required-blue?logo=docker)](https://www.docker.com/products/docker-desktop)
[![FastAPI](https://img.shields.io/badge/FastAPI-REST%20API-green?logo=fastapi)](https://fastapi.tiangolo.com/)
[![Python](https://img.shields.io/badge/Python-3.10+-yellow?logo=python)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-red.svg)](LICENSE)

> **AntiPhish** est une API intelligente de détection de phishing basée sur le Machine Learning. Elle analyse les caractéristiques structurelles d'une URL et prédit en temps réel si un site est **légitime** ou **malveillant**, avec un score de probabilité.

---

## 📋 Table des matières

- [Prérequis](#-prérequis)
- [Installation](#-installation)
- [Lancement](#-lancement)
- [Utilisation de l'API](#-utilisation-de-lapi)
- [Exemple de requête](#-exemple-de-requête)
- [Interprétation des résultats](#-interprétation-des-résultats)
- [Structure du projet](#-structure-du-projet)
- [Licence](#-licence)

---

## ✅ Prérequis

Avant de commencer, assurez-vous que les éléments suivants sont installés sur votre machine :

| Outil | Lien de téléchargement |
|-------|------------------------|
| **Git** | https://git-scm.com/downloads |
| **Docker Desktop** | https://www.docker.com/products/docker-desktop |

> ⚠️ **Important :** Docker Desktop doit être **démarré et en cours d'exécution** avant de lancer le projet.

---

## 📥 Installation

### 1. Cloner le dépôt GitHub

Ouvrez un terminal et exécutez la commande suivante :

```bash
git clone https://github.com/votre-username/AntiPhish.git
```

> 💡 Remplacez `votre-utilisateur` par votre nom d'utilisateur GitHub réel.

### 2. Se déplacer dans le répertoire du projet

```bash
cd AntiPhish
```

---

## 🚀 Lancement

### 3. Ouvrir Docker Desktop

Assurez-vous que **Docker Desktop est lancé** sur votre machine (l'icône Docker doit apparaître dans la barre des tâches).

### 4. Construire et démarrer les conteneurs

Dans le terminal, à la racine du projet, exécutez :

```bash
docker-compose up -d --build
```

Cette commande va :
- 📦 Télécharger les images nécessaires
- 🔨 Construire le conteneur de l'application
- ▶️ Démarrer l'API en arrière-plan

> ⏳ La première exécution peut prendre quelques minutes selon votre connexion Internet.

### 5. Vérifier que le service est actif

Une fois la commande terminée, ouvrez votre navigateur et accédez à :

```
http://localhost:8000/docs
```

Vous verrez l'interface **Swagger UI** — la documentation interactive de l'API.

---

## 🔌 Utilisation de l'API

L'API expose deux endpoints :

| Méthode | Route | Description |
|---------|-------|-------------|
| `GET` | `/home` | Vérifie que l'API est en ligne |
| `POST` | `/predict` | Analyse une URL et retourne une prédiction |

### Tester via Swagger UI

1. Rendez-vous sur **http://localhost:8000/docs**
2. Cliquez sur `POST /predict`
3. Cliquez sur le bouton **"Try it out"**
4. Collez votre JSON dans le champ **Request body**
5. Cliquez sur **"Execute"**

---

## 📨 Exemple de requête

### Corps de la requête (`Request Body`)

Copiez et collez ce JSON dans le champ de l'API :

```json
{
  "Querylength": 12,
  "domain_token_count": 2,
  "path_token_count": 1,
  "avgdomaintokenlen": 8.2,
  "longdomaintokenlen": 10,
  "avgpathtokenlen": 2.0,
  "tld": 1,
  "charcompvowels": 5,
  "charcompace": 1,
  "ldl_url": 0,
  "URLLength": 45,
  "DomainLength": 20,
  "IsDomainIP": 0,
  "URLSimilarityIndex": 0.5,
  "CharContinuationRate": 0.2,
  "TLDLegitimateProb": 0.8,
  "URLCharProb": 0.7,
  "TLDLength": 3,
  "NoOfSubDomain": 1,
  "HasObfuscation": 0,
  "NoOfObfuscatedChar": 0,
  "ObfuscationRatio": 0.0,
  "NoOfLettersInURL": 30,
  "LetterRatioInURL": 0.66,
  "NoOfDegitsInURL": 2,
  "DegitRatioInURL": 0.04,
  "NoOfEqualsInURL": 0,
  "NoOfQMarkInURL": 0,
  "NoOfAmpersandInURL": 0,
  "NoOfOtherSpecialCharsInURL": 2,
  "SpacialCharRatioInURL": 0.04,
  "IsHTTPS": 1,
  "LineOfCode": 100,
  "LargestLineLength": 50,
  "HasTitle": 1,
  "Title": 1,
  "DomainTitleMatchScore": 0.7,
  "URLTitleMatchScore": 0.6,
  "HasFavicon": 1,
  "Robots": 1,
  "IsResponsive": 1,
  "NoOfURLRedirect": 0,
  "NoOfSelfRedirect": 0,
  "HasDescription": 1,
  "NoOfPopup": 0,
  "NoOfiFrame": 0,
  "HasExternalFormSubmit": 0,
  "HasSocialNet": 0,
  "HasSubmitButton": 1,
  "HasHiddenFields": 0,
  "HasPasswordField": 1,
  "Bank": 0,
  "Pay": 0,
  "Crypto": 0,
  "HasCopyrightInfo": 1,
  "NoOfImage": 5,
  "NoOfCSS": 2,
  "NoOfJS": 3,
  "NoOfSelfRef": 10,
  "NoOfEmptyRef": 0,
  "NoOfExternalRef": 2,
  "SymbolCount_URL": 1,
  "SymbolCount_Domain": 0,
  "SymbolCount_DirectoryName": 1,
  "SymbolCount_FileName": 1,
  "SymbolCount_Extension": 0,
  "SymbolCount_Afterpath": 1,
  "Entropy_URL": 0.7,
  "Entropy_Domain": 0.6,
  "Entropy_DirectoryName": 0.5,
  "Entropy_Filename": 0.4,
  "Entropy_Extension": 0.3,
  "Entropy_Afterpath": 0.2
}
```

### Description des champs

| Champ | Description |
|-------|-------------|
| `Querylength` | Longueur totale de la requête URL |
| `domain_token_count` | Nombre de tokens dans le domaine |
| `path_token_count` | Nombre de tokens dans le chemin |
| `avgdomaintokenlen` | Longueur moyenne des tokens du domaine |
| `longdomaintokenlen` | Longueur du token le plus long dans le domaine |
| `avgpathtokenlen` | Longueur moyenne des tokens du chemin |
| `tld` | Indicateur du type de domaine de premier niveau |
| `charcompvowels` | Nombre de voyelles dans l'URL |
| `charcompace` | Nombre de caractères accentués |
| `ldl_url` | Ratio lettre/chiffre de l'URL |
| `SymbolCount_URL` | Nombre de symboles dans l'URL |
| `SymbolCount_Domain` | Nombre de symboles dans le domaine |
| `Entropy_URL` | Entropie de l'URL (mesure de complexité) |
| `Entropy_Domain` | Entropie du domaine |

---

## 📊 Interprétation des résultats

L'API retourne une réponse JSON avec deux informations :

```json
{
  "prediction": 0,
  "probability": [
    0.8006858825683594,
    0.199314147233963
  ]
}
```

### Signification de `prediction`

| Valeur | Signification |
|--------|---------------|
| `0` | ✅ Site **légitime** |
| `1` | 🚨 Site de **phishing** (malveillant) |

### Signification de `probability`

Le tableau `probability` contient deux valeurs :

| Index | Représente | Exemple |
|-------|-----------|---------|
| `probability[0]` | Probabilité que le site soit **légitime** | `0.80` → 80% légitime |
| `probability[1]` | Probabilité que le site soit **phishing** | `0.20` → 20% phishing |

> 💡 **Dans l'exemple ci-dessus :** le modèle prédit que le site est légitime (`prediction: 0`) avec une confiance de **80%**.

---

## 🗂️ Structure du projet

```
AntiPhish/
├── app/
│   ├── main.py              # Point d'entrée FastAPI
│   ├── model/               # Modèle ML entraîné
│   └── schemas.py           # Schémas de données Pydantic
├── docker-compose.yml       # Configuration Docker Compose
├── Dockerfile               # Image Docker de l'application
├── requirements.txt         # Dépendances Python
└── README.md                # Documentation du projet
```

---

## 🛑 Arrêter le service

Pour arrêter les conteneurs sans supprimer les données :

```bash
docker-compose down
```

Pour arrêter et supprimer complètement les conteneurs et volumes :

```bash
docker-compose down -v
```

---

## 🐛 Résolution de problèmes

| Problème | Solution |
|----------|----------|
| `docker: command not found` | Installez Docker Desktop et redémarrez votre terminal |
| Port `8000` déjà utilisé | Modifiez le port dans `docker-compose.yml` |
| L'API ne répond pas | Vérifiez que Docker Desktop est en cours d'exécution |
| Erreur lors du build | Exécutez `docker-compose down -v` puis relancez |

---

## 📄 Licence

Ce projet est distribué sous licence **MIT**. Voir le fichier [LICENSE](LICENSE) pour plus de détails.

---

<div align="center">

</div>