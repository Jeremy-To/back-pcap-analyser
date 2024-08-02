# Analyseur de fichiers PCAP avec VirusTotal

Cette application Flask permet d'analyser des fichiers PCAP en extrayant les fichiers qu'ils contiennent et en les scannant via l'API VirusTotal.

## Fonctionnalités

- Extraction de fichiers à partir de PCAP utilisant tshark
- Analyse des fichiers extraits (taille, hash SHA256)
- Scan des fichiers via l'API VirusTotal
- Interface API REST pour soumettre des fichiers PCAP et obtenir les résultats d'analyse

## Prérequis

- Docker
- Un compte Render
- Une clé API VirusTotal

## Déploiement sur Render

1. Créez un nouveau Web Service sur Render
2. Choisissez l'option "Deploy from a Docker Registry"
3. Configurez les variables d'environnement :
   - `API_SECRET`: Votre clé API VirusTotal
   - `PORT`: 5000 (ou le port de votre choix)

4. Déployez l'application

## Utilisation de l'API

### Analyser un fichier PCAP

POST /analyze
Content-Type: multipart/form-data
file: [Fichier PCAP]

Réponse :

```json
{
  "extracted_files": {
    "http": [
      ["fichier1.exe", 1.5, "sha256_hash1"],
      ["fichier2.dll", 0.5, "sha256_hash2"]
    ],
    "smb": [
      ["fichier3.doc", 2.0, "sha256_hash3"]
    ]
  },
  "vt_results": [
    {
      "filename": "fichier1.exe",
      "hash": "sha256_hash1",
      "score": "3/58",
      "vt_link": "https://www.virustotal.com/gui/file/sha256_hash1",
      "is_malicious": true
    },
    {
      "filename": "fichier2.dll",
      "hash": "sha256_hash2",
      "score": "0/58",
      "vt_link": "https://www.virustotal.com/gui/file/sha256_hash2",
      "is_malicious": false
    },
    {
      "filename": "fichier3.doc",
      "hash": "sha256_hash3",
      "status": "unknown"
    }
  ]
}
```
## Développement local

Clonez ce dépôt
Installez les dépendances : pip install -r requirements.txt
Configurez la variable d'environnement API_SECRET
Lancez l'application : python app.py

Licence
Ce projet est sous licence MIT.
