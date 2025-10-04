# CI Framework – Démonstrateur DevSecOps
Ce projet a servi de démonstrateur technique autour d’un pipeline DevSecOps complet.
Il illustre la mise en place d’une infrastructure cloud automatisée et conforme aux bonnes pratiques de sécurité et d’observabilité.
## Objectif
Concevoir un environnement cloud cohérent, intégrant les briques suivantes :

AWS : hébergement et orchestration de l’infrastructure.

Terraform : gestion déclarative de l’infrastructure (EKS, VPC, IAM, S3, etc.).

Kubernetes (EKS) : cluster managé pour le déploiement des workloads.

Vault : gestion centralisée des secrets.

Prometheus / Grafana : supervision et métriques.

Velero : sauvegarde et restauration du cluster.

GitHub Actions : automatisation du pipeline CI/CD, de la conformité et du déploiement


## Résultat

Le prototype n’a pas été poussé jusqu’au déploiement complet, par manque d'interêt de mobiliser du temps et des coûts opérationnels.
Il a servi à valider l’architecture, les interactions entre composants et la cohérence d’une approche DevSecOps intégrée.
Le projet reste ouvert à reprise comme démonstrateur technique ou socle de référence.

## Intérêt

Ce travail illustre la démarche d’un déploiement cloud industriel :
	•	conception orientée sécurité et observabilité,
	•	automatisation IaC maîtrisée,
	•	documentation et gouvernance dès la phase de prototypage.
