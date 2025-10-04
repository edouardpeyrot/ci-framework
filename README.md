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

GitHub Actions : automatisation du pipeline CI/CD, de la conformité et du déploiement.

## État du projet
L’infrastructure a été déployée avec succès sur AWS dans le cadre d’une phase d’expérimentation.

Le projet a été volontairement mis en pause : la finalité de l’infrastructure ne justifiait pas son maintien opérationnel.
Il reste néanmoins une base démonstrative de pratiques IaC, sécurisation et orchestration multi-composants.
Intérêt

Même sans exécution active du pipeline, le dépôt illustre :
- Une approche modulaire de l’automatisation cloud.
- La structuration d’un projet DevSecOps complet, reproductible et documenté.