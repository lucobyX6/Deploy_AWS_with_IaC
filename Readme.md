# TP3 - INF8102 - Mise en oeuvre d'un VPC et d'un compartiment S3 par IaC

## Description brève

Pour assurer une capacité de déploiement maximale et maintenir une sécurité optimale, le déploiement cherche à s'émanciper des actions humaines. L'`Infrastructure as Code` permet de déployer des objets cloud sans besoin d'intervention humaine. Cette technique est notamment utilisé dans les pipelines CI/CD pour assurer un déploiement rapide et sûr des nouvelles applications sur les serveurs cloud. 


## Organisation du répertoire :
Le répertoire du projet est constitué de la manière suivante : 
- `CloudFormation` : Contient les scripts `json` et `yaml` pour générer le VPC, le S3 et une instance EC2 avec **CloudFormation** de AWS. 
- `Ex1` : Contient le script `python` pour générer le VPC.
- `Ex2` : Contient le script `python` pour générer le compartiment S3.
- `Ex3` : Contient les scripts `python` pour améliorer la sécurité des objets. Pour le VPC, le FlowLogs a été ajouté, un utilisateur renseigné et des alarmes implémentées. Pour le compartiment S3, la réplication et CloudTrail ont été activé. 
- `Ex4` : Contient un script `python` pour générer des rapports de vulnérabilités des scripts précédents. 
- `Rapport_TP4` : Le rapport du TP avec les illustrations du bon fonctionnement des programmes. 
- `Images` : Contient les images du fonctionnement. Les images sont celle présentées dans le rapport. 


