# Dockerfile pour la documentation Docsify
FROM nginx:alpine

# Copier les fichiers de documentation
COPY . /usr/share/nginx/html/


# Exposer le port 80
EXPOSE 80

# Commande de démarrage
CMD ["nginx", "-g", "daemon off;"]
