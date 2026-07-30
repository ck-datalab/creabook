FROM node:20-alpine
WORKDIR /app
COPY api/package.json .
RUN npm install --production
COPY api/server.js .
COPY index.html .
EXPOSE 8080
CMD ["node", "server.js"]
