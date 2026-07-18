FROM apify/actor-node:20

WORKDIR /usr/src/app

COPY --chown=myuser package*.json ./
RUN npm --quiet set progress=false \
    && npm ci --include=dev --omit=optional

COPY --chown=myuser . ./
RUN npm run build \
    && npm prune --omit=dev

CMD ["npm", "start"]
