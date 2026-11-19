FROM node:24-alpine
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci --omit=dev
COPY *.js ./
USER node
ENV PORT=3000
EXPOSE 3000
ARG APP=vulnerable
ENV APP=${APP}
CMD ["sh", "-c", "exec node ${APP}.js"]
