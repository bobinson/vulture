FROM node:22-alpine AS build
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci
COPY . .
ARG VITE_API_URL=
ENV VITE_API_URL=$VITE_API_URL
RUN npm run build

FROM nginx:alpine
COPY --from=build /app/dist /usr/share/nginx/html
COPY nginx.conf.template /etc/nginx/templates/default.conf.template
# nginx master process requires root for port binding and worker management.
# The worker processes run as the 'nginx' user (configured in nginx.conf).
EXPOSE 23000
CMD ["nginx", "-g", "daemon off;"]
