FROM node:20-alpine AS build
WORKDIR /app
COPY dashboard/frontend/package.json ./
RUN npm install --no-audit --no-fund
COPY dashboard/frontend .
RUN npm run build

FROM nginx:alpine
COPY dashboard/frontend/nginx.conf /etc/nginx/conf.d/default.conf
COPY --from=build /app/dist /usr/share/nginx/html
EXPOSE 80
