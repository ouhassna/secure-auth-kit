FROM node:20-alpine

# Alpine doesn't ship OpenSSL by default — Prisma's query engine needs it to run.
RUN apk add --no-cache openssl

WORKDIR /app

# Install deps first (better layer caching)
COPY package*.json ./
RUN npm install

# Copy the rest of the app
COPY . .

# Generate Prisma client inside the image
RUN npx prisma generate

EXPOSE 3000

# Run migrations then start the server (dev.sh handles the "wait for db" case)
CMD ["sh", "docker/entrypoint.sh"]
