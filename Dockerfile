# Production Dockerfile for AgentShield
FROM node:18-alpine

# Create non-root user
RUN addgroup -g 1001 -S nodejs && \
    adduser -S agentshield -u 1001

# Set working directory
WORKDIR /app

# Copy package files
COPY package*.json ./

# Install dependencies (no native modules needed)
RUN npm ci --omit=dev && npm cache clean --force

# Copy application code
COPY . .

# Remove development files
RUN rm -rf .git .gitignore .dockerignore README.md

# Create directories with proper permissions
RUN mkdir -p /app/data && \
    chown agentshield:nodejs /app/data

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD node -e "require('http').get('http://localhost:3000/health', (res) => process.exit(res.statusCode === 200 ? 0 : 1))"

# Switch to non-root user
USER agentshield

# Expose port
EXPOSE 3000

# Set environment variables
ENV NODE_ENV=production
ENV DATABASE_PATH=/app/data/agent-shield.db

# Start the application
CMD ["node", "server.js"]
