# NGINX-maintained image that runs nginx as an unprivileged user (uid 101).
# Pulled from NGINX's ECR Public mirror rather than Docker Hub, whose
# anonymous pull limit breaks CI on shared runners. Same image and digest.
FROM public.ecr.aws/nginx/nginx-unprivileged:1.31.8-alpine@sha256:03df07e5931f8374d440bd62243a5ce9b24719715ef6fc4c9c626a5f1dbef417

# Copy custom nginx config
COPY nginx.conf /etc/nginx/nginx.conf

# Copy static files from dist folder to nginx html directory
COPY dist/ /usr/share/nginx/html/

# Move the build-generated CSP snippet out of the served directory
USER root
RUN mv /usr/share/nginx/html/nginx-csp-policy.conf /etc/nginx/csp-policy.conf
USER nginx

# Expose port 80 (containers allow unprivileged binding to low ports)
EXPOSE 80

# Start nginx
CMD ["nginx", "-g", "daemon off;"]
