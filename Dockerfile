# Use the official Python 3.9 image from the Docker Hub
FROM python:3.9

# Set environment variables
ENV PYTHONUNBUFFERED=1
ENV APP_HOME=/app

# Set the working directory
WORKDIR $APP_HOME

# Copy the application code to the container
COPY . .

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Install necessary system packages
RUN apt-get update && apt-get install -y gnupg

# Expose the port on which the app will run
EXPOSE 8080

# Start the application using Gunicorn
CMD ["gunicorn", "--bind", ":8080", "--workers", "1", "--threads", "8", "--timeout", "0", "decryprtion_over_cloud_run:decryprtion_over_cloud_run"]
