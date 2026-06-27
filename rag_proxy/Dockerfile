# Use an official Python runtime as a parent image (slim version for smaller size)
FROM python:3.10-slim

# Set the working directory inside the container to /app
WORKDIR /app

# Copy the requirements file into the container at /app
COPY requirements.txt .

# Install the Python dependencies specified in requirements.txt without caching to save space
RUN pip install --no-cache-dir -r requirements.txt

# Copy the rest of the application code into the container at /app
COPY . .

# Inform Docker that the container listens on port 8000 at runtime
EXPOSE 8000

# Run the FastAPI application using uvicorn, binding to all interfaces on port 8000
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
